"""Tests for deployment readiness analyzer."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from code_audit.analyzers.deployment import (
    CrossOriginValidator,
    DeploymentAnalyzer,
    DeploymentConfig,
    DockerDirectoryValidator,
    HardcodedUrlValidator,
    PythonDependencyValidator,
    WatchCoverageValidator,
)
from code_audit.contracts.validate import validate_finding
from code_audit.model import Severity


class TestDeploymentConfig:
    """Test configuration loading and discovery."""

    def test_default_config(self):
        config = DeploymentConfig()
        assert config.api_root == "services/api"
        assert config.client_root == "packages/client"
        assert "fastapi" in config.critical_deps

    def test_discover_monorepo(self, tmp_path: Path):
        """Auto-discover monorepo structure."""
        (tmp_path / "services" / "api").mkdir(parents=True)
        (tmp_path / "packages" / "client").mkdir(parents=True)

        config = DeploymentConfig.discover(tmp_path)
        assert config.api_root == "services/api"
        assert config.client_root == "packages/client"

    def test_discover_simple_project(self, tmp_path: Path):
        """Auto-discover simple project structure."""
        (tmp_path / "requirements.txt").write_text("fastapi\n")
        (tmp_path / "client").mkdir()

        config = DeploymentConfig.discover(tmp_path)
        assert config.api_root == "."
        assert config.client_root == "client"


class TestPythonDependencyValidator:
    """Test Python dependency validation."""

    def test_missing_critical_dep(self, tmp_path: Path):
        """Detect missing critical dependency."""
        api_root = tmp_path / "services" / "api"
        api_root.mkdir(parents=True)

        # Create requirements without openai
        (api_root / "requirements.txt").write_text("fastapi\nuvicorn\n")

        # Create Python file importing openai
        app_dir = api_root / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text("import openai\n")

        config = DeploymentConfig(
            api_root="services/api",
            critical_deps={"openai": "Required for AI"},
        )
        validator = PythonDependencyValidator()
        findings = validator.validate(tmp_path, config, list(tmp_path.rglob("*.py")))

        assert len(findings) == 1
        assert "openai" in findings[0].message
        assert findings[0].severity == Severity.HIGH

    def test_all_deps_present(self, tmp_path: Path):
        """No findings when all deps present."""
        api_root = tmp_path / "services" / "api"
        api_root.mkdir(parents=True)

        (api_root / "requirements.txt").write_text("fastapi\nopenai\n")

        app_dir = api_root / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text("import openai\nimport fastapi\n")

        config = DeploymentConfig(
            api_root="services/api",
            critical_deps={"openai": "AI", "fastapi": "API"},
        )
        validator = PythonDependencyValidator()
        findings = validator.validate(tmp_path, config, list(tmp_path.rglob("*.py")))

        assert len(findings) == 0


class TestDockerDirectoryValidator:
    """Test Docker directory validation."""

    def test_missing_mkdir(self, tmp_path: Path):
        """Detect missing mkdir for ENV directory."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM python:3.11
ENV DATA_DIR=/app/data
WORKDIR /app
""")

        config = DeploymentConfig(
            dockerfile_path="Dockerfile",
            docker_dir_env_mapping={"DATA_DIR": "/app/data"},
        )
        validator = DockerDirectoryValidator()
        findings = validator.validate(tmp_path, config, [])

        assert len(findings) == 1
        assert "DATA_DIR" in findings[0].message
        assert "mkdir" in findings[0].snippet

    def test_mkdir_present(self, tmp_path: Path):
        """No findings when mkdir present."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM python:3.11
RUN mkdir -p /app/data
ENV DATA_DIR=/app/data
WORKDIR /app
""")

        config = DeploymentConfig(
            dockerfile_path="Dockerfile",
            docker_dir_env_mapping={"DATA_DIR": "/app/data"},
        )
        validator = DockerDirectoryValidator()
        findings = validator.validate(tmp_path, config, [])

        assert len(findings) == 0


class TestCrossOriginValidator:
    """Test cross-origin URL validation."""

    def test_relative_fetch(self, tmp_path: Path):
        """Detect relative URL in fetch()."""
        client = tmp_path / "packages" / "client" / "src"
        client.mkdir(parents=True)

        (client / "api.ts").write_text("""
export async function getData() {
    const res = await fetch('/api/data');
    return res.json();
}
""")

        config = DeploymentConfig(client_root="packages/client")
        validator = CrossOriginValidator()
        findings = validator.validate(tmp_path, config, list(tmp_path.rglob("*.ts")))

        assert len(findings) == 1
        assert "fetch" in findings[0].message

    def test_api_base_used(self, tmp_path: Path):
        """No finding when API_BASE is used."""
        client = tmp_path / "packages" / "client" / "src"
        client.mkdir(parents=True)

        (client / "api.ts").write_text("""
const API_BASE = import.meta.env.VITE_API_BASE;
export async function getData() {
    const res = await fetch(`${API_BASE}/api/data`);
    return res.json();
}
""")

        config = DeploymentConfig(client_root="packages/client")
        validator = CrossOriginValidator()
        findings = validator.validate(tmp_path, config, list(tmp_path.rglob("*.ts")))

        assert len(findings) == 0


class TestHardcodedUrlValidator:
    """Test hardcoded URL detection."""

    def test_hardcoded_localhost(self, tmp_path: Path):
        """Detect hardcoded localhost URL."""
        client = tmp_path / "packages" / "client" / "src"
        client.mkdir(parents=True)

        (client / "config.ts").write_text("""
export const API_URL = "http://localhost:8000/api";
""")

        config = DeploymentConfig(client_root="packages/client")
        validator = HardcodedUrlValidator()
        findings = validator.validate(tmp_path, config, list(tmp_path.rglob("*.ts")))

        assert len(findings) == 1
        assert "localhost" in findings[0].message

    def test_localhost_fallback_allowed(self, tmp_path: Path):
        """Allow localhost as dev fallback."""
        client = tmp_path / "packages" / "client" / "src"
        client.mkdir(parents=True)

        (client / "config.ts").write_text("""
const API_URL = window.location.hostname === 'localhost' ? 'http://localhost:8000' : '';
""")

        config = DeploymentConfig(client_root="packages/client")
        validator = HardcodedUrlValidator()
        findings = validator.validate(tmp_path, config, list(tmp_path.rglob("*.ts")))

        assert len(findings) == 0


class TestDeploymentAnalyzer:
    """Test main analyzer orchestration."""

    def test_full_analysis(self, tmp_path: Path):
        """Run full analysis on mock project."""
        # Create minimal project structure
        api_root = tmp_path / "services" / "api"
        api_root.mkdir(parents=True)
        (api_root / "requirements.txt").write_text("fastapi\n")

        app_dir = api_root / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text("from fastapi import FastAPI\n")

        client = tmp_path / "packages" / "client" / "src"
        client.mkdir(parents=True)
        (client / "api.ts").write_text("export const x = 1;\n")

        # Run analyzer
        analyzer = DeploymentAnalyzer.from_root(tmp_path)
        files = list(tmp_path.rglob("*.py")) + list(tmp_path.rglob("*.ts"))
        findings = analyzer.run(tmp_path, files)

        # Should have no critical errors for this minimal setup
        errors = [f for f in findings if f.severity == Severity.HIGH]
        assert len(errors) == 0

    def test_custom_validator_registration(self):
        """Test registering custom validator."""
        from code_audit.analyzers.deployment import BaseValidator

        class CustomValidator(BaseValidator):
            id = "custom_check"

            def validate(self, root, config, files):
                return []

        DeploymentAnalyzer.register_validator(CustomValidator)
        assert "custom_check" in DeploymentAnalyzer._BUILTIN_VALIDATORS

    def test_list_validators(self):
        """Test that all built-in validators are registered."""
        expected = {"python_deps", "docker_dirs", "cross_origin", "hardcoded_urls", "field_mapping", "env_vars"}
        actual = set(DeploymentAnalyzer._BUILTIN_VALIDATORS.keys())
        assert expected.issubset(actual)


# Watch/trigger coverage drift — the trigger set narrower than what the build
# actually consumes (Family IV). Distinct from hollow_guarantee: there the guard
# cannot fire; here the guard can fire but its INPUT set is too narrow. Split into
# focused classes (the tool's own god-class metric applies to test classes too).

def _wc_run(root: Path):
    return WatchCoverageValidator().validate(root, DeploymentConfig(), [])


def _wc_write(root: Path, rel: str, content: str = "x\n") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestWatchCoverageGithubActions:
    """GitHub Actions on.*.paths filters narrower than what the job runs/reads."""

    def test_script_run_but_not_watched_is_flagged(self, tmp_path: Path):
        _wc_write(tmp_path, "scripts/build.sh")
        _wc_write(tmp_path, "scripts/watched.sh")
        _wc_write(tmp_path, ".github/workflows/ci.yml",
            "name: ci\non:\n  push:\n    paths:\n      - 'scripts/watched.sh'\n"
            "jobs:\n  b:\n    steps:\n      - run: bash scripts/build.sh\n")
        f = _wc_run(tmp_path)
        assert len(f) == 1
        assert f[0].severity is Severity.MEDIUM
        assert f[0].metadata["gap_kind"] == "watch_coverage_gap"
        assert f[0].metadata["consumed"] == "scripts/build.sh"
        assert f[0].metadata["trigger_source"] == "github_actions"

    def test_npm_ci_lockfile_gap_flagged(self, tmp_path: Path):
        _wc_write(tmp_path, "package.json", "{}")
        _wc_write(tmp_path, "package-lock.json", "{}")
        _wc_write(tmp_path, ".github/workflows/ci.yml",
            "name: ci\non:\n  push:\n    paths:\n      - 'src/**'\n"
            "jobs:\n  b:\n    steps:\n      - run: npm ci\n")
        consumed = {f.metadata["consumed"] for f in _wc_run(tmp_path)}
        assert "package-lock.json" in consumed and "package.json" in consumed

    def test_watched_script_is_silent(self, tmp_path: Path):
        _wc_write(tmp_path, "scripts/build.sh")
        _wc_write(tmp_path, ".github/workflows/ci.yml",
            "name: ci\non:\n  push:\n    paths:\n      - 'scripts/build.sh'\n"
            "jobs:\n  b:\n    steps:\n      - run: bash scripts/build.sh\n")
        assert _wc_run(tmp_path) == []

    def test_glob_covers_script(self, tmp_path: Path):
        _wc_write(tmp_path, "scripts/deep/build.sh")
        _wc_write(tmp_path, ".github/workflows/ci.yml",
            "name: ci\non:\n  push:\n    paths:\n      - 'scripts/**'\n"
            "jobs:\n  b:\n    steps:\n      - run: bash scripts/deep/build.sh\n")
        assert _wc_run(tmp_path) == []

    def test_no_path_filter_is_silent(self, tmp_path: Path):
        """No paths filter → the workflow triggers on every change → no gap."""
        _wc_write(tmp_path, "scripts/build.sh")
        _wc_write(tmp_path, ".github/workflows/ci.yml",
            "name: ci\non: [push]\njobs:\n  b:\n    steps:\n      - run: bash scripts/build.sh\n")
        assert _wc_run(tmp_path) == []

    def test_paths_ignore_is_not_modeled_silent(self, tmp_path: Path):
        _wc_write(tmp_path, "scripts/build.sh")
        _wc_write(tmp_path, ".github/workflows/ci.yml",
            "name: ci\non:\n  push:\n    paths-ignore:\n      - 'docs/**'\n"
            "jobs:\n  b:\n    steps:\n      - run: bash scripts/build.sh\n")
        assert _wc_run(tmp_path) == []

    def test_argument_directory_not_treated_as_script(self, tmp_path: Path):
        """The copy-lint shape: a data dir arg covered by the filter must not fire;
        only the uncovered script does."""
        _wc_write(tmp_path, "scripts/copy_lint.py")
        _wc_write(tmp_path, "scripts/locale_parity.py")
        _wc_write(tmp_path, "i18n/en/x.json", "{}")
        _wc_write(tmp_path, ".github/workflows/ci.yml",
            "name: ci\non:\n  push:\n    paths:\n      - 'i18n/**'\n      - 'scripts/copy_lint.py'\n"
            "jobs:\n  b:\n    steps:\n"
            "      - run: python scripts/copy_lint.py lint i18n/\n"
            "      - run: python scripts/locale_parity.py i18n/\n")
        f = _wc_run(tmp_path)
        assert [x.metadata["consumed"] for x in f] == ["scripts/locale_parity.py"]


class TestUnbuiltDockerfiles:
    """Dockerfiles present in the repo that no CI job builds."""

    def test_unbuilt_dockerfile_flagged_built_one_silent(self, tmp_path: Path):
        _wc_write(tmp_path, "Dockerfile", "FROM python\n")
        _wc_write(tmp_path, "svc/Dockerfile", "FROM node\n")
        _wc_write(tmp_path, ".github/workflows/img.yml",
            "name: img\non: [push]\njobs:\n  i:\n    steps:\n      - run: docker build -f Dockerfile .\n")
        f = _wc_run(tmp_path)
        unbuilt = [x.location.path for x in f if x.metadata["gap_kind"] == "unbuilt_dockerfile"]
        assert unbuilt == ["svc/Dockerfile"]

    def test_build_push_action_marks_built(self, tmp_path: Path):
        _wc_write(tmp_path, "svc/Dockerfile", "FROM node\n")
        _wc_write(tmp_path, ".github/workflows/img.yml",
            "name: img\non: [push]\njobs:\n  i:\n    steps:\n"
            "      - uses: docker/build-push-action@v5\n        with:\n          file: svc/Dockerfile\n")
        assert [f for f in _wc_run(tmp_path) if f.metadata["gap_kind"] == "unbuilt_dockerfile"] == []

    def test_compose_build_marks_built(self, tmp_path: Path):
        _wc_write(tmp_path, "svc/Dockerfile", "FROM node\n")
        _wc_write(tmp_path, "docker-compose.yml",
            "services:\n  api:\n    build:\n      context: svc\n")
        assert [f for f in _wc_run(tmp_path) if f.metadata["gap_kind"] == "unbuilt_dockerfile"] == []


class TestWatchCoverageRailwayAndContract:
    """Railway watchPatterns gaps, plus registration / robustness / contract."""

    def test_railway_start_command_gap_flagged(self, tmp_path: Path):
        _wc_write(tmp_path, "start.sh", "node server.js\n")
        _wc_write(tmp_path, "railway.json",
            '{"deploy": {"startCommand": "bash start.sh", "watchPatterns": ["src/**"]}}')
        f = _wc_run(tmp_path)
        assert any(x.metadata.get("trigger_source") == "railway"
                   and x.metadata["consumed"] == "start.sh" for x in f)

    def test_railway_no_watchpatterns_is_silent(self, tmp_path: Path):
        _wc_write(tmp_path, "start.sh", "node server.js\n")
        _wc_write(tmp_path, "railway.json", '{"deploy": {"startCommand": "bash start.sh"}}')
        assert _wc_run(tmp_path) == []

    # ── registration / robustness / contract ────────────────────────
    def test_registered_and_enabled_by_default(self):
        assert "watch_coverage" in DeploymentAnalyzer._BUILTIN_VALIDATORS
        assert "watch_coverage" in DeploymentConfig().enabled_validators
        assert DeploymentAnalyzer.version == "1.1.0"

    def test_dispatched_by_analyzer_run(self, tmp_path: Path):
        _wc_write(tmp_path, "scripts/build.sh")
        _wc_write(tmp_path, ".github/workflows/ci.yml",
            "name: ci\non:\n  push:\n    paths:\n      - 'x'\n"
            "jobs:\n  b:\n    steps:\n      - run: bash scripts/build.sh\n")
        findings = DeploymentAnalyzer().run(tmp_path, [])
        assert any(f.metadata.get("gap_kind") == "watch_coverage_gap" for f in findings)

    def test_malformed_yaml_does_not_crash(self, tmp_path: Path):
        _wc_write(tmp_path, ".github/workflows/bad.yml", "on: [push]\n  bad: : :\n:\n")
        assert isinstance(_wc_run(tmp_path), list)  # no exception

    def test_no_ci_surface_is_silent(self, tmp_path: Path):
        _wc_write(tmp_path, "app/main.py", "x = 1\n")
        assert _wc_run(tmp_path) == []

    def test_findings_contract_valid(self, tmp_path: Path):
        _wc_write(tmp_path, "scripts/build.sh")
        _wc_write(tmp_path, "svc/Dockerfile", "FROM node\n")
        _wc_write(tmp_path, ".github/workflows/ci.yml",
            "name: ci\non:\n  push:\n    paths:\n      - 'x'\n"
            "jobs:\n  b:\n    steps:\n      - run: bash scripts/build.sh\n")
        for f in DeploymentAnalyzer().run(tmp_path, []):
            validate_finding(f.to_dict())
