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
)
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
