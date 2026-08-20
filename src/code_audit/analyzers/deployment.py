"""Deployment Readiness Analyzer — detects issues that break production deployments.

Generic, pluggable deployment validation system that checks for:
- Missing dependencies (Python requirements, npm packages)
- Docker configuration issues (missing directories, env vars)
- Cross-origin URL problems (hardcoded URLs, relative API calls)
- Environment variable misconfigurations
- Field mapping mismatches (snake_case vs camelCase)

Configuration via .deployment.yaml or CLI arguments.

Usage:
    # As analyzer in code-audit pipeline
    analyzer = DeploymentAnalyzer.from_config(config)
    findings = analyzer.run(root, files)

    # Standalone CLI
    python -m code_audit.analyzers.deployment --root /path/to/project

Plugin architecture:
    - Validators are classes implementing ValidatorProtocol
    - Register custom validators via DeploymentAnalyzer.register_validator()
    - Each validator produces Findings with consistent structure
"""

from __future__ import annotations

import ast
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol, TypeAlias

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# =============================================================================
# CONFIGURATION TYPES
# =============================================================================

ValidatorConfig: TypeAlias = dict[str, Any]


@dataclass
class DeploymentConfig:
    """Configuration for deployment validation.

    Can be loaded from .deployment.yaml or constructed programmatically.
    """
    # Project structure
    api_root: str = "services/api"
    client_root: str = "packages/client"
    dockerfile_path: str = "services/api/Dockerfile"

    # Python dependency checking
    requirements_file: str = "requirements.txt"
    critical_deps: dict[str, str] = field(default_factory=lambda: {
        "fastapi": "API framework",
        "uvicorn": "ASGI server",
        "pydantic": "Data validation",
        "httpx": "Async HTTP client",
    })
    optional_deps: set[str] = field(default_factory=lambda: {"anthropic", "psycopg2"})

    # Docker validation
    docker_dir_env_mapping: dict[str, str] = field(default_factory=dict)

    # Frontend validation
    frontend_src: str = "src"
    frontend_extensions: tuple[str, ...] = (".vue", ".ts", ".tsx", ".js", ".jsx")
    cross_origin_patterns: list[tuple[str, str]] = field(default_factory=lambda: [
        (r"fetch\(['\"]\/api", "Relative URL in fetch() - needs API_BASE prefix"),
        (r":src=\"[^\"]*\.url\"", "Possible relative URL in :src binding"),
    ])
    hardcoded_url_patterns: list[tuple[str, str]] = field(default_factory=lambda: [
        (r"https?://localhost:\d+", "Hardcoded localhost URL"),
        (r"https?://127\.0\.0\.1:\d+", "Hardcoded loopback URL"),
        (r"https?://[a-z0-9-]+\.up\.railway\.app", "Hardcoded Railway URL"),
        (r"https?://[a-z0-9-]+\.vercel\.app", "Hardcoded Vercel URL"),
        (r"https?://[a-z0-9-]+\.netlify\.app", "Hardcoded Netlify URL"),
    ])

    # Field mapping rules (backend → frontend)
    field_mapping_rules: dict[str, str] = field(default_factory=lambda: {
        "created_at_utc": "createdAt",
        "updated_at_utc": "updatedAt",
    })

    # Enabled validators
    enabled_validators: list[str] = field(default_factory=lambda: [
        "python_deps",
        "docker_dirs",
        "cross_origin",
        "hardcoded_urls",
        "field_mapping",
        "env_vars",
        "watch_coverage",
    ])

    @classmethod
    def from_yaml(cls, path: Path) -> "DeploymentConfig":
        """Load configuration from YAML file."""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML required for config loading: pip install pyyaml")

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})

    @classmethod
    def discover(cls, root: Path) -> "DeploymentConfig":
        """Auto-discover configuration from project structure."""
        config = cls()

        # Auto-detect API root
        for candidate in ["services/api", "api", "backend", "server", "src/api"]:
            if (root / candidate).is_dir():
                config.api_root = candidate
                config.dockerfile_path = f"{candidate}/Dockerfile"
                break

        # Auto-detect client root
        for candidate in ["packages/client", "client", "frontend", "web", "src/client"]:
            if (root / candidate).is_dir():
                config.client_root = candidate
                break

        # Auto-detect monorepo vs single-package
        if not (root / config.api_root).exists():
            if (root / "requirements.txt").exists():
                config.api_root = "."
                config.requirements_file = "requirements.txt"
            if (root / "pyproject.toml").exists():
                config.api_root = "."

        return config


# =============================================================================
# VALIDATOR PROTOCOL & BASE
# =============================================================================

class ValidatorProtocol(Protocol):
    """Protocol for deployment validators."""

    id: str

    def validate(
        self,
        root: Path,
        config: DeploymentConfig,
        files: list[Path]
    ) -> list[Finding]:
        """Run validation and return findings."""
        ...


class BaseValidator(ABC):
    """Base class for validators with common utilities."""

    id: str = "base"
    severity_default: Severity = Severity.MEDIUM

    @abstractmethod
    def validate(
        self,
        root: Path,
        config: DeploymentConfig,
        files: list[Path]
    ) -> list[Finding]:
        """Run validation."""
        ...

    def _make_finding(
        self,
        rule_id: str,
        message: str,
        path: str,
        line: int = 1,
        severity: Severity | None = None,
        hint: str = "",
        **metadata: Any,
    ) -> Finding:
        """Create a Finding with consistent structure."""
        return Finding(
            finding_id="",  # Set by analyzer after collection
            type=AnalyzerType.SECURITY,  # Deployment issues are security-adjacent
            severity=severity or self.severity_default,
            confidence=0.9,
            message=message,
            location=Location(path=path, line_start=line, line_end=line),
            fingerprint=make_fingerprint(rule_id, path, "", message[:50]),
            snippet=hint,
            metadata={"rule_id": rule_id, "validator": self.id, **metadata},
        )


# =============================================================================
# BUILT-IN VALIDATORS
# =============================================================================

class PythonDependencyValidator(BaseValidator):
    """Checks that imported packages exist in requirements."""

    id = "python_deps"
    severity_default = Severity.HIGH

    def validate(
        self,
        root: Path,
        config: DeploymentConfig,
        files: list[Path]
    ) -> list[Finding]:
        findings: list[Finding] = []
        api_root = root / config.api_root
        
        # Skip if api_root doesn't exist (not a structured project)
        if not api_root.exists():
            return findings
            
        req_path = api_root / config.requirements_file

        if not req_path.exists():
            # Try pyproject.toml
            pyproject = api_root / "pyproject.toml"
            if pyproject.exists():
                return self._check_pyproject(pyproject, api_root, config, files)

            findings.append(self._make_finding(
                "DEP-001",
                f"Requirements file not found: {config.requirements_file}",
                str(req_path.relative_to(root)),
                severity=Severity.HIGH,
            ))
            return findings

        # Parse requirements.txt
        installed = self._parse_requirements(req_path)

        # Scan for critical imports
        critical_imports = self._find_critical_imports(
            api_root,
            config.critical_deps,
            files
        )

        # Check each critical import
        for pkg, (file_path, line) in critical_imports.items():
            pkg_norm = pkg.lower().replace("-", "_")
            if pkg_norm not in installed:
                reason = config.critical_deps.get(pkg, "Required dependency")
                rel_path = file_path.relative_to(root).as_posix()
                findings.append(self._make_finding(
                    "DEP-002",
                    f"Critical package '{pkg}' imported but not in requirements ({reason})",
                    rel_path,
                    line=line,
                    severity=Severity.HIGH,
                    hint=f"Add '{pkg}' to {config.requirements_file}",
                    package=pkg,
                ))

        return findings

    def _parse_requirements(self, path: Path) -> set[str]:
        """Parse requirements.txt into normalized package names."""
        installed = set()
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'^([a-zA-Z0-9_-]+)', line)
            if match:
                pkg = match.group(1).lower().replace("-", "_")
                installed.add(pkg)
                # Common aliases
                if pkg == "pillow":
                    installed.add("pil")
                if pkg == "opencv_python":
                    installed.add("cv2")
        return installed

    def _find_critical_imports(
        self,
        api_root: Path,
        critical_deps: dict[str, str],
        files: list[Path]
    ) -> dict[str, tuple[Path, int]]:
        """Find imports of critical dependencies."""
        found: dict[str, tuple[Path, int]] = {}
        critical_set = {k.lower() for k in critical_deps}

        for py_file in files:
            if not py_file.suffix == ".py":
                continue
            if not str(py_file).startswith(str(api_root)):
                continue

            try:
                content = py_file.read_text(encoding="utf-8")
                tree = ast.parse(content)

                for node in ast.walk(tree):
                    pkg = None
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            pkg = alias.name.split(".")[0]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        pkg = node.module.split(".")[0]

                    if pkg and pkg.lower() in critical_set:
                        if pkg.lower() not in found:
                            found[pkg.lower()] = (py_file, node.lineno)
            except (SyntaxError, UnicodeDecodeError):
                continue

        return found

    def _check_pyproject(
        self,
        pyproject: Path,
        api_root: Path,
        config: DeploymentConfig,
        files: list[Path]
    ) -> list[Finding]:
        """Check dependencies in pyproject.toml."""
        # Simplified - just check if file exists
        # Full implementation would parse TOML
        return []


class DockerDirectoryValidator(BaseValidator):
    """Checks that Dockerfile creates required directories."""

    id = "docker_dirs"
    severity_default = Severity.HIGH

    def validate(
        self,
        root: Path,
        config: DeploymentConfig,
        files: list[Path]
    ) -> list[Finding]:
        findings: list[Finding] = []
        dockerfile = root / config.dockerfile_path

        if not dockerfile.exists():
            # Try root Dockerfile
            dockerfile = root / "Dockerfile"
            if not dockerfile.exists():
                return findings  # No Dockerfile, skip

        content = dockerfile.read_text()

        # Normalize continuation lines
        normalized = content.replace("\\\n", " ")

        # Find ENV declarations
        env_vars = dict(re.findall(r'ENV\s+(\w+)=([^\n]+)', normalized))

        # Find mkdir paths
        mkdir_paths = set()
        for match in re.finditer(r'mkdir\s+-p\s+([^&\n]+)', normalized):
            for path in match.group(1).split():
                if path.startswith("/"):
                    mkdir_paths.add(path.strip())

        # Check configured mappings
        rel_dockerfile = dockerfile.relative_to(root).as_posix()
        for env_var, expected_path in config.docker_dir_env_mapping.items():
            if env_var in env_vars:
                actual_path = env_vars[env_var].strip('"').strip("'")
                if actual_path not in mkdir_paths:
                    findings.append(self._make_finding(
                        "DOCKER-001",
                        f"ENV {env_var}={actual_path} but directory not created",
                        rel_dockerfile,
                        severity=Severity.HIGH,
                        hint=f"Add 'mkdir -p {actual_path}' before ENV declaration",
                        env_var=env_var,
                        dir_path=actual_path,
                    ))

        return findings


class CrossOriginValidator(BaseValidator):
    """Checks for cross-origin URL issues in frontend code."""

    id = "cross_origin"
    severity_default = Severity.MEDIUM

    def validate(
        self,
        root: Path,
        config: DeploymentConfig,
        files: list[Path]
    ) -> list[Finding]:
        findings: list[Finding] = []
        client_root = root / config.client_root
        src_path = client_root / config.frontend_src

        if not src_path.exists():
            return findings

        for file_path in files:
            if not any(file_path.suffix == ext for ext in config.frontend_extensions):
                continue
            if not str(file_path).startswith(str(src_path)):
                continue

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            # Check if file has API_BASE defined
            has_api_base = "API_BASE" in content or "VITE_API_BASE" in content

            # Skip API wrapper files (they implement the fetch wrapper itself)
            is_api_wrapper = (
                "apiBase" in file_path.name or
                "api-base" in file_path.name or
                ("export" in content and "async function api(" in content) or
                ("export" in content and "function fetch" in content and "resolveApiUrl" in content)
            )
            if is_api_wrapper and has_api_base:
                continue  # This file IS the API wrapper, not a consumer

            for pattern, message in config.cross_origin_patterns:
                for match in re.finditer(pattern, content):
                    line = content[:match.start()].count("\n") + 1

                    # Check if this usage is handled
                    ctx_start = max(0, match.start() - 200)
                    ctx_end = min(len(content), match.end() + 200)
                    context = content[ctx_start:ctx_end]

                    if any(h in context for h in [
                        "resolveAssetUrl", "resolveApiUrl",
                        "${API_BASE}", "`${API_BASE}", "import.meta.env"
                    ]):
                        continue

                    rel_path = file_path.relative_to(root).as_posix()
                    findings.append(self._make_finding(
                        "CORS-001",
                        message,
                        rel_path,
                        line=line,
                        severity=Severity.HIGH if not has_api_base else Severity.MEDIUM,
                        hint="Use API_BASE prefix or resolveApiUrl() helper",
                        pattern=pattern,
                    ))

        return findings


class HardcodedUrlValidator(BaseValidator):
    """Checks for hardcoded deployment URLs."""

    id = "hardcoded_urls"
    severity_default = Severity.LOW

    def validate(
        self,
        root: Path,
        config: DeploymentConfig,
        files: list[Path]
    ) -> list[Finding]:
        findings: list[Finding] = []
        client_root = root / config.client_root
        src_path = client_root / config.frontend_src

        if not src_path.exists():
            return findings

        for file_path in files:
            if not any(file_path.suffix == ext for ext in config.frontend_extensions):
                continue
            if not str(file_path).startswith(str(src_path)):
                continue
            if ".spec." in str(file_path) or ".test." in str(file_path):
                continue  # Skip test files

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            for pattern, message in config.hardcoded_url_patterns:
                for match in re.finditer(pattern, content):
                    line = content[:match.start()].count("\n") + 1
                    rel_path = file_path.relative_to(root).as_posix()

                    # Check if it's a fallback (acceptable)
                    line_content = content.split("\n")[line - 1]
                    if "hostname === 'localhost'" in line_content:
                        continue  # Intentional dev fallback

                    findings.append(self._make_finding(
                        "URL-001",
                        f"{message}: {match.group()}",
                        rel_path,
                        line=line,
                        severity=Severity.LOW,
                        hint="Use environment variable instead",
                        url=match.group(),
                    ))

        return findings


class FieldMappingValidator(BaseValidator):
    """Checks for API field name mismatches."""

    id = "field_mapping"
    severity_default = Severity.LOW

    def validate(
        self,
        root: Path,
        config: DeploymentConfig,
        files: list[Path]
    ) -> list[Finding]:
        findings: list[Finding] = []
        client_root = root / config.client_root
        src_path = client_root / config.frontend_src

        if not src_path.exists():
            return findings

        for file_path in files:
            if file_path.suffix not in (".ts", ".tsx"):
                continue
            if not str(file_path).startswith(str(src_path)):
                continue

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            for backend_field, frontend_field in config.field_mapping_rules.items():
                pattern = rf'\.[a-z]*{backend_field}\b'
                if re.search(pattern, content):
                    # Check for proper mapping or fallback
                    has_fallback = f"?? " in content or f"|| " in content
                    if not has_fallback:
                        rel_path = file_path.relative_to(root).as_posix()
                        findings.append(self._make_finding(
                            "FIELD-001",
                            f"Field '{backend_field}' used without fallback",
                            rel_path,
                            severity=Severity.LOW,
                            hint=f"Use: {frontend_field} ?? {backend_field} ?? default",
                            backend_field=backend_field,
                            frontend_field=frontend_field,
                        ))

        return findings


class EnvVarValidator(BaseValidator):
    """Checks environment variable usage consistency."""

    id = "env_vars"
    severity_default = Severity.INFO

    def validate(
        self,
        root: Path,
        config: DeploymentConfig,
        files: list[Path]
    ) -> list[Finding]:
        findings: list[Finding] = []
        client_root = root / config.client_root
        src_path = client_root / config.frontend_src

        if not src_path.exists():
            return findings

        # Count files making API calls vs using API_BASE
        api_call_files: set[str] = set()
        env_var_files: set[str] = set()

        for file_path in files:
            if file_path.suffix not in config.frontend_extensions:
                continue
            if not str(file_path).startswith(str(src_path)):
                continue

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            rel = file_path.relative_to(root).as_posix()
            if re.search(r"fetch\(['\"]\/api", content):
                api_call_files.add(rel)
            if "VITE_API_BASE" in content or "API_BASE" in content:
                env_var_files.add(rel)

        # Files making calls without env var
        missing = api_call_files - env_var_files
        if missing:
            findings.append(self._make_finding(
                "ENV-001",
                f"{len(missing)} files make API calls without API_BASE import",
                ", ".join(list(missing)[:3]) + ("..." if len(missing) > 3 else ""),
                severity=Severity.INFO,
                hint="Centralize API calls through SDK module",
                count=len(missing),
            ))

        return findings


# =============================================================================
# WATCH / TRIGGER COVERAGE DRIFT
# =============================================================================
#
# Family IV (instrument scope < measured target): the trigger/coverage set is
# narrower than what the build actually consumes, so a change to a consumed input
# does not trigger the build/redeploy that depends on it. Distinct from the
# hollow-guarantee detector — there the guard CANNOT fire; here the guard CAN
# fire but its INPUT SET is too narrow to ever see the uncovered inputs.
#
# Motivating instances: GitHub Actions `on.push.paths` that omits a script the job
# runs (or `package-lock.json`/`.nvmrc` a Node build reads); Railway
# `watchPatterns` that omits `start.sh`/`scripts/**`; and Dockerfiles present in
# the repo that no CI job builds. All the same shape — coverage narrower than what
# is consumed.

_WATCH_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
})

# A script invoked by an interpreter/runner on a shell line. Group 1 is the file.
_RUN_SCRIPT_RE = re.compile(
    r"(?:^|[\s;&|(])(?:python[0-9.]*|py|bash|sh|node|npx|source|\.)\s+"
    r"(\.{0,2}/?[\w./-]+\.(?:py|sh|bash|js|cjs|mjs|ts))\b"
)
# A bare ./path invocation.
_RUN_DOTSLASH_RE = re.compile(r"(?:^|[\s;&|(])(\./[\w./-]+)\b")
# `docker build ... -f <path>` and the trailing context.
_DOCKER_BUILD_F_RE = re.compile(r"docker\s+build\b[^\n]*?-f\s+(\S+)")
_DOCKER_BUILD_CTX_RE = re.compile(r"docker\s+build\b(?:(?!-f)[^\n])*?\s(\S+)\s*$")


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile a GitHub-Actions path glob to a full-match regex.

    ``**`` matches across ``/``; ``*`` matches within a path segment; ``?`` one
    non-separator char. A bare directory pattern (``dir/``) matches everything
    beneath it.
    """
    pat = pattern.strip().rstrip("/")
    out: list[str] = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            if pat[i:i + 2] == "**":
                out.append(".*")
                i += 2
                if pat[i:i + 1] == "/":
                    i += 1
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    # A directory pattern also covers everything under it.
    return re.compile(r"(?s)^" + "".join(out) + r"(?:/.*)?$")


def _path_covered(path: str, patterns: list[str]) -> bool:
    """True if a change to ``path`` would match at least one trigger pattern.

    Covers three ways a file can be watched: a glob/literal that matches it, a
    watched directory it lives under, or (for a consumed *directory*) a watched
    path nested inside it.
    """
    p = path.strip().lstrip("./").rstrip("/")
    for raw in patterns:
        pat = raw.strip().lstrip("./").rstrip("/")
        if not pat:
            continue
        if _glob_to_regex(pat).match(p):
            return True
        if "*" not in pat and "?" not in pat:
            if p == pat or p.startswith(pat + "/") or pat.startswith(p + "/"):
                return True
    return False


# Pure helpers are module-level functions (not methods) so the validator class
# stays small and focused — the tool's own god-class metric applies to it too.

def _load_yaml(path: Path) -> Any:
    try:
        import yaml
    except ImportError:
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 — a malformed workflow is not our concern
        return None


def _workflow_files(root: Path) -> list[Path]:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    return sorted(p for p in wf_dir.iterdir()
                  if p.is_file() and p.suffix.lower() in (".yml", ".yaml"))


def _trigger_paths(on: Any) -> tuple[list[str], bool]:
    """Return (path patterns, has_path_filter). ``paths-ignore`` sets
    has_path_filter False (inverse semantics we don't model)."""
    patterns: list[str] = []
    has_filter = False
    events = [on.get("push"), on.get("pull_request")] if isinstance(on, dict) else []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if "paths-ignore" in ev:
            return [], False
        p = ev.get("paths")
        if isinstance(p, list):
            patterns.extend(str(x) for x in p)
            has_filter = True
    return patterns, has_filter


def _iter_run_strings(data: Any):
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, dict):
        return
    for job in jobs.values():
        steps = job.get("steps") if isinstance(job, dict) else None
        for step in steps if isinstance(steps, list) else []:
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                yield step["run"]


def _consumed_inputs(root: Path, run: str) -> set[str]:
    """Files a run block consumes: scripts it invokes, plus known manifests a Node
    install reads (package-lock.json / package.json / .nvmrc). Only inputs that
    actually exist in the repo are kept, so CLI args are not mistaken for files."""
    consumed: set[str] = set()
    for m in _RUN_SCRIPT_RE.finditer(run):
        consumed.add(m.group(1).lstrip("./"))
    for m in _RUN_DOTSLASH_RE.finditer(run):
        consumed.add(m.group(1).lstrip("./"))
    if re.search(r"\bnpm\s+(?:ci|install|run)\b", run):
        consumed.update(("package-lock.json", "package.json"))
    if ".nvmrc" in run:
        consumed.add(".nvmrc")
    return {c for c in consumed if (root / c).exists()}


def _find_dockerfiles(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        try:
            if not p.is_file():
                continue
            if any(part in _WATCH_SKIP_DIRS for part in p.relative_to(root).parts):
                continue
            n = p.name
            if n == "Dockerfile" or n.startswith("Dockerfile.") or n.endswith(".Dockerfile"):
                out.append(p)
        except OSError:
            continue
    return sorted(out)


def _collect_docker_refs_text(text: str, built: set[str]) -> None:
    for m in _DOCKER_BUILD_F_RE.finditer(text):
        built.add(m.group(1).strip().lstrip("./"))
    for m in _DOCKER_BUILD_CTX_RE.finditer(text):
        ctx = m.group(1).strip().rstrip("/").lstrip("./")
        if ctx and not ctx.startswith("-"):
            built.add((ctx + "/Dockerfile").lstrip("/") if ctx != "." else "Dockerfile")


def _action_built(data: Any, built: set[str]) -> None:
    """docker/build-push-action steps → the Dockerfile they build."""
    jobs = data.get("jobs") if isinstance(data, dict) else None
    for job in jobs.values() if isinstance(jobs, dict) else []:
        steps = job.get("steps") if isinstance(job, dict) else None
        for step in steps if isinstance(steps, list) else []:
            if not isinstance(step, dict):
                continue
            if "docker/build-push-action" not in str(step.get("uses", "")):
                continue
            with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
            f, ctx = with_.get("file"), with_.get("context")
            if isinstance(f, str):
                built.add(f.strip().lstrip("./"))
            elif isinstance(ctx, str):
                built.add((ctx.strip().rstrip("/").lstrip("./") + "/Dockerfile").lstrip("/"))


def _compose_service_built(svc: Any, built: set[str]) -> None:
    b = svc.get("build") if isinstance(svc, dict) else None
    if isinstance(b, str):
        built.add((b.rstrip("/").lstrip("./") + "/Dockerfile").lstrip("/"))
    elif isinstance(b, dict):
        ctx = str(b.get("context", ".")).rstrip("/").lstrip("./")
        dfile = b.get("dockerfile")
        if isinstance(dfile, str):
            built.add((f"{ctx}/{dfile}" if ctx and ctx != "." else dfile).lstrip("/"))
        else:
            built.add((f"{ctx}/Dockerfile" if ctx and ctx != "." else "Dockerfile").lstrip("/"))


def _compose_built(root: Path, built: set[str]) -> None:
    for comp in list(root.rglob("docker-compose*.yml")) + list(root.rglob("compose*.yml")):
        if any(part in _WATCH_SKIP_DIRS for part in comp.relative_to(root).parts):
            continue
        data = _load_yaml(comp)
        services = (data.get("services") or {}) if isinstance(data, dict) else {}
        for svc in services.values():
            _compose_service_built(svc, built)


def _built_dockerfiles(root: Path) -> set[str]:
    """Dockerfile paths (repo-relative posix) that some CI job builds."""
    built: set[str] = set()
    for wf in _workflow_files(root):
        data = _load_yaml(wf)
        if not isinstance(data, dict):
            _collect_docker_refs_text(wf.read_text(encoding="utf-8", errors="replace"), built)
            continue
        for run in _iter_run_strings(data):
            _collect_docker_refs_text(run, built)
        _action_built(data, built)
    _compose_built(root, built)
    return built


def _parse_config(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".toml":
        try:
            import tomllib
            return tomllib.loads(text)
        except Exception:  # noqa: BLE001
            return None
    try:
        import json as _json
        return _json.loads(text)
    except Exception:  # noqa: BLE001 — jsonc/malformed: best-effort only
        return None


def _find_all(data: Any, key: str) -> list[Any]:
    """Recursively collect every value stored under ``key`` (lists flattened)."""
    found: list[Any] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == key:
                    found.extend(v) if isinstance(v, list) else found.append(v)
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return found


class WatchCoverageValidator(BaseValidator):
    """Flag trigger/coverage sets narrower than what the build actually consumes."""

    id = "watch_coverage"
    severity_default = Severity.MEDIUM

    def validate(
        self, root: Path, config: DeploymentConfig, files: list[Path]
    ) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._github_actions_gaps(root))
        findings.extend(self._railway_gaps(root))
        findings.extend(self._unbuilt_dockerfiles(root))
        return findings

    def _github_actions_gaps(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for wf in _workflow_files(root):
            data = _load_yaml(wf)
            if not isinstance(data, dict):
                continue
            patterns, has_filter = _trigger_paths(data.get("on") or data.get(True))
            if not has_filter:
                continue  # no path filter → triggers on everything → no gap possible
            rel_wf = wf.relative_to(root).as_posix()
            reported: set[str] = set()
            for run in _iter_run_strings(data):
                for consumed in sorted(_consumed_inputs(root, run)):
                    if consumed in reported or _path_covered(consumed, patterns):
                        continue
                    reported.add(consumed)
                    findings.append(self._make_finding(
                        "WATCH-001",
                        f"'{rel_wf}' has a path filter but runs/reads '{consumed}', "
                        f"which no trigger path matches — a change to '{consumed}' "
                        f"will not trigger this workflow, so the check silently "
                        f"stops covering it.",
                        rel_wf,
                        severity=Severity.MEDIUM,
                        hint=f"Add '{consumed}' (or a covering glob) to on.*.paths.",
                        gap_kind="watch_coverage_gap",
                        trigger_source="github_actions",
                        consumed=consumed,
                    ))
        return findings

    def _railway_gaps(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for name in ("railway.json", "railway.jsonc", "railway.toml"):
            cfg = root / name
            if not cfg.is_file():
                continue
            data = _parse_config(cfg)
            patterns = _find_all(data, "watchPatterns") if isinstance(data, dict) else []
            if not patterns:
                continue  # no watchPatterns declared → nothing to under-cover
            commands = _find_all(data, "startCommand") + _find_all(data, "buildCommand")
            rel = cfg.relative_to(root).as_posix()
            reported: set[str] = set()
            for cmd in commands:
                if not isinstance(cmd, str):
                    continue
                for consumed in sorted(_consumed_inputs(root, cmd)):
                    if consumed in reported or _path_covered(consumed, patterns):
                        continue
                    reported.add(consumed)
                    findings.append(self._make_finding(
                        "WATCH-001",
                        f"'{rel}' declares watchPatterns but its start/build command "
                        f"runs '{consumed}', which no watchPattern matches — a change "
                        f"to '{consumed}' will not trigger a redeploy.",
                        rel,
                        severity=Severity.MEDIUM,
                        hint=f"Add '{consumed}' (or a covering glob) to watchPatterns.",
                        gap_kind="watch_coverage_gap",
                        trigger_source="railway",
                        consumed=consumed,
                    ))
        return findings

    def _unbuilt_dockerfiles(self, root: Path) -> list[Finding]:
        dockerfiles = _find_dockerfiles(root)
        if not dockerfiles:
            return []
        built = _built_dockerfiles(root)
        findings: list[Finding] = []
        for df in dockerfiles:
            rel = df.relative_to(root).as_posix()
            if rel in built:
                continue
            findings.append(self._make_finding(
                "DOCKER-002",
                f"Dockerfile '{rel}' exists but no CI job builds it — a break inside "
                f"it is never caught, because nothing in CI exercises this image.",
                rel,
                severity=Severity.MEDIUM,
                hint="Add a CI step that builds this Dockerfile, or remove it if dead.",
                gap_kind="unbuilt_dockerfile",
            ))
        return findings


# =============================================================================
# MAIN ANALYZER
# =============================================================================

class DeploymentAnalyzer:
    """Pluggable deployment readiness analyzer.

    Combines multiple validators into a cohesive analysis.
    """

    id: str = "deployment"
    version: str = "1.1.0"

    # Registry of built-in validators
    _BUILTIN_VALIDATORS: dict[str, type[BaseValidator]] = {
        "python_deps": PythonDependencyValidator,
        "docker_dirs": DockerDirectoryValidator,
        "cross_origin": CrossOriginValidator,
        "hardcoded_urls": HardcodedUrlValidator,
        "field_mapping": FieldMappingValidator,
        "env_vars": EnvVarValidator,
        "watch_coverage": WatchCoverageValidator,
    }

    def __init__(self, config: DeploymentConfig | None = None):
        self.config = config or DeploymentConfig()
        self._validators: list[ValidatorProtocol] = []
        self._custom_validators: dict[str, type[BaseValidator]] = {}

        # Initialize enabled validators
        for vid in self.config.enabled_validators:
            if vid in self._BUILTIN_VALIDATORS:
                self._validators.append(self._BUILTIN_VALIDATORS[vid]())
            elif vid in self._custom_validators:
                self._validators.append(self._custom_validators[vid]())

    @classmethod
    def from_config(cls, config_path: Path | str) -> "DeploymentAnalyzer":
        """Create analyzer from config file."""
        path = Path(config_path)
        if path.exists():
            config = DeploymentConfig.from_yaml(path)
        else:
            config = DeploymentConfig()
        return cls(config)

    @classmethod
    def from_root(cls, root: Path) -> "DeploymentAnalyzer":
        """Create analyzer with auto-discovered config."""
        # Look for config file
        for name in [".deployment.yaml", ".deployment.yml", "deployment.yaml"]:
            config_path = root / name
            if config_path.exists():
                return cls.from_config(config_path)

        # Auto-discover project structure
        config = DeploymentConfig.discover(root)
        return cls(config)

    @classmethod
    def register_validator(cls, validator_class: type[BaseValidator]) -> None:
        """Register a custom validator class."""
        cls._BUILTIN_VALIDATORS[validator_class.id] = validator_class

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        """Run all enabled validators and collect findings."""
        all_findings: list[Finding] = []

        for validator in self._validators:
            try:
                findings = validator.validate(root, self.config, files)
                all_findings.extend(findings)
            except Exception as e:
                # Log but don't fail entire analysis
                all_findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.SECURITY,
                    severity=Severity.INFO,
                    confidence=1.0,
                    message=f"Validator '{validator.id}' failed: {e}",
                    location=Location(path=".", line_start=1, line_end=1),
                    fingerprint=make_fingerprint("ERR-001", validator.id, "", str(e)),
                    metadata={"validator": validator.id, "error": str(e)},
                ))

        # Assign stable finding IDs
        for i, f in enumerate(all_findings):
            object.__setattr__(f, "finding_id", f"deploy_{f.fingerprint[7:15]}_{i:04d}")

        return all_findings

    def run_standalone(
        self,
        root: Path,
        verbose: bool = False,
        json_output: bool = False,
    ) -> int:
        """Run as standalone CLI tool."""
        import json as json_mod

        # Collect files
        files: list[Path] = []
        for ext in (".py", ".vue", ".ts", ".tsx", ".js", ".jsx"):
            files.extend(root.rglob(f"*{ext}"))

        # Filter out common excludes
        files = [
            f for f in files
            if "node_modules" not in str(f)
            and ".venv" not in str(f)
            and "__pycache__" not in str(f)
        ]

        if verbose:
            print(f"Scanning {len(files)} files...")

        findings = self.run(root, files)

        if json_output:
            print(json_mod.dumps([f.to_dict() for f in findings], indent=2))
        else:
            self._print_report(findings, verbose)

        # Exit codes
        errors = [f for f in findings if f.severity == Severity.HIGH]
        warnings = [f for f in findings if f.severity == Severity.MEDIUM]

        if errors:
            return 2
        if warnings:
            return 1
        return 0

    def _print_report(self, findings: list[Finding], verbose: bool) -> None:
        """Print human-readable report."""
        if not findings:
            print("[OK] All deployment checks passed")
            return

        errors = [f for f in findings if f.severity == Severity.HIGH]
        warnings = [f for f in findings if f.severity == Severity.MEDIUM]
        infos = [f for f in findings if f.severity in (Severity.LOW, Severity.INFO)]

        if errors:
            print(f"\n{'='*60}")
            print(f"ERRORS ({len(errors)}) - Must fix before deployment")
            print(f"{'='*60}")
            for f in errors:
                self._print_finding(f, verbose)

        if warnings:
            print(f"\n{'='*60}")
            print(f"WARNINGS ({len(warnings)}) - Review recommended")
            print(f"{'='*60}")
            for f in warnings:
                self._print_finding(f, verbose)

        if verbose and infos:
            print(f"\n{'='*60}")
            print(f"INFO ({len(infos)})")
            print(f"{'='*60}")
            for f in infos:
                self._print_finding(f, verbose)

        print(f"\nSummary: {len(errors)} errors, {len(warnings)} warnings, {len(infos)} info")

    def _print_finding(self, f: Finding, verbose: bool) -> None:
        """Print single finding."""
        icon = "[ERROR]" if f.severity == Severity.HIGH else "[WARN]" if f.severity == Severity.MEDIUM else "[INFO]"
        rule = f.metadata.get("rule_id", "")
        print(f"\n{icon} [{rule}] {f.message}")
        print(f"  Location: {f.location.path}:{f.location.line_start}")
        if f.snippet and verbose:
            print(f"  Hint: {f.snippet}")


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main() -> None:
    """CLI entry point for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Deployment Readiness Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Analyze current directory
    python -m code_audit.analyzers.deployment

    # Analyze specific project
    python -m code_audit.analyzers.deployment --root /path/to/project

    # Use custom config
    python -m code_audit.analyzers.deployment --config .deployment.yaml

    # JSON output for CI
    python -m code_audit.analyzers.deployment --json
        """,
    )
    parser.add_argument(
        "--root", "-r",
        type=Path,
        default=Path.cwd(),
        help="Project root directory (default: current directory)",
    )
    parser.add_argument(
        "--config", "-c",
        type=Path,
        help="Path to .deployment.yaml config file",
    )
    parser.add_argument(
        "--api-root",
        type=str,
        help="Override API root directory (e.g., 'services/api')",
    )
    parser.add_argument(
        "--client-root",
        type=str,
        help="Override client root directory (e.g., 'packages/client')",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output with hints",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON format",
    )
    parser.add_argument(
        "--list-validators",
        action="store_true",
        help="List available validators and exit",
    )

    args = parser.parse_args()

    if args.list_validators:
        print("Available validators:")
        for vid, vcls in DeploymentAnalyzer._BUILTIN_VALIDATORS.items():
            print(f"  {vid}: {vcls.__doc__.splitlines()[0] if vcls.__doc__ else 'No description'}")
        return

    # Create analyzer
    if args.config:
        analyzer = DeploymentAnalyzer.from_config(args.config)
    else:
        analyzer = DeploymentAnalyzer.from_root(args.root)

    # Apply CLI overrides
    if args.api_root:
        analyzer.config.api_root = args.api_root
    if args.client_root:
        analyzer.config.client_root = args.client_root

    # Run analysis
    exit_code = analyzer.run_standalone(
        args.root,
        verbose=args.verbose,
        json_output=args.json,
    )

    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
