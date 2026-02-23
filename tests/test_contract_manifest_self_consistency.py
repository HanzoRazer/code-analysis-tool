"""Manifest self-consistency check.

Ensures the unified golden fixtures manifest is complete and that every
promoted contract artifact is defended by both:

  - **semantic** gate(s): validate meaning / structure / behaviour
  - **version** gate(s): enforce signal_logic_version bump discipline

This prevents governance from degenerating into "file hash only" — every
promoted artifact must also have focused contract tests with operator-grade
error messages.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GOLDEN_MANIFEST = ROOT / "tests" / "contracts" / "golden_fixtures_manifest.json"


# ── Promoted-artifact → coverage mapping ────────────────────────────────
#
# These must match the required promoted files enforced by
# scripts/refresh_golden_manifest.py.
#
# Each entry declares:
#   coverage.semantic  – tests that validate meaning / structure
#   coverage.version   – tests that enforce bump discipline
#
# Both lists must be non-empty and reference existing test files.

PROMOTED_ARTIFACTS: dict[str, dict[str, object]] = {
    "tests/contracts/openapi_scrub_audit_baseline.json": {
        "description": "Accepted volatility baseline (what scrubbed fields are allowed).",
        "coverage": {
            "semantic": [
                "tests/test_openapi_scrub_audit_baseline.py",
            ],
            "version": [
                "tests/test_openapi_scrub_baseline_requires_signal_logic_bump.py",
            ],
        },
    },
    "tests/contracts/openapi_scrub_budgets.json": {
        "description": "Per-endpoint scrub budgets (how much volatility is allowed).",
        "coverage": {
            "semantic": [
                "tests/test_openapi_scrub_audit_baseline.py",
            ],
            "version": [
                "tests/test_openapi_scrub_budgets_requires_signal_logic_bump.py",
            ],
        },
    },
    "tests/contracts/openapi_golden_scrub_policy.json": {
        "description": "Volatility scrub policy (what patterns are considered volatile).",
        "coverage": {
            "semantic": [
                "tests/test_openapi_golden_endpoints.py",
                "tests/test_openapi_scrub_audit_baseline.py",
            ],
            "version": [
                # The golden manifest gate is the authoritative version gate for
                # this artifact (it is promoted into golden_fixtures_manifest.json).
                # If you later add a dedicated bump gate, list it here instead.
                "tests/test_golden_manifest_requires_signal_logic_bump.py",
            ],
        },
    },
    "tests/contracts/openapi_golden_endpoints.json": {
        "description": "Endpoint selection registry (public+stable endpoints locked by goldens).",
        "coverage": {
            "semantic": [
                "tests/test_openapi_golden_endpoints.py",
            ],
            "version": [
                "tests/test_golden_manifest_requires_signal_logic_bump.py",
            ],
        },
    },
}


# The umbrella version gate applies to all promoted artifacts.
UMBRELLA_VERSION_GATE = "tests/test_golden_manifest_requires_signal_logic_bump.py"

# Artifacts that must have exactly one non-umbrella ("dedicated") version gate.
REQUIRE_DEDICATED_VERSION_GATE: set[str] = {
    "tests/contracts/openapi_scrub_audit_baseline.json",
    "tests/contracts/openapi_scrub_budgets.json",
}


# ── Helpers ─────────────────────────────────────────────────────────────


def _load_golden_manifest_paths() -> set[str]:
    assert GOLDEN_MANIFEST.exists(), (
        "Missing tests/contracts/golden_fixtures_manifest.json.\n"
        "Run: python scripts/refresh_golden_manifest.py"
    )
    manifest = json.loads(GOLDEN_MANIFEST.read_text(encoding="utf-8"))
    files = manifest.get("files")
    assert isinstance(files, (dict, list)), (
        "golden_fixtures_manifest.json must contain 'files' (dict or list)"
    )
    if isinstance(files, dict):
        return set(files.keys())
    # list-of-dicts format
    paths: set[str] = set()
    for entry in files:
        if isinstance(entry, dict):
            p = entry.get("path")
            if isinstance(p, str) and p:
                paths.add(p)
    return paths


def _gate_files() -> list[str]:
    """Collect all unique gate file paths from semantic + version coverage."""
    gates: list[str] = []
    for meta in PROMOTED_ARTIFACTS.values():
        cov = meta.get("coverage") or {}
        if isinstance(cov, dict):
            for kind in ("semantic", "version"):
                lst = cov.get(kind)
                if isinstance(lst, list):
                    for g in lst:
                        if isinstance(g, str) and g.strip():
                            gates.append(g.strip())
    # Deduplicate while preserving stable order
    seen: set[str] = set()
    out: list[str] = []
    for g in gates:
        if g not in seen:
            out.append(g)
            seen.add(g)
    return out


def _has_pytest_tests(path: Path) -> bool:
    """Static check: file contains at least one top-level ``def test_*`` function.

    Also accepts ``class Test*`` with ``def test_*`` methods.
    This is a strong proxy for pytest collection without invoking pytest.
    """
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            return True
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for sub in node.body:
                if isinstance(sub, ast.FunctionDef) and sub.name.startswith("test_"):
                    return True
    return False


# ── Tests ───────────────────────────────────────────────────────────────


def test_promoted_artifacts_are_in_golden_manifest() -> None:
    """Every promoted artifact path must appear in golden_fixtures_manifest.json."""
    golden_paths = _load_golden_manifest_paths()
    missing = [p for p in PROMOTED_ARTIFACTS if p not in golden_paths]
    if missing:
        lines = [
            "Manifest self-consistency check failed:",
            "Promoted contract artifacts missing from golden_fixtures_manifest.json:",
        ]
        lines.extend([f"- {p}" for p in missing])
        lines.append("")
        lines.append("Fix:")
        lines.append("  - Ensure scripts/refresh_golden_manifest.py includes these files,")
        lines.append("  - Then run: python scripts/refresh_golden_manifest.py")
        raise AssertionError("\n".join(lines))


def test_promoted_artifacts_exist_on_disk() -> None:
    """Mirrors the refresh script's strict ``require present`` posture in pytest."""
    missing = [p for p in PROMOTED_ARTIFACTS if not (ROOT / p).exists()]
    if missing:
        lines = [
            "Manifest self-consistency check failed:",
            "Promoted contract artifacts missing on disk:",
        ]
        lines.extend([f"- {p}" for p in missing])
        raise AssertionError("\n".join(lines))


def test_promoted_artifacts_declare_coverage_intent() -> None:
    """Enforces the two-layer governance model for every promoted artifact:

    - ``coverage.semantic`` (non-empty): tests that validate meaning/structure
    - ``coverage.version``  (non-empty): tests that enforce bump discipline
    """
    missing_cov: list[str] = []
    missing_semantic: list[str] = []
    missing_version: list[str] = []
    bad_entries: list[tuple[str, str, str]] = []
    missing_files: list[tuple[str, str, str]] = []
    identical_lists: list[str] = []
    umbrella_only_semantic: list[str] = []
    missing_dedicated_version_gate: list[str] = []
    multiple_dedicated_version_gates: list[tuple[str, list[str]]] = []

    for artifact_path, meta in PROMOTED_ARTIFACTS.items():
        cov = meta.get("coverage")
        if not isinstance(cov, dict):
            missing_cov.append(artifact_path)
            continue

        semantic = cov.get("semantic")
        version = cov.get("version")

        if not isinstance(semantic, list) or not semantic:
            missing_semantic.append(artifact_path)
        if not isinstance(version, list) or not version:
            missing_version.append(artifact_path)

        # Validate entries + file existence
        for kind, lst in (("semantic", semantic), ("version", version)):
            if not isinstance(lst, list):
                continue
            for g in lst:
                if not isinstance(g, str) or not g.strip():
                    bad_entries.append((artifact_path, kind, repr(g)))
                    continue
                gp = ROOT / g
                if not gp.exists():
                    missing_files.append((artifact_path, kind, g))

        # Hygiene: discourage mapping the exact same list as both semantic and version
        if (
            isinstance(semantic, list)
            and isinstance(version, list)
            and semantic
            and version
        ):
            sem_norm = [x.strip() for x in semantic if isinstance(x, str)]
            ver_norm = [x.strip() for x in version if isinstance(x, str)]
            if sem_norm == ver_norm:
                identical_lists.append(artifact_path)

        # Umbrella-only semantic: if every semantic gate is the umbrella gate,
        # there's no dedicated semantic validation (degenerate governance).
        if isinstance(semantic, list) and semantic:
            sem_stripped = [x.strip() for x in semantic if isinstance(x, str) and x.strip()]
            if sem_stripped and all(x == UMBRELLA_VERSION_GATE for x in sem_stripped):
                umbrella_only_semantic.append(artifact_path)

        # Dedicated version gate enforcement (baseline + budgets).
        if artifact_path in REQUIRE_DEDICATED_VERSION_GATE:
            if isinstance(version, list) and version:
                vnorm = [x.strip() for x in version if isinstance(x, str) and x.strip()]
                dedicated = [x for x in vnorm if x != UMBRELLA_VERSION_GATE]
                if len(dedicated) == 0:
                    missing_dedicated_version_gate.append(artifact_path)
                elif len(dedicated) != 1:
                    multiple_dedicated_version_gates.append(
                        (artifact_path, dedicated)
                    )
            else:
                # If version is missing entirely, existing checks catch it, but include here too.
                missing_dedicated_version_gate.append(artifact_path)

    if any([missing_cov, missing_semantic, missing_version, bad_entries, missing_files, identical_lists, umbrella_only_semantic, missing_dedicated_version_gate, multiple_dedicated_version_gates]):
        lines = ["Manifest self-consistency check failed (coverage intent declaration):"]

        if missing_cov:
            lines.append("Promoted artifacts missing 'coverage' mapping:")
            lines.extend([f"- {p}" for p in missing_cov])

        if missing_semantic:
            lines.append("Promoted artifacts missing coverage.semantic (must be non-empty list):")
            lines.extend([f"- {p}" for p in missing_semantic])

        if missing_version:
            lines.append("Promoted artifacts missing coverage.version (must be non-empty list):")
            lines.extend([f"- {p}" for p in missing_version])

        if bad_entries:
            lines.append("Invalid gate entries:")
            for art, kind, bad in bad_entries:
                lines.append(f"- {art} [{kind}]: {bad}")

        if missing_files:
            lines.append("Referenced gate files missing from repo:")
            for art, kind, g in missing_files:
                lines.append(f"- {art} [{kind}]: missing {g}")

        if identical_lists:
            lines.append("Artifacts with identical semantic+version gate lists (discouraged):")
            lines.extend([f"- {p}" for p in identical_lists])
            lines.append("Tip: semantic gates validate meaning; version gates enforce bump discipline.")

        if umbrella_only_semantic:
            lines.append("Artifacts where all semantic gates are the umbrella gate (degenerate):")
            lines.extend([f"- {p}" for p in umbrella_only_semantic])
            lines.append("Tip: semantic gates should validate meaning/structure, not just version provenance.")

        if missing_dedicated_version_gate:
            lines.append("Artifacts in REQUIRE_DEDICATED_VERSION_GATE with no dedicated (non-umbrella) version gate:")
            lines.extend([f"- {p}" for p in missing_dedicated_version_gate])
            lines.append("Required dedicated version gate test files:")
            lines.append("  - tests/test_openapi_scrub_baseline_requires_signal_logic_bump.py")
            lines.append("  - tests/test_openapi_scrub_budgets_requires_signal_logic_bump.py")

        if multiple_dedicated_version_gates:
            lines.append("Artifacts with multiple dedicated (non-umbrella) version gates (forbidden):")
            for art, ded in multiple_dedicated_version_gates:
                lines.append(f"- {art}")
                for g in ded:
                    lines.append(f"    - {g}")
            lines.append("Policy: baseline + budgets must have exactly one dedicated version gate file each.")

        lines.append("")
        lines.append("Fix:")
        lines.append("  - For each promoted artifact, declare coverage.semantic and coverage.version.")
        lines.append("  - Ensure referenced test files exist and contain collectable tests.")
        raise AssertionError("\n".join(lines))


def test_dedicated_gate_files_are_collectable_tests() -> None:
    """Each listed gate file must be a real pytest test file:

    - file name matches ``test_*.py``
    - file defines at least one ``test_*`` function (top-level or in ``Test*`` class)
    """
    bad_names: list[str] = []
    empty_tests: list[str] = []

    for rel in _gate_files():
        p = ROOT / rel
        assert p.exists(), f"Missing dedicated gate file: {rel}"

        name = p.name
        if not (name.startswith("test_") and name.endswith(".py")):
            bad_names.append(rel)
            continue

        if not _has_pytest_tests(p):
            empty_tests.append(rel)

    if bad_names or empty_tests:
        lines = ["Gate file collection assertion failed:"]
        if bad_names:
            lines.append("Gate files must match pytest naming convention 'test_*.py':")
            lines.extend([f"- {x}" for x in bad_names])
        if empty_tests:
            lines.append("Gate files contain no discoverable tests (no test_* functions):")
            lines.extend([f"- {x}" for x in empty_tests])
        lines.append("")
        lines.append("Fix:")
        lines.append("  - Rename gate files to test_*.py, and/or")
        lines.append("  - Ensure each gate file defines at least one test_… function.")
        raise AssertionError("\n".join(lines))


def test_dedicated_gate_files_are_collected_by_pytest_in_ci() -> None:
    """Strongest assertion: ``pytest --collect-only`` confirms each gate file
    contributes at least one nodeid.  Enabled only when ``CI=true`` to avoid
    adding overhead to local dev runs.
    """
    if os.environ.get("CI", "").lower() not in ("true", "1"):
        return

    out = subprocess.check_output(
        ["python", "-m", "pytest", "--collect-only", "-q"],
        cwd=str(ROOT),
        text=True,
        stderr=subprocess.STDOUT,
    )
    # Node IDs look like: tests/test_file.py::test_name
    collected_files: set[str] = set()
    for line in out.splitlines():
        if "::" in line and line.strip().startswith("tests/"):
            collected_files.add(line.split("::", 1)[0].strip())

    missing: list[str] = []
    for rel in _gate_files():
        if not (Path(rel).name.startswith("test_") and rel.endswith(".py")):
            continue
        if rel not in collected_files:
            missing.append(rel)

    if missing:
        lines = ["Pytest collection assertion failed in CI:"]
        lines.append("The following dedicated gate files did not produce any collected tests:")
        lines.extend([f"- {x}" for x in missing])
        lines.append("")
        lines.append("This usually means:")
        lines.append("  - the file has no test_… functions, or")
        lines.append("  - tests are being skipped/guarded at import-time, or")
        lines.append("  - collection patterns were changed.")
        raise AssertionError("\n".join(lines))
