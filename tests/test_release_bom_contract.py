"""Release BOM contract tests.

Ensures:
  - BOM is buildable and self-consistent (hashes match repo files)
  - BOM tag matches pyproject.toml version on tagged CI
  - BOM proves golden manifest includes promoted OpenAPI artifacts
  - BOM web_api records (snapshot, validator manifest, registry, schema) hash correctly
  - Release requires OpenAPI snapshot + manifest + registry + schema on tagged CI
  - Release validates endpoint registry against its schema on tagged CI
  - Release enforces registry sorted + unique invariants on tagged CI
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist" / "release_bom.json"


def _sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_bom() -> None:
    subprocess.check_call(["python", "scripts/build_release_bom.py"], cwd=str(ROOT))


def _is_tagged_ci() -> tuple[bool, str]:
    if os.environ.get("CI", "").lower() not in ("true", "1"):
        return False, ""
    tag = os.environ.get("GITHUB_REF_NAME", "").strip()
    if tag.startswith("v") and tag.count(".") >= 2:
        return True, tag
    return False, ""


# ── Core BOM self-consistency ───────────────────────────────────────────


def test_release_bom_is_buildable_and_self_consistent() -> None:
    """Build BOM deterministically and verify all recorded hashes match repo files."""
    _build_bom()
    assert OUT.exists(), "release_bom.json not generated"

    bom = json.loads(OUT.read_text(encoding="utf-8"))
    assert bom.get("bom_version") == 1
    assert bom.get("repo") == "code-analysis-tool"

    versions = bom.get("versions") or {}
    assert isinstance(versions, dict)
    assert isinstance(versions.get("tool_version"), str) and versions["tool_version"]
    assert isinstance(versions.get("engine_version"), str) and versions["engine_version"]
    assert isinstance(versions.get("signal_logic_version"), str) and versions["signal_logic_version"]

    # Verify hashes for any present file records
    def verify_record(record: dict) -> None:
        assert "path" in record
        rel = record["path"]
        p = ROOT / rel
        present = record.get("present", True)
        if present is False:
            assert not p.exists(), f"Record says not present but file exists: {rel}"
            return
        assert p.exists(), f"Missing file referenced by BOM: {rel}"
        assert record.get("sha256") == _sha256(p), f"Hash mismatch for {rel}"

    schemas = bom.get("schemas") or {}
    assert isinstance(schemas, dict)
    for rec in schemas.values():
        assert isinstance(rec, dict)
        verify_record(rec)

    contracts = bom.get("contracts") or {}
    assert isinstance(contracts, dict)
    for rec in contracts.values():
        assert isinstance(rec, dict)
        verify_record(rec)

    web_api = bom.get("web_api") or {}
    assert isinstance(web_api, dict)
    for rec in web_api.values():
        assert isinstance(rec, dict)
        verify_record(rec)


# ── Tag/version discipline (tagged CI only) ────────────────────────────


def test_release_bom_tag_matches_pyproject_version_on_tagged_ci() -> None:
    """On tagged CI, tag vX.Y.Z must match pyproject.toml version X.Y.Z."""
    is_tagged, tag = _is_tagged_ci()
    if not is_tagged:
        return

    _build_bom()
    bom = json.loads(OUT.read_text(encoding="utf-8"))
    tool_version = bom["versions"]["tool_version"]
    assert tag == f"v{tool_version}", f"Tag {tag} must match pyproject version v{tool_version}"


# ── BOM proves golden manifest includes promoted OpenAPI artifacts ──────


def test_release_bom_proves_golden_manifest_includes_promoted_openapi_artifacts() -> None:
    """
    Release-hardening gate:
    The BOM must prove that the golden fixtures manifest (the unified contract gate)
    actually includes the promoted OpenAPI contract artifacts.
    """
    _build_bom()
    assert OUT.exists(), "release_bom.json not generated"

    bom = json.loads(OUT.read_text(encoding="utf-8"))
    contracts = bom.get("contracts") or {}
    assert isinstance(contracts, dict)

    gm = contracts.get("golden_fixtures_manifest") or {}
    assert isinstance(gm, dict)
    gm_path = gm.get("path")
    gm_present = gm.get("present", True)
    assert gm_present is True, "golden_fixtures_manifest must be present in BOM"
    assert isinstance(gm_path, str) and gm_path, "golden_fixtures_manifest.path missing in BOM"

    golden_manifest_path = ROOT / gm_path
    assert golden_manifest_path.exists(), f"Missing golden manifest at {gm_path}"

    golden_manifest = json.loads(golden_manifest_path.read_text(encoding="utf-8"))
    files = golden_manifest.get("files")

    # Support both dict format ({"path": "sha256:..."}) and list format ([{"path": ...}])
    golden_paths: set[str] = set()
    if isinstance(files, dict):
        golden_paths = set(files.keys())
    elif isinstance(files, list):
        for entry in files:
            if isinstance(entry, dict):
                p = entry.get("path")
                if isinstance(p, str) and p:
                    golden_paths.add(p)
    else:
        raise AssertionError("golden_fixtures_manifest.json must contain 'files' (dict or list)")

    required = [
        "tests/contracts/openapi_scrub_audit_baseline.json",
        "tests/contracts/openapi_scrub_budgets.json",
        "tests/contracts/openapi_golden_scrub_policy.json",
        "tests/contracts/openapi_golden_endpoints.json",
    ]

    missing = [p for p in required if p not in golden_paths]
    if missing:
        lines = [
            "Release gate failed: golden_fixtures_manifest.json does not include "
            "required promoted OpenAPI artifacts.",
            "",
            "Missing entries:",
        ]
        lines.extend([f"- {p}" for p in missing])
        lines.append("")
        lines.append("Fix:")
        lines.append("  1) Ensure scripts/refresh_golden_manifest.py promotes these artifacts (required-present mode).")
        lines.append("  2) Run: python scripts/refresh_golden_manifest.py")
        lines.append("  3) Commit updated tests/contracts/golden_fixtures_manifest.json")
        raise AssertionError("\n".join(lines))


# ── Release requires Web API artifacts on tagged CI ─────────────────────


def test_release_requires_openapi_snapshot_and_manifest_on_tagged_ci() -> None:
    """
    Release-hardening requirement:
    On tagged CI builds, a release must be self-describing for the Web API surface.
    """
    is_tagged, tag = _is_tagged_ci()
    if not is_tagged:
        return

    _build_bom()
    bom = json.loads(OUT.read_text(encoding="utf-8"))
    web_api = bom.get("web_api") or {}
    assert isinstance(web_api, dict)

    missing = []
    for k in (
        "openapi_snapshot",
        "openapi_validator_manifest",
        "openapi_endpoint_registry",
        "openapi_endpoint_registry_schema",
    ):
        rec = web_api.get(k) or {}
        if not isinstance(rec, dict) or rec.get("present") is not True:
            missing.append(k)

    if missing:
        lines = ["Release gate failed: OpenAPI self-description required on tagged CI."]
        lines.append(f"Tag: {tag}")
        lines.append("Missing BOM entries (present=false):")
        for m in missing:
            lines.append(f"- web_api.{m}")
        lines.append("")
        lines.append("Fix:")
        lines.append("  - Ensure docs/openapi.json exists (snapshot generator writes it),")
        lines.append("  - Ensure tests/contracts/openapi_manifest.json exists (validator manifest),")
        lines.append("  - Ensure tests/contracts/openapi_golden_endpoints.json exists (endpoint registry),")
        lines.append("  - Ensure tests/contracts/openapi_golden_endpoints.schema.json exists (registry schema),")
        lines.append("  - Re-run snapshot/manifest refresh scripts and commit outputs.")
        raise AssertionError("\n".join(lines))


# ── BOM validates registry against schema on tagged CI ──────────────────


def test_release_bom_validates_endpoint_registry_against_schema_on_tagged_ci() -> None:
    """
    Release gate (tagged CI):
    Validate the endpoint registry JSON against its schema using paths recorded in the BOM.
    This is defense-in-depth: the release artifact proves the registry is schema-valid.
    """
    is_tagged, tag = _is_tagged_ci()
    if not is_tagged:
        return

    _build_bom()
    assert OUT.exists(), "release_bom.json not generated"

    bom = json.loads(OUT.read_text(encoding="utf-8"))
    web_api = bom.get("web_api") or {}
    assert isinstance(web_api, dict)

    reg_rec = web_api.get("openapi_endpoint_registry") or {}
    schema_rec = web_api.get("openapi_endpoint_registry_schema") or {}
    assert isinstance(reg_rec, dict) and isinstance(schema_rec, dict)

    if reg_rec.get("present") is not True or schema_rec.get("present") is not True:
        raise AssertionError(
            "Release gate failed: endpoint registry and schema must be present in BOM on tagged CI.\n"
            f"Tag: {tag}\n"
            f"openapi_endpoint_registry present={reg_rec.get('present')}\n"
            f"openapi_endpoint_registry_schema present={schema_rec.get('present')}\n"
        )

    reg_path = reg_rec.get("path")
    schema_path = schema_rec.get("path")
    assert isinstance(reg_path, str) and reg_path
    assert isinstance(schema_path, str) and schema_path

    reg_file = ROOT / reg_path
    schema_file = ROOT / schema_path
    assert reg_file.exists(), f"Missing registry file recorded in BOM: {reg_path}"
    assert schema_file.exists(), f"Missing registry schema recorded in BOM: {schema_path}"

    registry = json.loads(reg_file.read_text(encoding="utf-8"))
    schema = json.loads(schema_file.read_text(encoding="utf-8"))

    try:
        jsonschema.validate(instance=registry, schema=schema)
    except jsonschema.ValidationError as e:
        lines = [
            "Release gate failed: endpoint registry is not valid under its schema.",
            f"Tag: {tag}",
            f"Registry: {reg_path}",
            f"Schema:   {schema_path}",
            "",
            f"ValidationError: {e.message}",
        ]
        if getattr(e, "path", None):
            lines.append(f"Instance path: {'/'.join([str(x) for x in e.path])}")
        if getattr(e, "schema_path", None):
            lines.append(f"Schema path: {'/'.join([str(x) for x in e.schema_path])}")
        raise AssertionError("\n".join(lines)) from e


# ── BOM enforces registry sorted + unique on tagged CI ──────────────────


def test_release_bom_enforces_endpoint_registry_sorted_unique_on_tagged_ci() -> None:
    """
    Release gate (tagged CI):
    Enforce endpoint registry deterministic invariants (unique + sorted) using BOM-recorded paths.
    Defense-in-depth in case a future release path skips the dedicated registry tests.
    """
    is_tagged, tag = _is_tagged_ci()
    if not is_tagged:
        return

    _build_bom()
    assert OUT.exists(), "release_bom.json not generated"

    bom = json.loads(OUT.read_text(encoding="utf-8"))
    web_api = bom.get("web_api") or {}
    assert isinstance(web_api, dict)

    reg_rec = web_api.get("openapi_endpoint_registry") or {}
    assert isinstance(reg_rec, dict)
    if reg_rec.get("present") is not True:
        raise AssertionError(
            "Release gate failed: endpoint registry must be present in BOM on tagged CI.\n"
            f"Tag: {tag}\n"
            f"openapi_endpoint_registry present={reg_rec.get('present')}\n"
        )

    reg_path = reg_rec.get("path")
    assert isinstance(reg_path, str) and reg_path
    reg_file = ROOT / reg_path
    assert reg_file.exists(), f"Missing registry file recorded in BOM: {reg_path}"

    registry = json.loads(reg_file.read_text(encoding="utf-8"))

    # Import endpoint extraction from the registry gate test
    from tests.test_release_openapi_registry_matches_snapshot import _extract_registry_endpoints

    endpoints = _extract_registry_endpoints(registry)
    assert endpoints, "Endpoint registry must contain at least one endpoint"

    # Uniqueness by (METHOD, path)
    seen: set[tuple[str, str]] = set()
    dups: list[tuple[str, str]] = []
    for ep in endpoints:
        if ep in seen:
            dups.append(ep)
        else:
            seen.add(ep)
    if dups:
        lines = [
            "Release gate failed: endpoint registry contains duplicate endpoints (METHOD, path).",
            f"Tag: {tag}",
            f"Registry: {reg_path}",
            "",
            "Duplicates:",
        ]
        lines.extend([f"- {m} {p}" for (m, p) in dups])
        raise AssertionError("\n".join(lines))

    # Sorted deterministically by (path, method)
    sorted_endpoints = sorted(endpoints, key=lambda t: (t[1], t[0]))
    if endpoints != sorted_endpoints:
        lines = [
            "Release gate failed: endpoint registry is not sorted by (path, method).",
            f"Tag: {tag}",
            f"Registry: {reg_path}",
            "",
            "Expected order:",
        ]
        lines.extend([f"- {m} {p}" for (m, p) in sorted_endpoints])
        lines.append("")
        lines.append("Fix: sort the endpoints deterministically in tests/contracts/openapi_golden_endpoints.json.")
        raise AssertionError("\n".join(lines))
