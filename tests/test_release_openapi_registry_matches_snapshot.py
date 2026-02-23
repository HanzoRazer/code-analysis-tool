"""Release gate: endpoint registry entries must exist in the OpenAPI snapshot.

Verifies every endpoint in ``openapi_golden_endpoints.json`` actually exists
in ``docs/openapi.json`` (method + path), with template-shape fallback
matching via ``openapi_path_match.normalize_openapi_path_template``.

Also enforces:
  - method validity (uppercase, known HTTP verb)
  - object-form-only entries (string form banned)
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from code_audit.web_api.openapi_path_match import normalize_openapi_path_template


ROOT = Path(__file__).resolve().parents[1]
BOM_PATH = ROOT / "dist" / "release_bom.json"

# Repo defaults (used if BOM is missing or omits these paths in non-release contexts)
DEFAULT_OPENAPI_SNAPSHOT = ROOT / "docs" / "openapi.json"
DEFAULT_ENDPOINT_REGISTRY = ROOT / "tests" / "contracts" / "openapi_golden_endpoints.json"


ALLOWED_HTTP_VERBS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "TRACE",
}


def _normalize_method(m: str) -> str:
    return m.strip().upper()


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_tagged_ci_release() -> bool:
    if os.environ.get("CI", "").lower() not in ("true", "1"):
        return False
    ref = os.environ.get("GITHUB_REF_NAME", "").strip()
    return ref.startswith("v") and ref.count(".") >= 2


def _build_bom() -> None:
    subprocess.check_call(["python", "scripts/build_release_bom.py"], cwd=str(ROOT))


def _resolve_paths_from_bom() -> tuple[Path, Path]:
    """Returns (openapi_snapshot_path, endpoint_registry_path) based on release_bom.json.

    Falls back to repo defaults if fields are missing (useful for local dev).
    """
    if not BOM_PATH.exists():
        return (DEFAULT_OPENAPI_SNAPSHOT, DEFAULT_ENDPOINT_REGISTRY)

    bom = _load_json(BOM_PATH)
    web_api = bom.get("web_api") or {}
    contracts = bom.get("contracts") or {}

    snap = None
    reg = None

    if isinstance(web_api, dict):
        rec = web_api.get("openapi_snapshot") or {}
        if isinstance(rec, dict) and rec.get("present") is True and isinstance(rec.get("path"), str):
            snap = ROOT / rec["path"]

    # endpoint registry is recorded under contracts in build_release_bom.py
    if isinstance(contracts, dict):
        rec = contracts.get("openapi_endpoints_registry") or {}
        if isinstance(rec, dict) and rec.get("present") is True and isinstance(rec.get("path"), str):
            reg = ROOT / rec["path"]

    return (snap or DEFAULT_OPENAPI_SNAPSHOT, reg or DEFAULT_ENDPOINT_REGISTRY)


def _extract_registry_endpoints(registry: dict) -> list[tuple[str, str]]:
    """Extract validated (METHOD, path) tuples from the endpoint registry.

    Enforces:
      - object-form only (string entries banned)
      - method must be uppercase canonical
      - method must be a valid HTTP verb
      - path must be non-empty
    """
    eps = registry.get("endpoints")
    out: list[tuple[str, str]] = []
    if isinstance(eps, list):
        for e in eps:
            if isinstance(e, str):
                raise AssertionError(
                    "Endpoint registry string entries are forbidden. "
                    'Use object form: {"method": "GET", "path": "/..."}.\n'
                    f"Invalid entry: {e!r}"
                )
            if isinstance(e, dict):
                m = e.get("method")
                p = e.get("path")
                if not isinstance(m, str) or not m.strip():
                    raise AssertionError(
                        f"Endpoint registry contains missing/blank method in entry: {e!r}"
                    )
                if not isinstance(p, str) or not p.strip():
                    raise AssertionError(
                        f"Endpoint registry contains missing/blank path in entry: {e!r}"
                    )

                method = _normalize_method(m)
                path = p.strip()

                # Enforce canonical uppercase in registry
                if m.strip() != method:
                    raise AssertionError(
                        f"Endpoint registry method must be uppercase canonical: "
                        f"got {m!r}, expected {method!r} for path {path!r}"
                    )
                if method not in ALLOWED_HTTP_VERBS:
                    raise AssertionError(
                        f"Endpoint registry contains invalid HTTP verb {method!r} "
                        f"for path {path!r}. Allowed: {sorted(ALLOWED_HTTP_VERBS)}"
                    )
                out.append((method, path))
    return out


# ── Tests ───────────────────────────────────────────────────────────────


def test_release_openapi_registry_exists_in_snapshot() -> None:
    """
    Release gate (tagged CI):
      Every endpoint in openapi_golden_endpoints.json must exist in docs/openapi.json snapshot.

    This ties:
      - endpoint registry (public+stable selection surface)
      - openapi snapshot (documented API surface)
    into the same governed release artifact set.
    """
    if _is_tagged_ci_release():
        _build_bom()

    openapi_path, registry_path = _resolve_paths_from_bom()

    if not openapi_path.exists() or not registry_path.exists():
        # Only hard-fail on tagged CI; local dev may not have these files
        if _is_tagged_ci_release():
            assert openapi_path.exists(), f"Missing OpenAPI snapshot: {openapi_path.relative_to(ROOT)}"
            assert registry_path.exists(), f"Missing endpoint registry: {registry_path.relative_to(ROOT)}"
        return

    openapi = _load_json(openapi_path)
    registry = _load_json(registry_path)

    paths = openapi.get("paths")
    assert isinstance(paths, dict), "OpenAPI snapshot missing 'paths' object"

    endpoints = _extract_registry_endpoints(registry)
    assert endpoints, "Endpoint registry contains no endpoints"

    snapshot_paths = sorted([p for p in paths.keys() if isinstance(p, str)])

    missing = []
    for method, path in endpoints:
        snapshot_path = None

        # 1) Exact match (preferred)
        if path in paths:
            snapshot_path = path
        else:
            # 2) Template-shape match (param names ignored)
            target_norm = normalize_openapi_path_template(path)
            candidates = [
                sp for sp in snapshot_paths if normalize_openapi_path_template(sp) == target_norm
            ]
            if len(candidates) == 1:
                snapshot_path = candidates[0]
            elif len(candidates) > 1:
                missing.append(
                    f"{method} {path} (ambiguous template match; candidates: {', '.join(candidates)})"
                )
                continue
            else:
                missing.append(f"{method} {path} (path missing)")
                continue

        item = paths.get(snapshot_path)
        if not isinstance(item, dict):
            missing.append(f"{method} {path} (path item not an object)")
            continue
        op = item.get(method.strip().lower())
        if op is None:
            missing.append(f"{method} {path} (method missing)")

    if missing:
        lines = [
            "Release gate failed: endpoint registry includes endpoints not present in OpenAPI snapshot.",
            f"Snapshot: {openapi_path.relative_to(ROOT)}",
            f"Registry:  {registry_path.relative_to(ROOT)}",
            "",
            "Missing endpoints:",
        ]
        lines.extend([f"- {m}" for m in missing])
        lines.append("")
        lines.append("Fix options:")
        lines.append("  1) Regenerate docs/openapi.json from the current web_api (preferred), or")
        lines.append("  2) Update tests/contracts/openapi_golden_endpoints.json to match the snapshot,")
        lines.append(
            "  3) If this reflects an intentional breaking/removal, "
            "ensure changelog + semver gates reflect it."
        )
        raise AssertionError("\n".join(lines))
