#!/usr/bin/env python3
"""Build a deterministic, self-describing release BOM (bill of materials).

Produces ``dist/release_bom.json`` capturing:

- versions (tool_version, engine_version, signal_logic_version)
- schema IDs and schema file hashes
- all contract manifests and their hashes
- promoted artifacts hashes (baseline/budgets/policy/endpoints)
- Web API (OpenAPI) snapshot + validator manifest + endpoint registry
- git metadata (commit SHA, tag if present)

Determinism guarantees:
  - stable sort keys
  - stable ordering of lists
  - no timestamps (unless ``--include-timestamp`` is passed)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUT_DEFAULT = ROOT / "dist" / "release_bom.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def must_read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def git(cmd: list[str]) -> str:
    return subprocess.check_output(["git", *cmd], cwd=str(ROOT), text=True).strip()


def try_git_tag() -> str | None:
    # If running on a tag in CI, GITHUB_REF_NAME is usually set to the tag name.
    ref = os.environ.get("GITHUB_REF_NAME", "").strip()
    if ref.startswith("v") and ref.count(".") >= 2:
        return ref
    # Fallback: try describe exact tag
    try:
        t = git(["describe", "--tags", "--exact-match"])
        return t or None
    except Exception:
        return None


def read_pyproject_version() -> str:
    txt = must_read_text(ROOT / "pyproject.toml")
    m = re.search(r'^\s*version\s*=\s*"([^"]+)"\s*$', txt, flags=re.MULTILINE)
    if not m:
        raise SystemExit("Could not parse version from pyproject.toml")
    return m.group(1)


def read_run_result_versions() -> dict[str, str]:
    p = ROOT / "src" / "code_audit" / "model" / "run_result.py"
    txt = must_read_text(p)

    def grab(name: str) -> str:
        m = re.search(rf'\b{name}(?:\s*:\s*\S+)?\s*=\s*"([^"]+)"', txt)
        if not m:
            raise SystemExit(f"Could not locate {name} in {p}")
        return m.group(1)

    return {
        "engine_version": grab("engine_version"),
        "signal_logic_version": grab("signal_logic_version"),
    }


def load_json(path: Path) -> Any:
    return json.loads(must_read_text(path))


def record_file(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": sha256_file(path),
    }


def maybe_record(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path.relative_to(ROOT)), "present": False}
    d = record_file(path)
    d["present"] = True
    return d


def main() -> int:
    out = Path(os.environ.get("RELEASE_BOM_OUT", str(OUT_DEFAULT)))
    out.parent.mkdir(parents=True, exist_ok=True)

    tool_version = read_pyproject_version()
    rr = read_run_result_versions()

    commit = git(["rev-parse", "HEAD"])
    tag = try_git_tag()

    # Core schemas
    schemas_dir = ROOT / "schemas"
    schemas = {
        "run_result": maybe_record(schemas_dir / "run_result.schema.json"),
        "debt_snapshot": maybe_record(schemas_dir / "debt_snapshot.schema.json"),
        "signals_latest": maybe_record(schemas_dir / "signals_latest.schema.json"),
        "user_event": maybe_record(schemas_dir / "user_event.schema.json"),
    }

    # Canonical contract manifests
    contracts_dir = ROOT / "tests" / "contracts"
    manifests = {
        "golden_fixtures_manifest": maybe_record(contracts_dir / "golden_fixtures_manifest.json"),
        "logic_manifest": maybe_record(contracts_dir / "logic_manifest.json"),
        "translator_policy_manifest": maybe_record(contracts_dir / "translator_policy_manifest.json"),
        # OpenAPI volatility governance artifacts (promoted under golden manifest)
        "openapi_scrub_baseline": maybe_record(contracts_dir / "openapi_scrub_audit_baseline.json"),
        "openapi_scrub_budgets": maybe_record(contracts_dir / "openapi_scrub_budgets.json"),
        "openapi_scrub_policy": maybe_record(contracts_dir / "openapi_golden_scrub_policy.json"),
        "openapi_endpoints_registry": maybe_record(contracts_dir / "openapi_golden_endpoints.json"),
        "openapi_scrub_audit_baseline_manifest": maybe_record(contracts_dir / "openapi_scrub_baseline_manifest.json"),
        "openapi_scrub_budgets_manifest": maybe_record(contracts_dir / "openapi_scrub_budgets_manifest.json"),
    }

    # Web API (OpenAPI) snapshot + validator manifest + endpoint registry
    # These make the release self-describing for the API surface.
    web_api = {
        "openapi_snapshot": maybe_record(ROOT / "docs" / "openapi.json"),
        "openapi_validator_manifest": maybe_record(contracts_dir / "openapi_manifest.json"),
        # Optional: dedicated validator manifest file
        "openapi_schema_validator_manifest": maybe_record(contracts_dir / "openapi_schema_validator_manifest.json"),
        # Endpoint registry + schema (public+stable selection surface)
        "openapi_endpoint_registry": maybe_record(contracts_dir / "openapi_golden_endpoints.json"),
        "openapi_endpoint_registry_schema": maybe_record(contracts_dir / "openapi_golden_endpoints.schema.json"),
    }

    bom = {
        "bom_version": 1,
        "repo": "code-analysis-tool",
        "git": {
            "commit": commit,
            "tag": tag,
        },
        "versions": {
            "tool_version": tool_version,
            **rr,
        },
        "schemas": schemas,
        "contracts": manifests,
        "web_api": web_api,
    }

    out.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
