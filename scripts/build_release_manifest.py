#!/usr/bin/env python3
"""Build a semantic BOM (bill of materials) for a release.

Captures the exact contract state shipped in a release:
  - git SHA, tag, build timestamp
  - package version from pyproject.toml
  - engine_version, signal_logic_version, confidence_logic_version
  - schema IDs + schema file hashes
  - contract manifest hashes

Usage:
  python scripts/build_release_manifest.py --out dist/release_manifest.json
  python scripts/build_release_manifest.py --strict --out dist/release_manifest.json

The --strict flag fails if core manifests are missing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_pyproject_version() -> str:
    pyproject = ROOT / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    v = (data.get("project") or {}).get("version")
    if not isinstance(v, str) or not v.strip():
        raise SystemExit("pyproject.toml missing [project].version")
    return v.strip()


def read_const_from_file(path: Path, name: str) -> str | None:
    """Extract a string constant: ``name = "value"`` or ``name: type = "value"``."""
    if not path.exists():
        return None
    txt = path.read_text(encoding="utf-8")
    # Matches both plain assignment and dataclass field defaults with type annotation
    m = re.search(rf'\b{name}(?:\s*:\s*\S+)?\s*=\s*"([^"]+)"', txt)
    return m.group(1) if m else None


def safe_load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def maybe_add_manifest(out: dict, key: str, path: Path) -> None:
    if not path.exists():
        out["manifests"][key] = {"present": False, "path": str(path.relative_to(ROOT))}
        return
    payload = safe_load_json(path)
    out["manifests"][key] = {
        "present": True,
        "path": str(path.relative_to(ROOT)),
        "sha256": sha256_file(path),
        "manifest_version": payload.get("manifest_version"),
        "signal_logic_version": payload.get("signal_logic_version"),
        "confidence_logic_version": payload.get("confidence_logic_version"),
    }


def add_schema(out: dict, name: str, path: Path) -> None:
    if not path.exists():
        raise SystemExit(f"Missing schema file: {path}")
    payload = safe_load_json(path)
    out["schemas"][name] = {
        "path": str(path.relative_to(ROOT)),
        "sha256": sha256_file(path),
        "$id": payload.get("$id"),
        "schema_version": payload.get("schema_version"),
        "title": payload.get("title"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Build semantic release BOM")
    ap.add_argument("--out", default="dist/release_manifest.json", help="Output path")
    ap.add_argument("--strict", action="store_true", help="Fail if core manifests are missing")
    args = ap.parse_args()

    tag = (os.environ.get("GITHUB_REF_NAME") or "").strip()
    sha = (os.environ.get("GITHUB_SHA") or "").strip()

    # Versions
    run_result_py = ROOT / "src" / "code_audit" / "model" / "run_result.py"
    confidence_py = ROOT / "src" / "code_audit" / "insights" / "confidence.py"

    engine_version = read_const_from_file(run_result_py, "engine_version")
    signal_logic_version = read_const_from_file(run_result_py, "signal_logic_version")
    confidence_logic_version = read_const_from_file(confidence_py, "confidence_logic_version")

    # Core anchors must exist
    if not engine_version or not signal_logic_version:
        raise SystemExit(
            "Missing engine_version or signal_logic_version in src/code_audit/model/run_result.py"
        )

    bom: dict = {
        "bom_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git": {
            "tag": tag or None,
            "sha": sha or None,
        },
        "package": {
            "name": "code_audit",
            "version": read_pyproject_version(),
        },
        "anchors": {
            "engine_version": engine_version,
            "signal_logic_version": signal_logic_version,
            "confidence_logic_version": confidence_logic_version,
        },
        "schemas": {},
        "manifests": {},
    }

    # Schemas (these are public contract surfaces)
    add_schema(bom, "run_result", ROOT / "schemas" / "run_result.schema.json")
    add_schema(bom, "debt_snapshot", ROOT / "schemas" / "debt_snapshot.schema.json")

    # Optional schemas (include if present)
    for opt_name, opt_path in [
        ("signals_latest", ROOT / "schemas" / "signals_latest.schema.json"),
        ("user_event", ROOT / "schemas" / "user_event.schema.json"),
        ("drift_budget_signal", ROOT / "schemas" / "drift_budget_signal.schema.json"),
    ]:
        if opt_path.exists():
            add_schema(bom, opt_name, opt_path)

    # Contract manifests (all should exist in governed mode)
    maybe_add_manifest(
        bom, "golden_fixtures_manifest",
        ROOT / "tests" / "contracts" / "golden_fixtures_manifest.json",
    )
    maybe_add_manifest(
        bom, "translator_policy_manifest",
        ROOT / "tests" / "contracts" / "translator_policy_manifest.json",
    )
    maybe_add_manifest(
        bom, "logic_manifest",
        ROOT / "tests" / "contracts" / "logic_manifest.json",
    )

    # Optional manifests depending on which hardening steps are present
    maybe_add_manifest(
        bom, "exit_code_policy_manifest",
        ROOT / "tests" / "contracts" / "exit_code_policy_manifest.json",
    )
    maybe_add_manifest(
        bom, "confidence_golden_manifest",
        ROOT / "tests" / "contracts" / "confidence_golden_manifest.json",
    )
    maybe_add_manifest(
        bom, "confidence_policy_manifest",
        ROOT / "tests" / "contracts" / "confidence_policy_manifest.json",
    )
    maybe_add_manifest(
        bom, "drift_budget_signal_manifest",
        ROOT / "tests" / "contracts" / "drift_budget_signal_manifest.json",
    )
    maybe_add_manifest(
        bom, "rule_registry_manifest",
        ROOT / "tests" / "contracts" / "rule_registry_manifest.json",
    )
    maybe_add_manifest(
        bom, "public_rule_registry_manifest",
        ROOT / "tests" / "contracts" / "public_rule_registry_manifest.json",
    )
    maybe_add_manifest(
        bom, "openapi_manifest",
        ROOT / "tests" / "contracts" / "openapi_manifest.json",
    )
    maybe_add_manifest(
        bom, "openapi_scrub_baseline_manifest",
        ROOT / "tests" / "contracts" / "openapi_scrub_baseline_manifest.json",
    )
    maybe_add_manifest(
        bom, "openapi_scrub_budgets_manifest",
        ROOT / "tests" / "contracts" / "openapi_scrub_budgets_manifest.json",
    )

    # OpenAPI scrub budgets file (if present)
    budgets_file = ROOT / "tests" / "contracts" / "openapi_scrub_budgets.json"
    if budgets_file.exists():
        bom["manifests"]["openapi_scrub_budgets_file"] = {
            "present": True,
            "path": str(budgets_file.relative_to(ROOT)),
            "sha256": sha256_file(budgets_file),
        }
    else:
        bom["manifests"]["openapi_scrub_budgets_file"] = {
            "present": False,
            "path": str(budgets_file.relative_to(ROOT)),
        }

    # OpenAPI snapshot (if present)
    openapi_snapshot = ROOT / "docs" / "openapi.json"
    if openapi_snapshot.exists():
        bom["manifests"]["openapi_snapshot"] = {
            "present": True,
            "path": str(openapi_snapshot.relative_to(ROOT)),
            "sha256": sha256_file(openapi_snapshot),
        }
    else:
        bom["manifests"]["openapi_snapshot"] = {
            "present": False,
            "path": str(openapi_snapshot.relative_to(ROOT)),
        }

    # Rule registry file (if present)
    rr_file = ROOT / "docs" / "rule_registry.json"
    if rr_file.exists():
        bom["manifests"]["rule_registry_file"] = {
            "present": True,
            "path": str(rr_file.relative_to(ROOT)),
            "sha256": sha256_file(rr_file),
        }
    else:
        bom["manifests"]["rule_registry_file"] = {
            "present": False,
            "path": str(rr_file.relative_to(ROOT)),
        }

    # Strict mode: fail if core manifests are missing
    if args.strict:
        required = [
            "golden_fixtures_manifest",
            "translator_policy_manifest",
            "logic_manifest",
        ]
        missing = [
            k for k in required
            if not bom["manifests"].get(k, {}).get("present")
        ]
        if missing:
            print(
                f"Strict release BOM failed: missing required manifests: {missing}",
                file=sys.stderr,
            )
            return 1

    # Write output
    out_path = (ROOT / args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(bom, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
