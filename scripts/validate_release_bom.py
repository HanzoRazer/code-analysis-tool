"""Validate a release BOM JSON file against the BOM schema.

Usage:
    python scripts/validate_release_bom.py dist/release_bom.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "dist" / "release_bom.schema.json"


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <bom.json>", file=sys.stderr)
        return 2

    bom_path = Path(sys.argv[1])
    if not bom_path.exists():
        print(f"File not found: {bom_path}", file=sys.stderr)
        return 1

    if not SCHEMA_PATH.exists():
        print(f"Schema not found: {SCHEMA_PATH}", file=sys.stderr)
        print("Run the release gate + BOM generator first to populate dist/.", file=sys.stderr)
        return 1

    try:
        import jsonschema  # type: ignore
    except ImportError:
        print("jsonschema package not installed; cannot validate.", file=sys.stderr)
        return 1

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    bom = json.loads(bom_path.read_text(encoding="utf-8"))

    validator = jsonschema.Draft202012Validator(schema)
    errors = list(validator.iter_errors(bom))

    if not errors:
        print(f"[validate-release-bom] OK: {bom_path} is valid.")
        return 0

    print(f"[validate-release-bom] FAIL: {len(errors)} validation error(s).")
    for i, err in enumerate(errors[:20]):
        path = ".".join(str(p) for p in err.absolute_path) or "(root)"
        print(f"  [{i + 1}] {path}: {err.message}")
    if len(errors) > 20:
        print(f"  ... ({len(errors) - 20} more)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
