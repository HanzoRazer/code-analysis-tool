"""Validate an OpenAPI release gate result JSON file against its schema.

Usage:
    python scripts/validate_openapi_release_gate_result.py result.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "openapi_release_gate_result.schema.json"
SCHEMA_DIR = ROOT / "schemas"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <gate_result.json>", file=sys.stderr)
        return 2

    target_path = Path(sys.argv[1])
    if not target_path.exists():
        print(f"File not found: {target_path}", file=sys.stderr)
        return 1

    if not SCHEMA.exists():
        print(f"Schema not found: {SCHEMA}", file=sys.stderr)
        return 1

    try:
        import jsonschema
        from jsonschema import RefResolver
    except ImportError:
        print("jsonschema package not installed; cannot validate.", file=sys.stderr)
        return 1

    schema = _load_json(SCHEMA)
    obj = _load_json(target_path)

    # Resolve $ref relative to schemas/ directory.
    resolver = RefResolver(base_uri=SCHEMA_DIR.as_uri() + "/", referrer=schema)
    v = jsonschema.Draft202012Validator(schema, resolver=resolver)
    errors = list(v.iter_errors(obj))

    if not errors:
        print(f"[validate-openapi-gate-result] OK: {target_path} is valid.")
        return 0

    print(f"[validate-openapi-gate-result] FAIL: {len(errors)} validation error(s).")
    for i, err in enumerate(errors[:20]):
        path = ".".join(str(p) for p in err.absolute_path) or "(root)"
        print(f"  [{i + 1}] {path}: {err.message}")
    if len(errors) > 20:
        print(f"  ... ({len(errors) - 20} more)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
