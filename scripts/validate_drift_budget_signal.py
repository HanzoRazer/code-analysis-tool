"""Validate a drift_budget_signal_v1 JSON artifact against its JSON Schema.

Usage:
    python scripts/validate_drift_budget_signal.py artifacts/drift_budget_signal.json
    python scripts/validate_drift_budget_signal.py --schema schemas/drift_budget_signal.schema.json artifacts/drift_budget_signal.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("error: jsonschema package required — pip install jsonschema", file=sys.stderr)
    sys.exit(1)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = REPO_ROOT / "schemas" / "drift_budget_signal.schema.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate drift budget signal artifact")
    parser.add_argument("artifact", help="Path to the drift_budget_signal.json artifact")
    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA),
        help="Path to the JSON Schema (default: schemas/drift_budget_signal.schema.json)",
    )
    args = parser.parse_args()

    schema_path = Path(args.schema)
    artifact_path = Path(args.artifact)

    if not schema_path.exists():
        print(f"error: schema not found: {schema_path}", file=sys.stderr)
        return 1
    if not artifact_path.exists():
        print(f"error: artifact not found: {artifact_path}", file=sys.stderr)
        return 1

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))

    try:
        jsonschema.validate(instance=artifact, schema=schema)
    except jsonschema.ValidationError as e:
        print(f"drift budget signal INVALID: {e.message}", file=sys.stderr)
        print(f"  path: {'.'.join(str(p) for p in e.absolute_path)}", file=sys.stderr)
        return 1

    print("drift budget signal OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
