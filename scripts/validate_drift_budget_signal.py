"""Validate a drift_budget_signal_v1 JSON artifact against its JSON Schema.

Usage:
    python scripts/validate_drift_budget_signal.py artifacts/drift_budget_signal.json
    python scripts/validate_drift_budget_signal.py --schema schemas/drift_budget_signal.schema.json artifacts/drift_budget_signal.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = REPO_ROOT / "schemas" / "drift_budget_signal.schema.json"


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <signal.json> [--schema <path>]", file=sys.stderr)
        return 1

    signal_path = Path(sys.argv[1])
    schema_path = SCHEMA
    if "--schema" in sys.argv:
        idx = sys.argv.index("--schema")
        schema_path = Path(sys.argv[idx + 1])

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    signal = json.loads(signal_path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=signal, schema=schema)
    print("drift budget signal OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
