#!/usr/bin/env python3
"""Validate a JSON instance against a JSON Schema.

Usage
-----
    python scripts/validate_schema.py <instance.json> <schema.json>

Exit codes
----------
    0  — instance is valid
    1  — validation errors found
    2  — usage / IO error
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: scripts/validate_schema.py <instance.json> <schema.json>",
            file=sys.stderr,
        )
        return 2

    instance_path = Path(sys.argv[1])
    schema_path = Path(sys.argv[2])

    try:
        instance = json.loads(instance_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        jsonschema.validate(instance=instance, schema=schema)
    except jsonschema.ValidationError as exc:
        print(f"FAIL: {exc.message}", file=sys.stderr)
        return 1

    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
