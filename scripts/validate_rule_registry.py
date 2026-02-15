#!/usr/bin/env python3
"""Validate docs/rule_registry.json against schemas/rule_registry.schema.json.

Minimal JSON Schema validator that avoids external dependencies for CI.
Validates: required keys, additionalProperties, array items (type, pattern,
uniqueItems, minItems), and const values.

Exit codes:
  0 = valid
  1 = invalid
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "rule_registry.json"
SCHEMA = ROOT / "schemas" / "rule_registry.schema.json"


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_array(
    arr: list, spec: dict, field_name: str
) -> list[str]:
    """Validate an array field against its schema spec."""
    errors: list[str] = []

    if not isinstance(arr, list):
        return [f"{field_name} must be an array"]

    min_items = spec.get("minItems", 0)
    if len(arr) < min_items:
        errors.append(f"{field_name} requires at least {min_items} item(s)")

    item_spec = spec.get("items", {})
    expected_type = item_spec.get("type")
    pattern = item_spec.get("pattern")
    rule_re = re.compile(pattern) if pattern else None

    for i, item in enumerate(arr):
        if expected_type == "string" and not isinstance(item, str):
            errors.append(f"{field_name}[{i}]: expected string, got {type(item).__name__}")
        elif rule_re and isinstance(item, str) and not rule_re.match(item):
            errors.append(f"{field_name}[{i}]: '{item}' does not match pattern {pattern}")

    if spec.get("uniqueItems") is True and len(arr) != len(set(arr)):
        errors.append(f"{field_name} must contain unique items")

    return errors


def _validate_schema(data: object, schema: dict) -> list[str]:
    """Minimal JSON-schema validator for the subset we use.

    Intentionally avoids external deps for CI.
    """
    errors: list[str] = []

    if schema.get("type") != "object" or not isinstance(data, dict):
        return ["Top-level must be an object"]

    # Required keys
    for k in schema.get("required", []):
        if k not in data:
            errors.append(f"Missing required key: {k}")

    props = schema.get("properties", {})

    # additionalProperties
    if schema.get("additionalProperties") is False:
        extra = set(data.keys()) - set(props.keys())
        if extra:
            errors.append(f"Unexpected keys: {sorted(extra)}")

    # Validate each known property
    for key, spec in props.items():
        if key not in data:
            continue
        value = data[key]

        # const check
        if "const" in spec:
            if value != spec["const"]:
                errors.append(
                    f"{key}: expected const {spec['const']!r}, got {value!r}"
                )

        # type check
        expected_type = spec.get("type")
        if expected_type == "string" and not isinstance(value, str):
            errors.append(f"{key}: expected string, got {type(value).__name__}")
        elif expected_type == "array":
            errors.extend(_validate_array(value, spec, key))

    return errors


def main() -> int:
    if not DOCS.exists():
        print(f"Missing {DOCS}", file=sys.stderr)
        return 1
    if not SCHEMA.exists():
        print(f"Missing {SCHEMA}", file=sys.stderr)
        return 1

    try:
        data = _load_json(DOCS)
    except Exception as e:
        print(f"Invalid JSON in {DOCS}: {e}", file=sys.stderr)
        return 1

    try:
        schema = _load_json(SCHEMA)
    except Exception as e:
        print(f"Invalid JSON in {SCHEMA}: {e}", file=sys.stderr)
        return 1

    if not isinstance(schema, dict):
        print("Schema must be a JSON object", file=sys.stderr)
        return 1

    errors = _validate_schema(data, schema)
    if errors:
        print("rule_registry.json is INVALID:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("OK: docs/rule_registry.json matches schemas/rule_registry.schema.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
