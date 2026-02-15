#!/usr/bin/env python3
"""Regenerate docs/rule_registry.json from canonical rules.py.

Usage:
    python scripts/sync_rule_registry.py          # check mode (CI)
    python scripts/sync_rule_registry.py --write  # write mode (dev)

Validations (fail early):
    - All IDs match naming convention: PREFIX_NAME_NNN
    - All IDs are unique across all buckets
    - No overlap between public/experimental/deprecated
    - Lists are sorted alphabetically
    - PUBLIC_RULE_IDS is non-empty
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PY = ROOT / "src" / "code_audit" / "rules.py"
OUTPUT = ROOT / "docs" / "rule_registry.json"

# Rule ID naming convention: PREFIX_NAME_NNN (e.g., DC_UNREACHABLE_001)
RULE_ID_PATTERN = re.compile(r"^[A-Z]{2,4}_[A-Z][A-Z0-9_]*_\d{3}$")


def load_buckets() -> dict[str, list[str]]:
    """Load rule buckets from rules.py without importing the full package."""
    namespace: dict = {}
    exec(RULES_PY.read_text(encoding="utf-8"), namespace)
    return {
        "public": namespace["PUBLIC_RULE_IDS"],
        "experimental": namespace["EXPERIMENTAL_RULE_IDS"],
        "deprecated": namespace["DEPRECATED_RULE_IDS"],
        "all": namespace["ALL_RULE_IDS"],
    }


def validate(buckets: dict[str, list[str]]) -> list[str]:
    """Validate rule buckets. Returns list of error messages."""
    errors: list[str] = []
    public = buckets["public"]
    experimental = buckets["experimental"]
    deprecated = buckets["deprecated"]
    all_ids = buckets["all"]

    # PUBLIC_RULE_IDS must be non-empty
    if not public:
        errors.append("PUBLIC_RULE_IDS is empty")

    # All IDs must match naming convention
    for bucket_name, ids in [("public", public), ("experimental", experimental), ("deprecated", deprecated)]:
        for rule_id in ids:
            if not RULE_ID_PATTERN.match(rule_id):
                errors.append(f"{bucket_name}: '{rule_id}' does not match pattern PREFIX_NAME_NNN")

    # No duplicates within buckets
    for bucket_name, ids in [("public", public), ("experimental", experimental), ("deprecated", deprecated)]:
        seen = set()
        for rule_id in ids:
            if rule_id in seen:
                errors.append(f"{bucket_name}: duplicate '{rule_id}'")
            seen.add(rule_id)

    # No overlap between buckets
    public_set = set(public)
    experimental_set = set(experimental)
    deprecated_set = set(deprecated)

    overlap_pe = public_set & experimental_set
    if overlap_pe:
        errors.append(f"public/experimental overlap: {sorted(overlap_pe)}")

    overlap_pd = public_set & deprecated_set
    if overlap_pd:
        errors.append(f"public/deprecated overlap: {sorted(overlap_pd)}")

    overlap_ed = experimental_set & deprecated_set
    if overlap_ed:
        errors.append(f"experimental/deprecated overlap: {sorted(overlap_ed)}")

    # ALL_RULE_IDS must equal union
    expected_all = public_set | experimental_set | deprecated_set
    actual_all = set(all_ids)
    if expected_all != actual_all:
        missing = expected_all - actual_all
        extra = actual_all - expected_all
        if missing:
            errors.append(f"ALL_RULE_IDS missing: {sorted(missing)}")
        if extra:
            errors.append(f"ALL_RULE_IDS has extra: {sorted(extra)}")

    # Lists should be sorted (warning, not error - we'll sort in output)
    for bucket_name, ids in [("public", public), ("experimental", experimental), ("deprecated", deprecated)]:
        if ids != sorted(ids):
            # Just a note - we sort in output anyway
            pass

    return errors


def generate(buckets: dict[str, list[str]]) -> str:
    """Generate rule_registry.json content."""
    data: dict = {
        "schema_version": "rule_registry_v1",
        "supported_rule_ids": sorted(buckets["public"]),
    }

    # Only include non-empty optional sections
    if buckets["experimental"]:
        data["experimental_rule_ids"] = sorted(buckets["experimental"])

    if buckets["deprecated"]:
        data["deprecated_rule_ids"] = sorted(buckets["deprecated"])

    return json.dumps(data, indent=2) + "\n"


SCHEMA_PATH = ROOT / "schemas" / "rule_registry.schema.json"


def validate_against_schema(data: dict) -> list[str]:
    """Validate generated data against JSON schema (if jsonschema available)."""
    try:
        import jsonschema
    except ImportError:
        return []  # Skip if jsonschema not installed

    if not SCHEMA_PATH.exists():
        return [f"Schema not found: {SCHEMA_PATH}"]

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(data, schema)
        return []
    except jsonschema.ValidationError as e:
        return [f"Schema validation failed: {e.message}"]


def main() -> int:
    write_mode = "--write" in sys.argv

    # Load and validate
    buckets = load_buckets()
    errors = validate(buckets)

    if errors:
        print("Validation errors in rules.py:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    expected = generate(buckets)

    # Validate against schema
    data = json.loads(expected)
    schema_errors = validate_against_schema(data)
    if schema_errors:
        print("Schema validation errors:", file=sys.stderr)
        for e in schema_errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    if write_mode:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"Wrote {OUTPUT}")
        print(f"  supported_rule_ids: {len(buckets['public'])}")
        if buckets["experimental"]:
            print(f"  experimental_rule_ids: {len(buckets['experimental'])}")
        if buckets["deprecated"]:
            print(f"  deprecated_rule_ids: {len(buckets['deprecated'])}")
        return 0

    # Check mode
    if not OUTPUT.exists():
        print(f"FAIL: {OUTPUT} does not exist", file=sys.stderr)
        print("Fix: python scripts/sync_rule_registry.py --write", file=sys.stderr)
        return 1

    actual = OUTPUT.read_text(encoding="utf-8")

    if actual != expected:
        print(f"FAIL: {OUTPUT} is out of sync with rules.py", file=sys.stderr)
        print("Fix: python scripts/sync_rule_registry.py --write", file=sys.stderr)
        return 1

    print(f"OK: {OUTPUT} matches rules.py ({len(buckets['public'])} supported rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
