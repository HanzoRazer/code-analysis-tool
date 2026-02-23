from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "release_audit_failure.schema.json"


def test_release_audit_failure_kind_enum_is_present_and_unique() -> None:
    """
    Enforce that the audit failure schema defines a kind enum that is:
      - non-empty
      - unique (no duplicates)
      - all strings
    """
    assert SCHEMA_PATH.exists(), f"Missing {SCHEMA_PATH}"
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    # The kind enum may be at top-level properties or in $defs/detail_item
    kind_enum = None

    # Check top-level kind (may be inline or $ref)
    props = schema.get("properties", {})
    if "kind" in props and "enum" in props["kind"]:
        kind_enum = props["kind"]["enum"]

    # Check $defs/kind if present (the $ref target)
    defs = schema.get("$defs", {})
    if "kind" in defs and "enum" in defs["kind"]:
        kind_enum = defs["kind"]["enum"]

    # Also check $defs/detail_kind if present
    if "detail_kind" in defs and "enum" in defs["detail_kind"]:
        kind_enum = defs["detail_kind"]["enum"]

    assert kind_enum is not None, "release_audit_failure schema: kind enum not found"
    assert len(kind_enum) > 0, "release_audit_failure schema: kind enum is empty"
    assert all(isinstance(k, str) for k in kind_enum), "release_audit_failure schema: kind enum must be all strings"
    assert len(kind_enum) == len(set(kind_enum)), (
        f"release_audit_failure schema: kind enum has duplicates: "
        f"{[k for k in kind_enum if kind_enum.count(k) > 1]}"
    )
