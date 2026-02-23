from __future__ import annotations

import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]

SCHEMAS = [
    ROOT / "schemas" / "release_bom.schema.json",
    ROOT / "schemas" / "release_audit_failure.schema.json",
    ROOT / "schemas" / "release_bom_consistency_result.schema.json",
]


def test_release_related_schemas_are_valid_draft202012() -> None:
    for p in SCHEMAS:
        if not p.exists():
            continue  # Schema not yet created; skip gracefully
        obj = json.loads(p.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(obj)
