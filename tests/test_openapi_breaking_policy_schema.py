from __future__ import annotations

import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "tests" / "contracts" / "openapi_breaking_policy.json"
SCHEMA = ROOT / "tests" / "contracts" / "openapi_breaking_policy.schema.json"


def test_openapi_breaking_policy_conforms_to_schema() -> None:
    assert POLICY.exists(), "Missing tests/contracts/openapi_breaking_policy.json"
    assert SCHEMA.exists(), "Missing tests/contracts/openapi_breaking_policy.schema.json"

    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.validate(instance=policy, schema=schema)
