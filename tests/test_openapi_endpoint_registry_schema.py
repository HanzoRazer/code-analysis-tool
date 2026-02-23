"""Schema validation test for the OpenAPI golden endpoints registry.

Ensures ``tests/contracts/openapi_golden_endpoints.json`` conforms to its
JSON Schema (``openapi_golden_endpoints.schema.json``), which bans string-form
entries and enforces object-only with uppercase canonical HTTP verbs.
"""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "contracts" / "openapi_golden_endpoints.json"
SCHEMA = ROOT / "tests" / "contracts" / "openapi_golden_endpoints.schema.json"


def test_openapi_endpoint_registry_conforms_to_schema() -> None:
    assert REGISTRY.exists(), "Missing tests/contracts/openapi_golden_endpoints.json"
    assert SCHEMA.exists(), "Missing tests/contracts/openapi_golden_endpoints.schema.json"

    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    jsonschema.validate(instance=data, schema=schema)
