from __future__ import annotations

import json


def test_schema_meta_error_marker_prefix_is_parseable_json() -> None:
    # Contract: if a line begins with "SCHEMA_META_ERROR: ",
    # the remainder must be valid JSON with required keys.
    sample = (
        'SCHEMA_META_ERROR: {"kind":"schema_meta_validation_failed","path":"dist/x.json",'
        '"expected":"valid Draft 2020-12 JSON Schema","got":"invalid_schema","details":{"exception_type":"SchemaError","exception_message":"boom"}}'
    )
    assert sample.startswith("SCHEMA_META_ERROR: ")
    payload = json.loads(sample.split("SCHEMA_META_ERROR: ", 1)[1])
    for k in ("kind", "path", "expected", "got", "details"):
        assert k in payload
