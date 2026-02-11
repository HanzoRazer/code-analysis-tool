"""Smoke tests: schemas load and carry correct $id values."""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_run_result_schema_loads():
    schema_path = REPO_ROOT / "schemas" / "run_result.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$id"] == "run_result_v1"


def test_signals_latest_schema_loads():
    schema_path = REPO_ROOT / "schemas" / "signals_latest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$id"] == "signals_latest_v1"
