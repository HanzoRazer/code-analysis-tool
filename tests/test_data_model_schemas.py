"""Validate every Hybrid Snapshot example against its JSON Schema."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


def _load(name: str) -> dict:
    return json.loads((SCHEMAS_DIR / name).read_text(encoding="utf-8"))


# ── fixtures ────────────────────────────────────────────────────────

@pytest.fixture()
def run_result_schema():
    return _load("run_result.schema.json")


@pytest.fixture()
def run_result_example():
    return _load("run_result.example.json")


@pytest.fixture()
def signals_latest_schema():
    return _load("signals_latest.schema.json")


@pytest.fixture()
def signals_latest_example():
    return _load("signals_latest.example.json")


@pytest.fixture()
def user_event_schema():
    return _load("user_event.schema.json")


@pytest.fixture()
def user_event_example():
    return _load("user_event.example.json")


# ── happy-path: examples validate ───────────────────────────────────

class TestRunResult:
    def test_example_validates(self, run_result_schema, run_result_example):
        Draft202012Validator(run_result_schema).validate(run_result_example)

    def test_schema_version_const(self, run_result_example):
        assert run_result_example["schema_version"] == "run_result_v1"

    def test_summary_confidence_range(self, run_result_example):
        score = run_result_example["summary"]["confidence_score"]
        assert 0 <= score <= 100

    def test_signals_snapshot_not_empty(self, run_result_example):
        assert len(run_result_example["signals_snapshot"]) > 0

    def test_findings_raw_not_empty(self, run_result_example):
        assert len(run_result_example["findings_raw"]) > 0

    def test_artifacts_accepted_if_present(self, run_result_schema, run_result_example):
        """artifacts is optional — but when present it must be an object."""
        if "artifacts" in run_result_example:
            Draft202012Validator(run_result_schema).validate(run_result_example)
            assert isinstance(run_result_example["artifacts"], dict)


class TestSignalsLatest:
    def test_example_validates(self, signals_latest_schema, signals_latest_example):
        Draft202012Validator(signals_latest_schema).validate(signals_latest_example)

    def test_schema_version_const(self, signals_latest_example):
        assert signals_latest_example["schema_version"] == "signals_latest_v1"

    def test_experiment_block_present(self, signals_latest_example):
        assert "experiment" in signals_latest_example
        assert "id" in signals_latest_example["experiment"]
        assert "variant" in signals_latest_example["experiment"]


class TestUserEvent:
    def test_example_validates(self, user_event_schema, user_event_example):
        Draft202012Validator(user_event_schema).validate(user_event_example)

    def test_schema_version_const(self, user_event_example):
        assert user_event_example["schema_version"] == "user_event_v1"

    def test_event_type_values(self, user_event_schema, user_event_example):
        allowed = user_event_schema["properties"]["events"]["items"]["properties"][
            "type"
        ]["enum"]
        for ev in user_event_example["events"]:
            assert ev["type"] in allowed

    def test_all_events_have_signal_id(self, user_event_example):
        for ev in user_event_example["events"]:
            assert "signal_id" in ev


# ── negative: reject invalid payloads ──────────────────────────────

class TestNegativeCases:
    """Ensure schemas actually reject structurally invalid data."""

    def test_run_result_rejects_missing_run(self, run_result_schema):
        bad = {"schema_version": "run_result_v1", "summary": {}, "signals_snapshot": [], "findings_raw": [], "artifacts": {}}
        with pytest.raises(ValidationError):
            Draft202012Validator(run_result_schema).validate(bad)

    def test_run_result_rejects_bad_vibe_tier(self, run_result_schema, run_result_example):
        bad = json.loads(json.dumps(run_result_example))
        bad["summary"]["vibe_tier"] = "purple"
        with pytest.raises(ValidationError):
            Draft202012Validator(run_result_schema).validate(bad)

    def test_signals_latest_rejects_missing_run_id(self, signals_latest_schema):
        bad = {"schema_version": "signals_latest_v1", "computed_at": "2026-01-01T00:00:00Z", "signal_logic_version": "v1", "copy_version": "v1", "signals": []}
        with pytest.raises(ValidationError):
            Draft202012Validator(signals_latest_schema).validate(bad)

    def test_user_event_rejects_bad_event_type(self, user_event_schema, user_event_example):
        bad = json.loads(json.dumps(user_event_example))
        bad["events"][0]["type"] = "signal_exploded"
        with pytest.raises(ValidationError):
            Draft202012Validator(user_event_schema).validate(bad)
