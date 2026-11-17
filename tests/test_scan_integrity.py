"""Teeth for fail-closed scan integrity. These fail if the guard is removed."""

from __future__ import annotations

from code_audit.core.scan_integrity import (
    evaluate_scan_integrity,
    interpret_stored_result,
)
from tests._helpers.integrity import make_outcome


def test_empty_repo_not_assessable() -> None:
    integrity = evaluate_scan_integrity(
        0,
        [make_outcome("security", "not_applicable", critical=True)],
    )
    assert integrity.assessable is False
    assert "no_source_files" in integrity.reasons
    assert integrity.degraded == []


def test_zero_ok_not_assessable() -> None:
    integrity = evaluate_scan_integrity(
        3,
        [
            make_outcome("security", "failed", critical=True),
            make_outcome("complexity", "failed"),
        ],
    )
    assert integrity.assessable is False
    assert "no_analyzer_completed" in integrity.reasons


def test_critical_failed_not_assessable() -> None:
    integrity = evaluate_scan_integrity(
        4,
        [
            make_outcome("complexity", "ok"),
            make_outcome("security", "failed", critical=True),
        ],
    )
    assert integrity.assessable is False
    assert any(
        reason.startswith("critical_analyzer_failed:security") for reason in integrity.reasons
    )
    assert [item.analyzer_id for item in integrity.degraded] == ["security"]


def test_critical_missing_capability_not_assessable() -> None:
    integrity = evaluate_scan_integrity(
        2,
        [make_outcome("security", "missing_capability", critical=True)],
    )
    assert integrity.assessable is False
    assert integrity.degraded[0].status == "missing_capability"


def test_noncritical_failed_assessable_but_degraded() -> None:
    integrity = evaluate_scan_integrity(
        2,
        [
            make_outcome("security", "ok", critical=True),
            make_outcome("complexity", "failed"),
        ],
    )
    assert integrity.assessable is True
    assert [item.analyzer_id for item in integrity.degraded] == ["complexity"]
    assert "noncritical_degradation" in integrity.reasons


def test_not_applicable_analyzer_does_not_degrade() -> None:
    integrity = evaluate_scan_integrity(
        2,
        [
            make_outcome("security", "ok", critical=True),
            make_outcome("exceptions", "ok", critical=True),
            make_outcome("js_ts_security", "not_applicable"),
        ],
    )
    assert integrity.assessable is True
    assert integrity.degraded == []
    assert integrity.analyzers_ok == 2


def test_not_scheduled_does_not_degrade() -> None:
    integrity = evaluate_scan_integrity(
        1,
        [
            make_outcome("security", "ok", critical=True),
            make_outcome("js_ts_security", "not_scheduled"),
        ],
    )
    assert integrity.assessable is True
    assert integrity.degraded == []


def test_round_trip_dict() -> None:
    integrity = evaluate_scan_integrity(
        1,
        [make_outcome("complexity", "failed")],
    )
    restored = type(integrity).from_dict(integrity.to_dict())
    assert restored == integrity
    assert restored.to_dict()["degraded"][0]["duration_s"] is None


def test_legacy_result_without_scan_integrity_is_unverified() -> None:
    view = interpret_stored_result(
        {
            "schema_version": "run_result_v1",
            "summary": {"vibe_tier": "green", "confidence_score": 83},
        }
    )
    assert view.verified is False
    assert view.effective_tier == "inconclusive"
    assert view.integrity is None


def test_legacy_red_stays_red_but_unverified() -> None:
    view = interpret_stored_result(
        {"summary": {"vibe_tier": "red", "confidence_score": 20}}
    )
    assert view.verified is False
    assert view.effective_tier == "red"
