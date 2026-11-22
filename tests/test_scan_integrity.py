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


def test_noncritical_missing_capability_not_assessable() -> None:
    """Eligible files with no parser were never assessed; criticality is moot."""
    integrity = evaluate_scan_integrity(
        2,
        [
            make_outcome("complexity", "ok"),
            make_outcome("js_ts_security", "missing_capability"),
        ],
    )
    assert integrity.assessable is False
    assert "missing_capability:js_ts_security" in integrity.reasons


def test_noncritical_failed_stays_assessable() -> None:
    integrity = evaluate_scan_integrity(
        2,
        [make_outcome("complexity", "ok"), make_outcome("dead_code", "failed")],
    )
    assert integrity.assessable is True
    assert integrity.reasons == ["noncritical_degradation"]


def test_legacy_builder_emits_integrity(tmp_path) -> None:
    """The deprecated builder now carries integrity evidence (verified view).

    Note: on main this builder raises IndexError for any tree without an
    exceptions finding (including empty trees), so only a tree with one is
    exercised here.
    """
    import warnings

    from code_audit.run_result import build_run_result

    (tmp_path / "a.py").write_text(
        "def f():\n    try:\n        pass\n    except:\n        pass\n", encoding="utf-8"
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        result = build_run_result(root=str(tmp_path), tool_version="t")
    assert result["scan_integrity"]["assessable"] is True
    assert result["scan_integrity"]["files_scanned"] == 1
    assert interpret_stored_result(result).verified is True


def _cli_result(tier, score, **by_severity):
    return {
        "summary": {
            "vibe_tier": tier,
            "confidence_score": score,
            "counts": {"findings_total": sum(by_severity.values()), "by_severity": by_severity},
        }
    }


def test_cli_exit_inconclusive_is_3_in_both_modes() -> None:
    from code_audit.__main__ import _exit_from_result

    result = _cli_result("inconclusive", None)
    assert _exit_from_result(result, ci_mode=False) == 3
    assert _exit_from_result(result, ci_mode=True) == 3


def test_ci_exit_completed_fail_finding_outranks_inconclusive() -> None:
    """INCONCLUSIVE (3) must not mask a completed fail-level finding (2)."""
    from code_audit.__main__ import _exit_from_result

    result = _cli_result("inconclusive", None, critical=1)
    assert _exit_from_result(result, ci_mode=True) == 2


def test_ci_exit_inconclusive_with_low_findings_stays_3() -> None:
    from code_audit.__main__ import _exit_from_result

    result = _cli_result("inconclusive", None, low=2)
    assert _exit_from_result(result, ci_mode=True) == 3


def test_exit_precedence_covers_every_exit_code() -> None:
    """A new ExitCode must be ranked explicitly, never by numeric value."""
    from code_audit.__main__ import _EXIT_PRECEDENCE
    from code_audit.utils.exit_codes import ExitCode

    assert set(_EXIT_PRECEDENCE) == set(ExitCode)
    assert len(_EXIT_PRECEDENCE) == len(set(_EXIT_PRECEDENCE))


def test_most_severe_exit_ranks_by_precedence_not_value() -> None:
    from code_audit.__main__ import _most_severe_exit
    from code_audit.utils.exit_codes import ExitCode

    assert _most_severe_exit(ExitCode.INCONCLUSIVE, ExitCode.ERROR) == ExitCode.ERROR
    assert _most_severe_exit(ExitCode.INCONCLUSIVE, ExitCode.VIOLATION) == ExitCode.INCONCLUSIVE
    assert _most_severe_exit(ExitCode.SUCCESS, ExitCode.VIOLATION) == ExitCode.VIOLATION
