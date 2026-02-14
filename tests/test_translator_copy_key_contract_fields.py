from __future__ import annotations

from code_audit.api import scan_project


def test_copy_key_contract_fields_present_in_signals_ci() -> None:
    """
    Runtime contract: every signal emitted by the canonical scan engine
    must include the expected copy-key fields (title_key, summary_key,
    why_key, action.text_key).

    This complements the policy-hash gate with a runtime shape check.
    """
    _, d = scan_project("tests/fixtures/repos/sample_repo_exceptions", ci_mode=True)
    signals = d.get("signals_snapshot", [])
    assert signals, "fixture must produce at least one signal for this contract test"

    for s in signals:
        assert "title_key" in s, f"signal missing title_key: {s.get('signal_id')}"
        assert "summary_key" in s, f"signal missing summary_key: {s.get('signal_id')}"
        assert "why_key" in s, f"signal missing why_key: {s.get('signal_id')}"
        assert "action" in s and isinstance(s["action"], dict), (
            f"signal missing action dict: {s.get('signal_id')}"
        )
        assert "text_key" in s["action"], f"signal action missing text_key: {s.get('signal_id')}"
