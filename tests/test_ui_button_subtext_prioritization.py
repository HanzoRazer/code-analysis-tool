import json
from pathlib import Path

from code_audit.ui.button_copy import choose_subtext_risk_level, resolve_button_subtext

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_buttons_en():
    return json.loads((REPO_ROOT / "i18n" / "en" / "buttons.json").read_text(encoding="utf-8"))


def test_exceptions_with_swallowed_keeps_red_subtext():
    buttons = _load_buttons_en()
    signal = {
        "type": "exceptions",
        "risk_level": "red",
        "evidence": {"summary": {"swallowed_count": 2, "logged_count": 0}},
    }
    assert choose_subtext_risk_level(signal) == "red"
    sub = resolve_button_subtext(buttons, signal=signal, tier="primary")
    # Uses existing copy in buttons.json: subtext_by_risk.red.primary
    assert isinstance(sub, str) and sub.strip()


def test_exceptions_without_swallowed_softens_subtext_to_yellow():
    buttons = _load_buttons_en()
    signal = {
        "type": "exceptions",
        "risk_level": "red",
        "evidence": {"summary": {"swallowed_count": 0, "logged_count": 3}},
    }
    assert choose_subtext_risk_level(signal) == "yellow"
    sub = resolve_button_subtext(buttons, signal=signal, tier="primary")
    # Uses existing copy in buttons.json: subtext_by_risk.yellow.primary
    assert isinstance(sub, str) and sub.strip()
