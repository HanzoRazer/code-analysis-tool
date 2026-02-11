from __future__ import annotations

from typing import Any, Dict, Literal

ButtonTier = Literal["primary", "secondary", "tertiary"]
RiskLevel = Literal["green", "yellow", "red"]


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def choose_subtext_risk_level(signal: Dict[str, Any]) -> RiskLevel:
    """
    UI-facing prioritization WITHOUT changing copy:

    Baseline:
      - use signal.risk_level as the driver for subtext selection

    Exceptions nuance:
      - If risk is red but there are *no swallowed errors*, we intentionally soften
        the *subtext* one notch (red -> yellow) because:
          * the user is still informed via the signal card itself
          * but the CTA microcopy should feel less "panic-button"
          * this keeps beginners calmer without hiding risk

    This only affects the *subtext line* under buttons, not the signal copy keys.
    """
    risk = signal.get("risk_level", "yellow")
    if risk not in ("green", "yellow", "red"):
        risk = "yellow"

    if signal.get("type") == "exceptions" and risk == "red":
        evidence = signal.get("evidence") or {}
        summary = evidence.get("summary") or {}
        swallowed = _as_int(summary.get("swallowed_count"), 0)

        # If nothing is being swallowed, downgrade subtext severity one notch.
        if swallowed <= 0:
            return "yellow"

    return risk  # type: ignore[return-value]


def resolve_button_subtext(
    buttons_i18n: Dict[str, Any],
    *,
    signal: Dict[str, Any],
    tier: ButtonTier,
) -> str:
    """
    Resolve the correct subtext string (already localized) for a given button tier
    and signal context.

    Expected structure:
      buttons_i18n["buttons"]["subtext_by_risk"][risk][tier] -> str
    """
    base = buttons_i18n.get("buttons") or {}
    sbr = base.get("subtext_by_risk") or {}

    risk: RiskLevel = choose_subtext_risk_level(signal)
    risk_obj = sbr.get(risk) or {}

    val = risk_obj.get(tier)
    if isinstance(val, str) and val.strip():
        return val

    # Safe fallback: try yellow, then green, then red (most permissive -> least)
    for r in ("yellow", "green", "red"):
        ro = sbr.get(r) or {}
        v = ro.get(tier)
        if isinstance(v, str) and v.strip():
            return v

    # Last resort: empty string (UI can omit subtext line)
    return ""
