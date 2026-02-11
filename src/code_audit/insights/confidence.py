"""Confidence scorer — the single number beginner Vibe Coders see first.

Formula:
    score = clamp(base − risk_penalty − overwhelm_penalty + recovery_bonus, 0, 100)

Constants pulled straight from the copilot-instructions spec.
"""

from __future__ import annotations

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding

# ── type weights (how scary each category is for beginners) ──────────
_TYPE_WEIGHT: dict[AnalyzerType, int] = {
    AnalyzerType.SECURITY: 14,
    AnalyzerType.EXCEPTIONS: 11,
    AnalyzerType.SAFETY: 10,
    AnalyzerType.GLOBAL_STATE: 6,
    AnalyzerType.COMPLEXITY: 4,
    AnalyzerType.DEAD_CODE: 1,
}

# ── severity multiplier ─────────────────────────────────────────────
_SEVERITY_FACTOR: dict[Severity, float] = {
    Severity.CRITICAL: 2.0,
    Severity.HIGH: 1.5,
    Severity.MEDIUM: 1.0,
    Severity.LOW: 0.5,
    Severity.INFO: 0.0,
}

# ── volume factor (capped) ──────────────────────────────────────────
_VOLUME_CAP = 30

# ── overwhelm penalty ───────────────────────────────────────────────
_OVERWHELM_THRESHOLD = 15
_OVERWHELM_PER_FINDING = 0.3
_OVERWHELM_CAP = 10

# ── base score ───────────────────────────────────────────────────────
_BASE = 78

# ── recovery bonus (no HIGH/CRITICAL) ───────────────────────────────
_RECOVERY_BONUS = 5


def _clamp(value: float, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(round(value))))


def compute_confidence(findings: list[Finding]) -> int:
    """Return a 0-100 integer confidence score.

    Higher is better — ≥75 green, 55-74 yellow, <55 red.
    """
    if not findings:
        return _BASE + _RECOVERY_BONUS  # clean codebase

    # ── risk penalty ─────────────────────────────────────────────
    risk = 0.0
    for f in findings:
        tw = _TYPE_WEIGHT.get(f.type, 1)
        sf = _SEVERITY_FACTOR.get(f.severity, 1.0)
        risk += tw * sf
    # cap volume contribution
    volume = min(len(findings), _VOLUME_CAP)
    risk_penalty = risk * (volume / _VOLUME_CAP)

    # ── overwhelm penalty ────────────────────────────────────────
    overwhelm = 0.0
    if len(findings) > _OVERWHELM_THRESHOLD:
        overwhelm = min(
            (len(findings) - _OVERWHELM_THRESHOLD) * _OVERWHELM_PER_FINDING,
            _OVERWHELM_CAP,
        )

    # ── recovery bonus ───────────────────────────────────────────
    has_high_or_critical = any(
        f.severity in {Severity.HIGH, Severity.CRITICAL} for f in findings
    )
    recovery = 0 if has_high_or_critical else _RECOVERY_BONUS

    score = _BASE - risk_penalty - overwhelm + recovery
    return _clamp(score, 0, 100)
