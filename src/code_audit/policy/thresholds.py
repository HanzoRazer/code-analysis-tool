"""Score → tier → exit-code policy — single source of truth.

Every comp layer (API runner, CLI exit-code, insights display) must derive
tier and exit-code from this module instead of hard-coding thresholds locally.
"""

from __future__ import annotations

from dataclasses import dataclass

from code_audit.model import RiskLevel
from code_audit.utils.exit_codes import ExitCode


@dataclass(frozen=True, slots=True)
class ScoreThresholds:
    """Tunable thresholds for score → tier mapping."""

    green_min: int = 75
    yellow_min: int = 55


DEFAULT_THRESHOLDS = ScoreThresholds()


def tier_from_score(
    score: int,
    *,
    thresholds: ScoreThresholds = DEFAULT_THRESHOLDS,
) -> RiskLevel:
    """Map integer confidence score to a ``RiskLevel`` tier.

    Policy: ≥75 green, 55-74 yellow, <55 red.
    """
    if score >= thresholds.green_min:
        return RiskLevel.GREEN
    if score >= thresholds.yellow_min:
        return RiskLevel.YELLOW
    return RiskLevel.RED


def exit_code_from_tier(tier: RiskLevel) -> int:
    """Map a ``RiskLevel`` tier to a CLI exit code.

    Policy: green → 0, yellow → 1, red → 2.
    """
    if tier == RiskLevel.GREEN:
        return ExitCode.SUCCESS
    if tier == RiskLevel.YELLOW:
        return ExitCode.VIOLATION
    return ExitCode.ERROR


def exit_code_from_score(
    score: int,
    *,
    thresholds: ScoreThresholds = DEFAULT_THRESHOLDS,
) -> int:
    """Map integer confidence score directly to a CLI exit code.

    Convenience: ``exit_code_from_tier(tier_from_score(score))``.
    """
    return exit_code_from_tier(tier_from_score(score, thresholds=thresholds))
