"""Tests for policy.thresholds — single source of truth for score → tier → exit code."""

from __future__ import annotations

import pytest

from code_audit.model import RiskLevel
from code_audit.policy.thresholds import (
    DEFAULT_THRESHOLDS,
    ScoreThresholds,
    exit_code_from_score,
    exit_code_from_tier,
    tier_from_score,
)


class TestTierFromScore:
    """tier_from_score maps confidence score to RiskLevel."""

    def test_75_is_green(self) -> None:
        assert tier_from_score(75) == RiskLevel.GREEN

    def test_74_is_yellow(self) -> None:
        assert tier_from_score(74) == RiskLevel.YELLOW

    def test_55_is_yellow(self) -> None:
        assert tier_from_score(55) == RiskLevel.YELLOW

    def test_54_is_red(self) -> None:
        assert tier_from_score(54) == RiskLevel.RED

    def test_100_is_green(self) -> None:
        assert tier_from_score(100) == RiskLevel.GREEN

    def test_0_is_red(self) -> None:
        assert tier_from_score(0) == RiskLevel.RED


class TestExitCodeFromScore:
    """exit_code_from_score maps score to CLI exit code (0/1/2)."""

    def test_green_exit_0(self) -> None:
        assert exit_code_from_score(75) == 0

    def test_yellow_exit_1(self) -> None:
        assert exit_code_from_score(74) == 1

    def test_yellow_low_exit_1(self) -> None:
        assert exit_code_from_score(55) == 1

    def test_red_exit_2(self) -> None:
        assert exit_code_from_score(54) == 2

    def test_max_exit_0(self) -> None:
        assert exit_code_from_score(100) == 0

    def test_min_exit_2(self) -> None:
        assert exit_code_from_score(0) == 2


class TestExitCodeFromTier:
    """exit_code_from_tier maps RiskLevel to exit code."""

    def test_green_0(self) -> None:
        assert exit_code_from_tier(RiskLevel.GREEN) == 0

    def test_yellow_1(self) -> None:
        assert exit_code_from_tier(RiskLevel.YELLOW) == 1

    def test_red_2(self) -> None:
        assert exit_code_from_tier(RiskLevel.RED) == 2


class TestCustomThresholds:
    """ScoreThresholds can be overridden for custom policies."""

    def test_stricter_thresholds(self) -> None:
        strict = ScoreThresholds(green_min=90, yellow_min=70)
        assert tier_from_score(89, thresholds=strict) == RiskLevel.YELLOW
        assert tier_from_score(90, thresholds=strict) == RiskLevel.GREEN
        assert tier_from_score(69, thresholds=strict) == RiskLevel.RED


class TestDefaultThresholds:
    """DEFAULT_THRESHOLDS matches the documented policy."""

    def test_green_min(self) -> None:
        assert DEFAULT_THRESHOLDS.green_min == 75

    def test_yellow_min(self) -> None:
        assert DEFAULT_THRESHOLDS.yellow_min == 55


class TestRunnerParity:
    """Runner's tier_from_score matches what the runner previously hard-coded."""

    @pytest.mark.parametrize(
        "score, expected",
        [
            (83, RiskLevel.GREEN),
            (78, RiskLevel.GREEN),
            (75, RiskLevel.GREEN),
            (74, RiskLevel.YELLOW),
            (60, RiskLevel.YELLOW),
            (55, RiskLevel.YELLOW),
            (54, RiskLevel.RED),
            (30, RiskLevel.RED),
            (0, RiskLevel.RED),
        ],
    )
    def test_score_tier_mapping(self, score: int, expected: RiskLevel) -> None:
        assert tier_from_score(score) == expected
