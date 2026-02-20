"""Behavior contract: explicit mapping table for worst_severity → exit_code.

This test freezes the public behavior of the exit-code policy.
If someone rewrites the implementation, the mapping must remain stable
unless they intentionally bump versions and refresh the manifest.
"""

from __future__ import annotations

import pytest

from code_audit.policy.exit_codes import (
    DEFAULT_POLICY,
    exit_code_for_worst_severity,
    worst_severity_from_counts,
)


@pytest.mark.parametrize(
    "worst, expected",
    [
        # Clean / no findings
        (None, DEFAULT_POLICY.ok),
        ("", DEFAULT_POLICY.ok),
        ("NONE", DEFAULT_POLICY.ok),
        # Low severity — below warn threshold
        ("LOW", DEFAULT_POLICY.ok),
        ("low", DEFAULT_POLICY.ok),
        # Medium — warn threshold
        ("MEDIUM", DEFAULT_POLICY.warn),
        ("medium", DEFAULT_POLICY.warn),
        # High — fail threshold
        ("HIGH", DEFAULT_POLICY.fail),
        ("high", DEFAULT_POLICY.fail),
        # Critical — above fail threshold
        ("CRITICAL", DEFAULT_POLICY.fail),
        ("critical", DEFAULT_POLICY.fail),
        # Defensive: unknown values fail-safe
        ("UNKNOWN_SEVERITY", DEFAULT_POLICY.fail),
        ("weird", DEFAULT_POLICY.fail),
        ("  HIGH  ", DEFAULT_POLICY.fail),  # whitespace tolerance
    ],
)
def test_exit_code_policy_mapping_contract(worst: str | None, expected: int) -> None:
    """Each severity maps to a deterministic exit code per DEFAULT_POLICY."""
    assert exit_code_for_worst_severity(worst) == expected


def test_exit_code_monotonicity() -> None:
    """Worse severity must never produce a *lower* exit code."""
    ordered = [None, "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    codes = [exit_code_for_worst_severity(s) for s in ordered]
    for i in range(1, len(codes)):
        assert codes[i] >= codes[i - 1], (
            f"Non-monotonic: {ordered[i]} → {codes[i]} < {ordered[i-1]} → {codes[i-1]}"
        )


class TestWorstSeverityFromCounts:
    """Verify the helper that derives worst_severity from by_severity dicts."""

    def test_empty_dict(self) -> None:
        assert worst_severity_from_counts({}) is None

    def test_none(self) -> None:
        assert worst_severity_from_counts(None) is None

    def test_single_severity(self) -> None:
        assert worst_severity_from_counts({"high": 3}) == "HIGH"

    def test_multiple_severities(self) -> None:
        counts = {"low": 5, "medium": 2, "high": 1}
        assert worst_severity_from_counts(counts) == "HIGH"

    def test_critical_wins(self) -> None:
        counts = {"info": 10, "low": 5, "critical": 1}
        assert worst_severity_from_counts(counts) == "CRITICAL"

    def test_zero_counts_ignored(self) -> None:
        counts = {"high": 0, "medium": 0, "low": 3}
        assert worst_severity_from_counts(counts) == "LOW"

    def test_all_zero(self) -> None:
        counts = {"high": 0, "medium": 0}
        assert worst_severity_from_counts(counts) is None
