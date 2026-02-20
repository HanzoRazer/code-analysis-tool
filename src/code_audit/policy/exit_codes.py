"""Exit-code policy — severity-based CI exit-code contract.

This module is treated as a governed contract surface.
Changes require ``signal_logic_version`` bump + manifest refresh.

Philosophy:
  - Deterministic in CI
  - Stable mapping from worst severity → exit code
  - No hidden magic inside CLI glue
  - Unknown severities are fail-safe (CRITICAL)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from code_audit.utils.exit_codes import ExitCode


Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(frozen=True)
class ExitCodePolicy:
    """Tunable thresholds for severity → exit-code mapping."""

    ok: int = ExitCode.SUCCESS
    warn: int = ExitCode.VIOLATION
    fail: int = ExitCode.ERROR
    # Minimum severity that triggers warn/fail
    warn_at: Severity = "MEDIUM"
    fail_at: Severity = "HIGH"


# Default CI policy.
# Keep this policy stable; changes require signal_logic_version bump
# + manifest refresh.
DEFAULT_POLICY = ExitCodePolicy(
    ok=ExitCode.SUCCESS,
    warn=ExitCode.VIOLATION,
    fail=ExitCode.ERROR,
    warn_at="MEDIUM",
    fail_at="HIGH",
)


_SEV_RANK: dict[Severity, int] = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _normalize_severity(value: str | None) -> Severity:
    """Normalize a raw severity string to a canonical ``Severity`` literal.

    Unknown or missing values are treated as ``CRITICAL`` (fail-safe in CI).
    """
    if not value:
        return "NONE"
    v = value.strip().upper()
    if v in _SEV_RANK:
        return v  # type: ignore[return-value]
    # Unknown values are treated as worst-case for safety in CI.
    return "CRITICAL"


def exit_code_for_worst_severity(
    worst_severity: str | None,
    *,
    policy: ExitCodePolicy = DEFAULT_POLICY,
) -> int:
    """Compute the CI exit code from a worst-severity string.

    Contract:
      - monotonic (worse severity never produces a lower exit code)
      - unknown severities treated as CRITICAL (fail-safe)
    """
    sev = _normalize_severity(worst_severity)
    sev_rank = _SEV_RANK[sev]

    if sev_rank >= _SEV_RANK[policy.fail_at]:
        return policy.fail
    if sev_rank >= _SEV_RANK[policy.warn_at]:
        return policy.warn
    return policy.ok


def worst_severity_from_counts(by_severity: dict[str, int] | None) -> str | None:
    """Derive the worst severity present from a ``by_severity`` counts dict.

    The ``by_severity`` dict maps lowercase severity names (e.g. ``"high"``)
    to their counts.  Returns the worst severity with a non-zero count,
    or ``None`` if no findings are present.
    """
    if not by_severity:
        return None
    worst: str | None = None
    worst_rank = -1
    for sev_str, count in by_severity.items():
        if not count:
            continue
        normalized = _normalize_severity(sev_str)
        rank = _SEV_RANK[normalized]
        if rank > worst_rank:
            worst_rank = rank
            worst = normalized
    return worst
