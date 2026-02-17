"""Brute-force monotonicity test for _human_duration() over 0–10,000 seconds.

Locks the duration formatting contract mathematically:
  - total minutes == floor(seconds / 60) exactly
  - monotonic non-decreasing minute transitions
  - no hours below 3600s, no days below 86400s
  - minute always present in output
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_GENERATOR_PATH = _REPO_ROOT / "scripts" / "generate_drift_budget_signal.py"


def _import_human_duration():
    """Import _human_duration from the generator script (not a package)."""
    spec = importlib.util.spec_from_file_location(
        "generate_drift_budget_signal", str(_GENERATOR_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._human_duration


_MINUTES_ONLY_RE = re.compile(r"^(\d+)m$")
_HOURS_MINUTES_RE = re.compile(r"^(\d+)h (\d+)m$")
_DAYS_RE = re.compile(r"^(\d+)d(?: (\d+)h)? (\d+)m$")


def _parse_minutes(output: str) -> int:
    """Parse formatter output and return total minutes."""
    s = output.strip()

    m = _MINUTES_ONLY_RE.match(s)
    if m:
        return int(m.group(1))

    m = _HOURS_MINUTES_RE.match(s)
    if m:
        hours = int(m.group(1))
        minutes = int(m.group(2))
        return hours * 60 + minutes

    m = _DAYS_RE.match(s)
    if m:
        days = int(m.group(1))
        hours = int(m.group(2)) if m.group(2) is not None else 0
        minutes = int(m.group(3))
        return days * 24 * 60 + hours * 60 + minutes

    raise AssertionError(f"Unrecognized duration format: {output!r}")


def test_human_duration_bruteforce_monotonic_minutes_0_to_10000() -> None:
    """Over 0–10000s: floor minutes, monotonic, correct grammar bands."""
    human = _import_human_duration()

    prev_minutes = None
    prev_s = None

    for s in range(0, 10001):
        out = human(s)
        minutes = _parse_minutes(out)

        # Total minutes MUST equal floor(seconds / 60).
        expected = s // 60
        assert minutes == expected, (
            "Duration formatter minute math drift:\n"
            f"  seconds={s}\n"
            f"  output={out!r}\n"
            f"  parsed_minutes={minutes}\n"
            f"  expected_floor_minutes={expected}\n"
        )

        # Grammar band checks.
        if s < 3600:
            assert "h" not in out and "d" not in out, (
                "Formatter emitted hours/days below 3600 seconds:\n"
                f"  seconds={s}\n"
                f"  output={out!r}\n"
            )
        else:
            assert "d" not in out, (
                "Formatter emitted days below 86400 seconds:\n"
                f"  seconds={s}\n"
                f"  output={out!r}\n"
            )

        # Monotonicity (non-decreasing).
        if prev_minutes is not None:
            assert minutes >= prev_minutes, (
                "Non-monotonic minute transitions detected:\n"
                f"  prev_seconds={prev_s}\n"
                f"  prev_minutes={prev_minutes}\n"
                f"  seconds={s}\n"
                f"  minutes={minutes}\n"
            )
            # No jumps > 1 minute per second step.
            assert (minutes - prev_minutes) in (0, 1), (
                "Minute jump anomaly detected:\n"
                f"  prev_seconds={prev_s}\n"
                f"  prev_minutes={prev_minutes}\n"
                f"  seconds={s}\n"
                f"  minutes={minutes}\n"
                f"  delta={minutes - prev_minutes}\n"
            )

        prev_minutes = minutes
        prev_s = s
