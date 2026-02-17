"""Golden confidence-score tests — exact numeric equality + relative ordering.

Each case in ``tests/fixtures/confidence/cases.json`` has a corresponding
expected file at ``tests/fixtures/confidence/expected/<case>.json`` produced by
``scripts/refresh_golden_confidence.py``.

Invariants enforced:
  1. Exact numeric match: ``compute_confidence(findings) == expected_score``.
  2. Relative ordering: scores must satisfy a monotonic dominance chain
     that catches weighting inversions across refactors.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# ── repo plumbing ────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from code_audit.insights.confidence import compute_confidence  # noqa: E402
from code_audit.model import AnalyzerType, Severity             # noqa: E402
from code_audit.model.finding import Finding, Location, make_fingerprint  # noqa: E402

_CASES_PATH = _REPO_ROOT / "tests" / "fixtures" / "confidence" / "cases.json"
_EXPECTED_DIR = _REPO_ROOT / "tests" / "fixtures" / "confidence" / "expected"


# ── helpers ──────────────────────────────────────────────────────────

def _load_cases() -> dict:
    return json.loads(_CASES_PATH.read_text(encoding="utf-8"))


def _load_expected(case_name: str) -> dict:
    path = _EXPECTED_DIR / f"{case_name}.json"
    assert path.exists(), f"Missing expected file: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def _build_finding(raw: dict) -> Finding:
    """Construct a Finding from a flat JSON dict in cases.json."""
    return Finding(
        finding_id=raw["finding_id"],
        type=AnalyzerType(raw["type"]),
        severity=Severity(raw["severity"]),
        confidence=raw.get("confidence", 1.0),
        message=raw["message"],
        location=Location(
            path=raw["path"],
            line_start=raw["line_start"],
            line_end=raw["line_end"],
        ),
        fingerprint=make_fingerprint(
            raw.get("rule_id", raw["finding_id"]),
            raw["path"],
            raw.get("symbol", ""),
            raw.get("snippet", ""),
        ),
        snippet=raw.get("snippet", ""),
    )


def _case_names() -> list[str]:
    return [c["name"] for c in _load_cases()["cases"]]


# ── parametrised exact-match test ────────────────────────────────────

@pytest.mark.parametrize("case_name", _case_names())
def test_golden_confidence_score(case_name: str) -> None:
    """Assert compute_confidence() matches the golden expected score."""
    cases = _load_cases()
    case = next(c for c in cases["cases"] if c["name"] == case_name)
    expected_data = _load_expected(case_name)

    findings = [_build_finding(f) for f in case["findings"]]
    actual = compute_confidence(findings)

    assert actual == expected_data["expected_score"], (
        f"Confidence score drift for {case_name!r}:\n"
        f"  actual={actual}\n"
        f"  expected={expected_data['expected_score']}\n"
        f"  finding_count={len(findings)}\n"
        f"  description={case.get('description', '')}\n"
        f"\n  If the scoring formula changed intentionally, run:\n"
        f"    python scripts/refresh_golden_confidence.py\n"
    )


# ── relative ordering invariant ──────────────────────────────────────

# Dominance chain — each entry scores ≤ the next.
# Catches weighting inversions if scoring constants ever change.
_ORDERING_CHAIN: list[str] = [
    "overwhelm_threshold_crossing",   # most severe scenario (many findings + overwhelm)
    "mixed_severity_sanity",          # multi-category with HIGH → no recovery
    "one_critical_security",          # single CRITICAL → no recovery, but low volume
    "many_low_dead_code",             # many findings but minimal weight + recovery
    "no_findings",                    # clean codebase → highest score
]


def test_golden_confidence_relative_ordering() -> None:
    """Assert scores obey a strict dominance chain across scenarios.

    overwhelm ≤ mixed ≤ one_critical ≤ many_low_dead ≤ no_findings

    This invariant catches weighting inversions that would break the
    intuitive severity gradient even if individual scores shift.
    """
    cases = _load_cases()
    case_map = {c["name"]: c for c in cases["cases"]}

    scores: dict[str, int] = {}
    for name in _ORDERING_CHAIN:
        case = case_map[name]
        findings = [_build_finding(f) for f in case["findings"]]
        scores[name] = compute_confidence(findings)

    for i in range(len(_ORDERING_CHAIN) - 1):
        lo_name = _ORDERING_CHAIN[i]
        hi_name = _ORDERING_CHAIN[i + 1]
        assert scores[lo_name] <= scores[hi_name], (
            f"Relative ordering violation:\n"
            f"  {lo_name} ({scores[lo_name]}) should be ≤ "
            f"{hi_name} ({scores[hi_name]})\n"
            f"  Full chain: {', '.join(f'{n}={scores[n]}' for n in _ORDERING_CHAIN)}\n"
        )
