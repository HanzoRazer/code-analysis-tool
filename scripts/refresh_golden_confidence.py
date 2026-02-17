#!/usr/bin/env python3
"""Refresh golden confidence expected scores from cases.json.

Usage:
    python scripts/refresh_golden_confidence.py

Reads   tests/fixtures/confidence/cases.json
Writes  tests/fixtures/confidence/expected/<case_name>.json   (one per case)

The expected files are committed — CI golden tests compare against them.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# ── repo plumbing ────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from code_audit.insights.confidence import compute_confidence  # noqa: E402
from code_audit.model import AnalyzerType, Severity             # noqa: E402
from code_audit.model.finding import Finding, Location, make_fingerprint  # noqa: E402

_CASES_PATH = _REPO_ROOT / "tests" / "fixtures" / "confidence" / "cases.json"
_EXPECTED_DIR = _REPO_ROOT / "tests" / "fixtures" / "confidence" / "expected"


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


def main() -> None:
    cases = json.loads(_CASES_PATH.read_text(encoding="utf-8"))

    _EXPECTED_DIR.mkdir(parents=True, exist_ok=True)

    for case in cases["cases"]:
        findings = [_build_finding(f) for f in case["findings"]]
        score = compute_confidence(findings)

        payload = {
            "case": case["name"],
            "description": case["description"],
            "finding_count": len(findings),
            "expected_score": score,
        }

        out_path = _EXPECTED_DIR / f"{case['name']}.json"
        out_path.write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"  {case['name']}: {score}  →  {out_path.relative_to(_REPO_ROOT)}")

    print(f"\nWrote {len(cases['cases'])} expected files to {_EXPECTED_DIR.relative_to(_REPO_ROOT)}/")


if __name__ == "__main__":
    main()
