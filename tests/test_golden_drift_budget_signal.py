"""Golden fixture tests for the drift budget signal generator.

Runs the generator via subprocess with known handoff inputs and
deep-compares JSON output against expected fixtures.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_GENERATOR = _REPO_ROOT / "scripts" / "generate_drift_budget_signal.py"
_VALIDATOR = _REPO_ROOT / "scripts" / "validate_drift_budget_signal.py"
_FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "drift_budget"


def _run_generator(handoff_path: Path, out_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(_GENERATOR), "--in", str(handoff_path), "--out", str(out_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"generator failed:\n{result.stderr}"


def _run_inline_case(handoff_obj: dict, expected_name: str, tmp_path: Path, out_slug: str) -> None:
    """Write a handoff dict to disk, run generator, validate, and compare to expected fixture."""
    out = tmp_path / f"out_{out_slug}.json"
    handoff_path = tmp_path / f"handoff_{out_slug}.json"
    handoff_path.write_text(json.dumps(handoff_obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    expected = _FIXTURES / expected_name
    assert expected.exists(), f"missing expected: {expected}"

    _run_generator(handoff_path, out)

    # Also validate against schema.
    val = subprocess.run(
        [sys.executable, str(_VALIDATOR), str(out)],
        capture_output=True,
        text=True,
    )
    assert val.returncode == 0, f"validator failed:\n{val.stderr}"

    got = json.loads(out.read_text(encoding="utf-8"))
    exp = json.loads(expected.read_text(encoding="utf-8"))
    assert got == exp, (
        f"Golden mismatch for {out_slug}:\n"
        f"  expected: {json.dumps(exp, indent=2, sort_keys=True)}\n"
        f"  actual:   {json.dumps(got, indent=2, sort_keys=True)}"
    )


@pytest.mark.parametrize(
    "handoff_name,expected_name",
    [
        ("handoff_unresolved.json", "expected_unresolved.json"),
        ("handoff_resolved.json", "expected_resolved.json"),
    ],
)
def test_golden_drift_budget_signal(handoff_name: str, expected_name: str) -> None:
    """Generator output must exactly match the golden expected fixture."""
    handoff_path = _FIXTURES / handoff_name
    expected_path = _FIXTURES / expected_name
    assert handoff_path.exists(), f"missing fixture: {handoff_path}"
    assert expected_path.exists(), f"missing fixture: {expected_path}"

    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "signal.json"
        _run_generator(handoff_path, out_path)
        actual = json.loads(out_path.read_text(encoding="utf-8"))

    assert actual == expected, (
        f"Golden mismatch for {handoff_name}:\n"
        f"  expected: {json.dumps(expected, indent=2, sort_keys=True)}\n"
        f"  actual:   {json.dumps(actual, indent=2, sort_keys=True)}"
    )


def test_golden_drift_budget_signal_duration_boundaries(tmp_path: Path) -> None:
    """Lock _human_duration() formatting at hour/day/minute boundaries."""
    boundary = json.loads((_FIXTURES / "handoff_boundaries.json").read_text(encoding="utf-8"))
    cases = boundary.get("cases", [])
    assert isinstance(cases, list) and cases, "handoff_boundaries.json must contain non-empty cases[]"

    expected_map = {
        "1m": "expected_1m.json",
        "59m": "expected_59m.json",
        "1h0m": "expected_1h0m.json",
        "1d0m": "expected_1d0m.json",
        "1d1h0m": "expected_1d1h0m.json",
    }

    for c in cases:
        name = c.get("name")
        handoff = c.get("handoff")
        assert name in expected_map, f"unexpected boundary case name: {name}"
        assert isinstance(handoff, dict), f"boundary case {name} missing handoff object"
        _run_inline_case(handoff, expected_map[name], tmp_path, out_slug=f"boundary_{name}")
