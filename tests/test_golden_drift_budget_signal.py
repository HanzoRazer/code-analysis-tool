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
_FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "drift_budget"


def _run_generator(handoff_path: Path, out_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(_GENERATOR), "--in", str(handoff_path), "--out", str(out_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"generator failed:\n{result.stderr}"


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
