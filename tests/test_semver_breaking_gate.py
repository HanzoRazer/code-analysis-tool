"""scripts/check_semver_breaking_gate.py: breaking-change bump rule.

Pre-1.0 a breaking change needs a MINOR bump (SemVer item 4; docs/CONTRACT.md
section 5). From 1.0 on it needs a MAJOR bump.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_semver_breaking_gate.py"
_spec = importlib.util.spec_from_file_location("check_semver_breaking_gate", _SCRIPT)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


@pytest.mark.parametrize(
    ("prev", "current", "ok"),
    [
        ((0, 2, 0), (0, 3, 0), True),   # pre-1.0 minor bump: allowed
        ((0, 2, 0), (0, 2, 1), False),  # pre-1.0 patch bump: too small
        ((0, 2, 0), (1, 0, 0), True),   # leaving 0.x
        ((1, 4, 0), (1, 5, 0), False),  # post-1.0 minor bump: too small
        ((1, 4, 0), (2, 0, 0), True),   # post-1.0 major bump
    ],
)
def test_is_breaking_bump(prev, current, ok) -> None:
    assert gate.is_breaking_bump(prev, current) is ok


def test_required_component_named_in_error() -> None:
    assert gate.breaking_bump_required((0, 2, 0), (0, 2, 1)) == "minor"
    assert gate.breaking_bump_required((1, 0, 0), (1, 1, 0)) == "major"
