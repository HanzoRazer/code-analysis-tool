"""Standalone CI environment contract tests.

These tests enforce that required environment variables are explicitly set
in CI, preventing accidental fallback to implicit defaults.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def _is_ci() -> bool:
    v = os.environ.get("CI", "").strip()
    return v.lower() in {"1", "true", "yes", "on"}


@pytest.mark.contract
def test_ci_requires_confidence_entrypoints_env() -> None:
    """
    Standalone CI contract:
      When running in CI, CONFIDENCE_ENTRYPOINTS must be explicitly set.

    This prevents default entrypoint mode (implicit hashing roots) and makes the
    confidence policy guard stable and reviewable in workflow config.
    """
    if not _is_ci():
        pytest.skip("Not running in CI")

    v = os.environ.get("CONFIDENCE_ENTRYPOINTS", "").strip()
    assert v, (
        "CI requires CONFIDENCE_ENTRYPOINTS to be set.\n"
        "Example:\n"
        "  CONFIDENCE_ENTRYPOINTS=src/code_audit/insights/confidence.py\n"
        "Set this in your GitHub Actions workflow env."
    )

    # Validate repo-relative paths exist (prevents typos silently weakening the guard).
    root = Path(__file__).resolve().parents[1]  # repo root via tests/..
    missing = []
    for rel in [p.strip() for p in v.split(",") if p.strip()]:
        p = root / rel
        if not p.exists():
            missing.append(rel)
    assert not missing, (
        "CONFIDENCE_ENTRYPOINTS contains missing path(s):\n"
        "  - " + "\n  - ".join(missing)
    )
