"""Contract test: docs/openapi.json must be a spec-valid OpenAPI document.

Runs the validator script as a subprocess — same path CI and developers use —
so dependency wiring and script entrypoint are both exercised.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_openapi_snapshot_is_spec_valid() -> None:
    """docs/openapi.json must pass full OpenAPI spec validation."""
    subprocess.check_call(
        [sys.executable, "scripts/validate_openapi_snapshot.py", "docs/openapi.json"],
        cwd=str(ROOT),
    )
