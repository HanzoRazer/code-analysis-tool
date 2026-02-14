"""CI guard: missing summary.vibe_tier is a hard error (exit 2).

Monkeypatches _api_scan_project to return a malformed result dict,
then calls main() directly.  No subprocess, no filesystem dependency.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Import the *real* __main__ from src/, not the repo-root shim.
_spec = importlib.util.spec_from_file_location(
    "code_audit.__main__",
    REPO_ROOT / "src" / "code_audit" / "__main__.py",
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _malformed_result() -> dict:
    """API result missing summary.vibe_tier."""
    return {
        "run": {
            "run_id": "ci-test",
            "created_at": "2000-01-01T00:00:00+00:00",
        },
        "summary": {
            "confidence_score": 80,
            # "vibe_tier" intentionally missing
            "counts": {"findings_total": 0},
        },
    }


class TestScanSubcommandCiGuard:
    """scan subcommand: missing vibe_tier → exit 2."""

    def test_missing_vibe_tier_exits_2(self, monkeypatch, capsys, tmp_path):
        fake = lambda *a, **kw: (None, _malformed_result())
        monkeypatch.setattr(_mod, "_api_scan_project", fake)

        rc = _mod.main([
            "scan", "--root", str(tmp_path),
            "--out", str(tmp_path / "out.json"),
            "--ci",
        ])

        assert rc == 2
        err = capsys.readouterr().err.strip()
        assert err == "error: API result missing required field summary.vibe_tier."


class TestDefaultPositionalCiGuard:
    """default positional: missing vibe_tier → exit 2."""

    def test_missing_vibe_tier_exits_2(self, monkeypatch, capsys, tmp_path):
        fake = lambda *a, **kw: (None, _malformed_result())
        monkeypatch.setattr(_mod, "_api_scan_project", fake)

        rc = _mod.main([str(tmp_path), "--ci"])

        assert rc == 2
        err = capsys.readouterr().err.strip()
        assert err == "error: API result missing required field summary.vibe_tier."
