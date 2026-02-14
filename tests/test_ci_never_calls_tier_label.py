"""Meta-test: _tier_label() must never be called in CI mode.

Guarantees no fallback tier logic executes in CI — the API result
is the single source of truth.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Import the real __main__ from src/, not the repo-root shim.
_spec = importlib.util.spec_from_file_location(
    "code_audit.__main__",
    REPO_ROOT / "src" / "code_audit" / "__main__.py",
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _good_result() -> tuple[None, dict]:
    """API result with all required fields present (including vibe_tier)."""
    return (
        None,
        {
            "run": {
                "run_id": "ci-test",
                "created_at": "2000-01-01T00:00:00+00:00",
                "signal_logic_version": "signals_v1",
                "copy_version": "i18n@dev",
            },
            "summary": {
                "confidence_score": 80,
                "vibe_tier": "green",
                "counts": {"findings_total": 0, "by_severity": {}},
            },
            "signals_snapshot": [],
        },
    )


def test_scan_subcommand_ci_never_calls_tier_label(monkeypatch, tmp_path):
    """In CI scan subcommand, _tier_label() must never be called."""
    monkeypatch.setattr(_mod, "_api_scan_project", lambda *a, **kw: _good_result())
    monkeypatch.setattr(
        _mod, "_tier_label",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("_tier_label() was called in CI mode")
        ),
    )

    rc = _mod.main([
        "scan", "--root", str(tmp_path),
        "--out", str(tmp_path / "out.json"),
        "--ci",
    ])
    assert rc == 0


def test_default_positional_ci_never_calls_tier_label(monkeypatch, tmp_path):
    """In CI default positional, _tier_label() must never be called."""
    monkeypatch.setattr(_mod, "_api_scan_project", lambda *a, **kw: _good_result())
    monkeypatch.setattr(
        _mod, "_tier_label",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("_tier_label() was called in CI mode")
        ),
    )

    rc = _mod.main([str(tmp_path), "--ci"])
    assert rc == 0
