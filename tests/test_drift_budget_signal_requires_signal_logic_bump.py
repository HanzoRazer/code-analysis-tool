"""CI gate: drift budget signal governance surfaces require signal_logic_version bump.

Guards:
  - schemas/drift_budget_signal.schema.json
  - scripts/generate_drift_budget_signal.py

If any governed file changes, signal_logic_version must be bumped and the
manifest refreshed:
    python scripts/refresh_drift_budget_signal_manifest.py
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
_MANIFEST = _REPO_ROOT / "tests" / "contracts" / "drift_budget_signal_manifest.json"

_GOVERNED_FILES = [
    _REPO_ROOT / "schemas" / "drift_budget_signal.schema.json",
    _REPO_ROOT / "scripts" / "generate_drift_budget_signal.py",
]


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _find_signal_logic_version() -> str:
    candidates = [
        _SRC / "code_audit" / "model" / "run_result.py",
        _SRC / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = _read_text(p)
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)
    raise AssertionError(
        "Could not locate signal_logic_version default. "
        "Expected it in src/code_audit/model/run_result.py."
    )


def _load_manifest() -> dict[str, Any]:
    assert _MANIFEST.exists(), (
        f"Missing drift budget signal manifest: {_MANIFEST}\n"
        "Generate it with:\n"
        "  python scripts/refresh_drift_budget_signal_manifest.py\n"
    )
    return json.loads(_read_text(_MANIFEST))


def _file_hash(p: Path) -> str:
    return f"sha256:{hashlib.sha256(p.read_bytes()).hexdigest()}"


def _rel(p: Path) -> str:
    """Relative path with forward slashes (portable across OS)."""
    return str(p.relative_to(_REPO_ROOT)).replace("\\", "/")


def test_drift_budget_signal_surface_requires_signal_logic_bump() -> None:
    """Per-file drift detection with bidirectional enforcement."""
    missing = [f for f in _GOVERNED_FILES if not f.exists()]
    assert not missing, f"Missing governed files: {[str(f) for f in missing]}"

    manifest = _load_manifest()
    current_ver = _find_signal_logic_version()
    manifest_ver = manifest.get("signal_logic_version", "")
    manifest_files = manifest.get("files", {})

    # Detect per-file drift.
    drifted: list[str] = []
    for f in _GOVERNED_FILES:
        rel = _rel(f)
        current_hash = _file_hash(f)
        manifest_hash = manifest_files.get(rel, "")
        if current_hash != manifest_hash:
            drifted.append(rel)

    # Bidirectional enforcement:
    # 1. Files drifted → signal_logic_version must bump + manifest refresh.
    if drifted:
        raise AssertionError(
            "Drift budget signal governance surface changed.\n"
            f"  drifted files: {drifted}\n\n"
            "Hard rule: bump signal_logic_version, then refresh manifest:\n"
            "  python scripts/refresh_drift_budget_signal_manifest.py\n"
        )

    # 2. Version bumped but manifest not refreshed.
    assert manifest_ver == current_ver, (
        "signal_logic_version bumped but manifest not refreshed.\n"
        f"  code:     {current_ver!r}\n"
        f"  manifest: {manifest_ver!r}\n"
        "Fix:\n"
        "  python scripts/refresh_drift_budget_signal_manifest.py\n"
    )
