"""Refresh the drift budget signal manifest.

Hashes the governance surfaces:
  - schemas/drift_budget_signal.schema.json
  - scripts/generate_drift_budget_signal.py
  - scripts/validate_drift_budget_signal.py

Locks them behind the current signal_logic_version.

Usage:
    python scripts/refresh_drift_budget_signal_manifest.py
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
OUT = REPO_ROOT / "tests" / "contracts" / "drift_budget_signal_manifest.json"

GOVERNED_FILES = [
    REPO_ROOT / "schemas" / "drift_budget_signal.schema.json",
    REPO_ROOT / "scripts" / "generate_drift_budget_signal.py",
    REPO_ROOT / "scripts" / "validate_drift_budget_signal.py",
]


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _find_signal_logic_version() -> str:
    candidates = [
        SRC / "code_audit" / "model" / "run_result.py",
        SRC / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = _read_text(p)
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)
    raise SystemExit("error: could not locate signal_logic_version default")


def _file_hash(p: Path) -> str:
    """SHA-256 of a file's contents."""
    content = p.read_bytes()
    return hashlib.sha256(content).hexdigest()


def _composite_hash(files: list[Path]) -> str:
    """Deterministic composite hash of multiple files (sorted by relative path)."""
    h = hashlib.sha256()
    for f in sorted(files, key=lambda p: str(p.relative_to(REPO_ROOT))):
        h.update(str(f.relative_to(REPO_ROOT)).encode("utf-8"))
        h.update(b"\x00")
        h.update(f.read_bytes())
        h.update(b"\x00")
    return f"sha256:{h.hexdigest()}"


def main() -> int:
    missing = [f for f in GOVERNED_FILES if not f.exists()]
    if missing:
        for f in missing:
            print(f"error: missing governed file: {f}")
        return 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "signal_logic_version": _find_signal_logic_version(),
        "composite_hash": _composite_hash(GOVERNED_FILES),
        "files": {
            str(f.relative_to(REPO_ROOT)): f"sha256:{_file_hash(f)}"
            for f in sorted(GOVERNED_FILES, key=lambda p: str(p.relative_to(REPO_ROOT)))
        },
    }
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
