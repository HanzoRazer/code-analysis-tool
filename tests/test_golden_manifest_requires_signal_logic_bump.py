from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


_REPO_ROOT = Path(__file__).resolve().parents[1]
_EXPECTED_DIR = _REPO_ROOT / "tests" / "fixtures" / "expected"
_MANIFEST = _REPO_ROOT / "tests" / "contracts" / "golden_fixtures_manifest.json"
_SRC = _REPO_ROOT / "src"


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _find_signal_logic_version() -> str:
    """
    Resolve signal_logic_version default without importing runtime modules.
    Canonical location in this repo: src/code_audit/model/run_result.py
    """
    candidates = [
        _SRC / "code_audit" / "model" / "run_result.py",
        _SRC / "code_audit" / "run_result.py",  # legacy layout fallback
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = _read_text(p)
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)
    raise AssertionError(
        "Could not locate signal_logic_version default. Expected it in "
        "src/code_audit/model/run_result.py. If it moved, update the test."
    )


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return f"sha256:{h.hexdigest()}"


def _compute_expected_hashes() -> dict[str, str]:
    """
    Compute deterministic hashes for all golden expected outputs.
    Keys are repo-relative POSIX paths.
    """
    if not _EXPECTED_DIR.exists():
        raise AssertionError(f"Missing expected dir: {_EXPECTED_DIR}")

    files = sorted(_EXPECTED_DIR.glob("*.json"))
    hashes: dict[str, str] = {}
    for p in files:
        rel = p.relative_to(_REPO_ROOT).as_posix()
        hashes[rel] = _sha256_file(p)
    return hashes


def _load_manifest() -> dict[str, Any]:
    if not _MANIFEST.exists():
        raise AssertionError(
            f"Missing golden manifest: {_MANIFEST}\n"
            "Generate it with:\n"
            "  python scripts/refresh_golden_manifest.py\n"
        )
    return json.loads(_read_text(_MANIFEST))


def test_golden_fixtures_manifest_matches_and_requires_signal_logic_version_bump() -> None:
    """
    Hard gate:
      - Any byte change to tests/fixtures/expected/*.json MUST be accompanied by
        a signal_logic_version bump and a refreshed golden manifest.

    Mechanism:
      - golden_fixtures_manifest.json stores:
          { "signal_logic_version": "<current>", "files": { "<relpath>": "sha256:..." } }
      - CI recomputes hashes and compares them. If anything differs, it fails.
      - Also asserts manifest.signal_logic_version equals current default.
    """
    current_signal_logic = _find_signal_logic_version()
    manifest = _load_manifest()

    manifest_ver = manifest.get("signal_logic_version")
    if not isinstance(manifest_ver, str) or not manifest_ver:
        raise AssertionError("Manifest missing non-empty 'signal_logic_version'")

    # If you bumped signal_logic_version, you MUST regenerate manifest.
    assert (
        manifest_ver == current_signal_logic
    ), (
        "signal_logic_version bump enforcement: manifest version mismatch.\n"
        f"  current default signal_logic_version: {current_signal_logic!r}\n"
        f"  manifest signal_logic_version:        {manifest_ver!r}\n\n"
        "Fix:\n"
        "  1) If you intentionally changed golden outputs: bump signal_logic_version in RunResult defaults\n"
        "  2) Regenerate manifest: python scripts/refresh_golden_manifest.py\n"
        "  3) Commit tests/contracts/golden_fixtures_manifest.json and updated goldens\n"
    )

    recorded = manifest.get("files")
    if not isinstance(recorded, dict):
        raise AssertionError("Manifest 'files' must be an object mapping path->sha256")

    current = _compute_expected_hashes()

    # Detect missing/new/changed files deterministically.
    missing = sorted(set(recorded.keys()) - set(current.keys()))
    added = sorted(set(current.keys()) - set(recorded.keys()))
    changed = sorted(k for k in set(current.keys()) & set(recorded.keys()) if current[k] != recorded[k])

    if missing or added or changed:
        lines: list[str] = []
        if missing:
            lines.append("Missing expected files (present in manifest, absent on disk):")
            lines.extend(f"  - {k}" for k in missing)
        if added:
            lines.append("New expected files (present on disk, absent in manifest):")
            lines.extend(f"  - {k}" for k in added)
        if changed:
            lines.append("Changed expected files (hash mismatch):")
            for k in changed:
                lines.append(f"  - {k}")
                lines.append(f"      manifest: {recorded[k]}")
                lines.append(f"      current:  {current[k]}")

        raise AssertionError(
            "Golden fixture contract changed.\n\n"
            + "\n".join(lines)
            + "\n\n"
            "Hard rule: any golden JSON change MUST bump signal_logic_version.\n"
            "Fix:\n"
            "  1) Bump signal_logic_version (RunResult default)\n"
            "  2) Regenerate goldens (per repo process)\n"
            "  3) Refresh manifest: python scripts/refresh_golden_manifest.py\n"
        )
