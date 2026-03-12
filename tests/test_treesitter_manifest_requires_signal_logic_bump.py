"""Test: tree-sitter manifest requires signal_logic_version bump on change.

Phase 3 of Multi-Language Analyzer implementation.
Verifies:
1. treesitter_manifest.json exists and is valid.
2. All recorded file hashes match current files.
3. signal_logic_version in manifest equals current versions.json.
4. versions_json_hash is present and correct.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PARSERS_DIR = _REPO_ROOT / "src" / "code_audit" / "parsers"
_VERSIONS_JSON = _REPO_ROOT / "src" / "code_audit" / "contracts" / "versions.json"
_QUERIES_DIR = _REPO_ROOT / "src" / "code_audit" / "data" / "treesitter" / "queries"
_MANIFEST = _REPO_ROOT / "tests" / "contracts" / "treesitter_manifest.json"


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return f"sha256:{h.hexdigest()}"


def _load_manifest() -> dict:
    if not _MANIFEST.exists():
        raise AssertionError(
            f"Missing treesitter manifest: {_MANIFEST}\n"
            "Generate it with:\n"
            "  python scripts/refresh_treesitter_manifest.py\n"
        )
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def _current_signal_logic_version() -> str:
    data = json.loads(_VERSIONS_JSON.read_text(encoding="utf-8"))
    return data["signal_logic_version"]


def _compute_expected_hashes() -> dict[str, str]:
    hashes: dict[str, str] = {}
    for p in sorted(_PARSERS_DIR.glob("*.py")):
        rel = p.relative_to(_REPO_ROOT).as_posix()
        hashes[rel] = _sha256_file(p)
    if _QUERIES_DIR.exists():
        for p in sorted(_QUERIES_DIR.glob("*.scm")):
            rel = p.relative_to(_REPO_ROOT).as_posix()
            hashes[rel] = _sha256_file(p)
    if _VERSIONS_JSON.exists():
        rel = _VERSIONS_JSON.relative_to(_REPO_ROOT).as_posix()
        hashes[rel] = _sha256_file(_VERSIONS_JSON)
    return hashes


def test_treesitter_manifest_exists():
    assert _MANIFEST.exists(), (
        f"Missing: {_MANIFEST}\n"
        "Run: python scripts/refresh_treesitter_manifest.py"
    )


def test_treesitter_manifest_signal_logic_version():
    manifest = _load_manifest()
    current = _current_signal_logic_version()
    assert manifest["signal_logic_version"] == current, (
        "signal_logic_version mismatch in treesitter manifest.\n"
        f"  manifest: {manifest['signal_logic_version']!r}\n"
        f"  current:  {current!r}\n\n"
        "Fix: bump signal_logic_version in versions.json, then:\n"
        "  python scripts/refresh_treesitter_manifest.py"
    )


def test_treesitter_manifest_versions_json_hash():
    manifest = _load_manifest()
    expected = _sha256_file(_VERSIONS_JSON)
    assert manifest["versions_json_hash"] == expected, (
        "versions.json hash mismatch in treesitter manifest.\n"
        f"  manifest: {manifest['versions_json_hash']!r}\n"
        f"  current:  {expected!r}\n\n"
        "Fix: python scripts/refresh_treesitter_manifest.py"
    )


def test_treesitter_manifest_file_hashes_match():
    manifest = _load_manifest()
    recorded = manifest.get("files", {})
    current = _compute_expected_hashes()

    missing = sorted(set(recorded.keys()) - set(current.keys()))
    added = sorted(set(current.keys()) - set(recorded.keys()))
    changed = sorted(
        k for k in set(current.keys()) & set(recorded.keys())
        if current[k] != recorded[k]
    )

    if missing or added or changed:
        lines: list[str] = []
        if missing:
            lines.append("Missing files (in manifest, not on disk):")
            lines.extend(f"  - {k}" for k in missing)
        if added:
            lines.append("New files (on disk, not in manifest):")
            lines.extend(f"  - {k}" for k in added)
        if changed:
            lines.append("Changed files (hash mismatch):")
            for k in changed:
                lines.append(f"  - {k}")
                lines.append(f"      manifest: {recorded[k]}")
                lines.append(f"      current:  {current[k]}")

        raise AssertionError(
            "Treesitter manifest file hashes changed.\n\n"
            + "\n".join(lines) + "\n\n"
            "Any parser change MUST bump signal_logic_version.\n"
            "Fix:\n"
            "  1) Bump signal_logic_version in versions.json\n"
            "  2) Regenerate: python scripts/refresh_treesitter_manifest.py\n"
        )
