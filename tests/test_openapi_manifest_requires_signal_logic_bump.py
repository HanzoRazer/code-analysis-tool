"""Contract gate: OpenAPI snapshot changes require signal_logic_version bump.

Hard gate — if ``docs/openapi.json`` changes without a corresponding
``signal_logic_version`` bump (and manifest refresh), CI blocks the merge.

Mechanism:
  - ``tests/contracts/openapi_manifest.json`` stores:
        { "signal_logic_version": "<ver>", "openapi_snapshot_sha256": "sha256:..." }
  - CI recomputes the hash and compares.  If it differs, the test fails.
  - Also asserts manifest.signal_logic_version equals the current default.

Fix workflow:
  1) Bump ``signal_logic_version`` in ``src/code_audit/model/run_result.py``
  2) Regenerate snapshot: ``python scripts/refresh_openapi_snapshot.py --write``
  3) Refresh manifest: ``python scripts/refresh_openapi_manifest.py``
  4) Commit ``docs/openapi.json`` + ``tests/contracts/openapi_manifest.json``
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


_REPO_ROOT = Path(__file__).resolve().parents[1]
_SNAPSHOT = _REPO_ROOT / "docs" / "openapi.json"
_MANIFEST = _REPO_ROOT / "tests" / "contracts" / "openapi_manifest.json"
_SRC = _REPO_ROOT / "src"


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _find_signal_logic_version() -> str:
    """Resolve signal_logic_version without importing runtime modules."""
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
        "Could not locate signal_logic_version default. Expected it in "
        "src/code_audit/model/run_result.py. If it moved, update the test."
    )


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return f"sha256:{h.hexdigest()}"


def _load_manifest() -> dict[str, Any]:
    if not _MANIFEST.exists():
        raise AssertionError(
            f"Missing OpenAPI manifest: {_MANIFEST}\n"
            "Generate it with:\n"
            "  python scripts/refresh_openapi_manifest.py\n"
        )
    return json.loads(_read_text(_MANIFEST))


def test_openapi_manifest_requires_signal_logic_version_bump() -> None:
    """
    Hard gate:
      - Any byte change to docs/openapi.json MUST be accompanied by a
        signal_logic_version bump and a refreshed OpenAPI manifest.
    """
    if not _SNAPSHOT.exists():
        raise AssertionError(
            f"Missing OpenAPI snapshot: {_SNAPSHOT}\n"
            "Generate it with:\n"
            "  python scripts/refresh_openapi_snapshot.py --write\n"
        )

    current_signal_logic = _find_signal_logic_version()
    manifest = _load_manifest()

    # ── version alignment ────────────────────────────────────────
    manifest_ver = manifest.get("signal_logic_version")
    if not isinstance(manifest_ver, str) or not manifest_ver:
        raise AssertionError("Manifest missing non-empty 'signal_logic_version'")

    assert manifest_ver == current_signal_logic, (
        "signal_logic_version bump enforcement: manifest version mismatch.\n"
        f"  current default signal_logic_version: {current_signal_logic!r}\n"
        f"  manifest signal_logic_version:        {manifest_ver!r}\n\n"
        "Fix:\n"
        "  1) If you intentionally changed the Web API surface: bump signal_logic_version\n"
        "  2) Regenerate snapshot: python scripts/refresh_openapi_snapshot.py --write\n"
        "  3) Refresh manifest: python scripts/refresh_openapi_manifest.py\n"
        "  4) Commit docs/openapi.json + tests/contracts/openapi_manifest.json\n"
    )

    # ── hash alignment ───────────────────────────────────────────
    recorded_hash = manifest.get("openapi_snapshot_sha256")
    if not isinstance(recorded_hash, str) or not recorded_hash:
        raise AssertionError("Manifest missing non-empty 'openapi_snapshot_sha256'")

    current_hash = _sha256_file(_SNAPSHOT)

    assert recorded_hash == current_hash, (
        "OpenAPI snapshot contract changed.\n"
        f"  manifest hash: {recorded_hash}\n"
        f"  current hash:  {current_hash}\n\n"
        "Hard rule: any OpenAPI spec change MUST bump signal_logic_version.\n"
        "Fix:\n"
        "  1) Bump signal_logic_version in src/code_audit/model/run_result.py\n"
        "  2) Regenerate snapshot: python scripts/refresh_openapi_snapshot.py --write\n"
        "  3) Refresh manifest: python scripts/refresh_openapi_manifest.py\n"
        "  4) Commit docs/openapi.json + tests/contracts/openapi_manifest.json\n"
    )
