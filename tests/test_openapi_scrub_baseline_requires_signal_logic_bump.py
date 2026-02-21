"""Contract gate: OpenAPI scrub audit baseline requires signal_logic_version bump.

The scrub audit baseline (``tests/contracts/openapi_scrub_audit_baseline.json``)
defines which volatile fields are acceptable to scrub from the public API
contract golden fixtures.  That is a **semantic contract decision**.

This test enforces two directions:

1. **Baseline changed → must bump** ``signal_logic_version`` and refresh
   the baseline manifest.
2. **``signal_logic_version`` bumped → must refresh** the baseline manifest
   so provenance stays aligned.

Fix workflow:
  1) Bump ``signal_logic_version`` in ``src/code_audit/model/run_result.py``
  2) ``python scripts/refresh_openapi_scrub_baseline_manifest.py``
  3) Commit baseline + manifest + signal version bump.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests" / "contracts" / "openapi_scrub_audit_baseline.json"
MANIFEST = ROOT / "tests" / "contracts" / "openapi_scrub_baseline_manifest.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_signal_logic_version() -> str:
    target = ROOT / "src" / "code_audit" / "model" / "run_result.py"
    txt = target.read_text(encoding="utf-8")
    m = re.search(r'\bsignal_logic_version(?:\s*:\s*\S+)?\s*=\s*"([^"]+)"', txt)
    assert m, (
        "Could not locate signal_logic_version in "
        "src/code_audit/model/run_result.py"
    )
    return m.group(1)


def test_openapi_scrub_baseline_requires_signal_logic_bump() -> None:
    """Fail if baseline changes without signal_logic_version bump + manifest refresh."""
    assert BASELINE.exists(), (
        "Missing tests/contracts/openapi_scrub_audit_baseline.json"
    )
    assert MANIFEST.exists(), (
        "Missing tests/contracts/openapi_scrub_baseline_manifest.json\n"
        "Run: python scripts/refresh_openapi_scrub_baseline_manifest.py"
    )

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest.get("manifest_version") == 1
    assert manifest.get("baseline_path") == (
        "tests/contracts/openapi_scrub_audit_baseline.json"
    )

    recorded_sig = manifest.get("signal_logic_version")
    recorded_hash = manifest.get("baseline_sha256")
    assert isinstance(recorded_sig, str) and recorded_sig
    assert isinstance(recorded_hash, str) and recorded_hash

    current_sig = read_signal_logic_version()
    current_hash = sha256_file(BASELINE)

    changed = current_hash != recorded_hash
    bumped = current_sig != recorded_sig

    if changed and not bumped:
        raise AssertionError(
            "OpenAPI scrub audit baseline changed without bumping "
            "signal_logic_version.\n\n"
            "This baseline defines which volatile fields are acceptable "
            "to scrub from the public API contract.\n"
            "Changing it is a semantic contract change.\n\n"
            "Required action:\n"
            "  1) Bump signal_logic_version in "
            "src/code_audit/model/run_result.py\n"
            "  2) python scripts/"
            "refresh_openapi_scrub_baseline_manifest.py\n"
            "  3) Commit updated baseline + manifest\n"
        )

    if bumped and not changed:
        raise AssertionError(
            "signal_logic_version bumped but OpenAPI scrub baseline "
            "manifest not refreshed.\n"
            "Run: python scripts/"
            "refresh_openapi_scrub_baseline_manifest.py\n"
        )

    # Hash must match (covers: baseline changed + version bumped but forgot refresh)
    if current_hash != recorded_hash:
        raise AssertionError(
            "OpenAPI scrub baseline manifest is stale — baseline hash "
            "does not match.\n"
            "Run: python scripts/"
            "refresh_openapi_scrub_baseline_manifest.py\n"
        )

    # signal_logic_version in manifest must match current
    if current_sig != recorded_sig:
        raise AssertionError(
            "OpenAPI scrub baseline manifest records "
            f"signal_logic_version={recorded_sig!r} but current is "
            f"{current_sig!r}.\n"
            "Run: python scripts/"
            "refresh_openapi_scrub_baseline_manifest.py\n"
        )
