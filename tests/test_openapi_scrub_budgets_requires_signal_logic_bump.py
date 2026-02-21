"""Contract gate: OpenAPI scrub budgets require signal_logic_version bump.

Scrub budgets (``tests/contracts/openapi_scrub_budgets.json``) cap the
number of volatile field removals per endpoint.  Raising a budget is
effectively loosening the behavioural contract — that must be:

  * intentional
  * versioned (``signal_logic_version`` bump)
  * traceable in git

This test enforces two directions:

1. **Budgets changed → must bump** ``signal_logic_version`` and refresh
   the budgets manifest.
2. **``signal_logic_version`` bumped → must refresh** the budgets
   manifest so provenance stays aligned.

Fix workflow:
  1) Bump ``signal_logic_version`` in ``src/code_audit/model/run_result.py``
  2) ``python scripts/refresh_openapi_scrub_budgets_manifest.py``
  3) Commit budgets + manifest + signal version bump.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUDGETS = ROOT / "tests" / "contracts" / "openapi_scrub_budgets.json"
MANIFEST = ROOT / "tests" / "contracts" / "openapi_scrub_budgets_manifest.json"


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


def test_openapi_scrub_budgets_requires_signal_logic_bump() -> None:
    """Fail if budgets change without signal_logic_version bump + manifest refresh."""
    assert BUDGETS.exists(), (
        "Missing tests/contracts/openapi_scrub_budgets.json"
    )
    assert MANIFEST.exists(), (
        "Missing tests/contracts/openapi_scrub_budgets_manifest.json\n"
        "Run: python scripts/refresh_openapi_scrub_budgets_manifest.py"
    )

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest.get("manifest_version") == 1
    assert manifest.get("budgets_path") == (
        "tests/contracts/openapi_scrub_budgets.json"
    )

    recorded_sig = manifest.get("signal_logic_version")
    recorded_hash = manifest.get("budgets_sha256")
    assert isinstance(recorded_sig, str) and recorded_sig
    assert isinstance(recorded_hash, str) and recorded_hash

    current_sig = read_signal_logic_version()
    current_hash = sha256_file(BUDGETS)

    changed = current_hash != recorded_hash
    bumped = current_sig != recorded_sig

    if changed and not bumped:
        raise AssertionError(
            "OpenAPI scrub budgets changed without bumping "
            "signal_logic_version.\n\n"
            "Scrub budgets define acceptable volatility per endpoint "
            "(behavioral contract policy).\n"
            "Changing budgets is a semantic contract change.\n\n"
            "Required action:\n"
            "  1) Bump signal_logic_version in "
            "src/code_audit/model/run_result.py\n"
            "  2) python scripts/"
            "refresh_openapi_scrub_budgets_manifest.py\n"
            "  3) Commit updated budgets + manifest\n"
        )

    if bumped and not changed:
        raise AssertionError(
            "signal_logic_version bumped but OpenAPI scrub budgets "
            "manifest not refreshed.\n"
            "Run: python scripts/"
            "refresh_openapi_scrub_budgets_manifest.py\n"
        )
