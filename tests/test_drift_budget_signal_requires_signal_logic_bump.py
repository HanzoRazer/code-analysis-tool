"""CI gate: drift budget signal governance surfaces require signal_logic_version bump.

Guards:
  - schemas/drift_budget_signal.schema.json
  - scripts/generate_drift_budget_signal.py
  - scripts/validate_drift_budget_signal.py

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
    _REPO_ROOT / "scripts" / "validate_drift_budget_signal.py",
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
    if not _MANIFEST.exists():
        raise AssertionError(
            f"Missing drift budget signal manifest: {_MANIFEST}\n"
            "Generate it with:\n"
            "  python scripts/refresh_drift_budget_signal_manifest.py\n"
        )
    return json.loads(_read_text(_MANIFEST))


def _composite_hash(files: list[Path]) -> str:
    h = hashlib.sha256()
    for f in sorted(files, key=lambda p: str(p.relative_to(_REPO_ROOT))):
        h.update(str(f.relative_to(_REPO_ROOT)).encode("utf-8"))
        h.update(b"\x00")
        h.update(f.read_bytes())
        h.update(b"\x00")
    return f"sha256:{h.hexdigest()}"


def test_drift_budget_signal_schema_exists() -> None:
    """Schema file must exist in schemas/."""
    schema_path = _REPO_ROOT / "schemas" / "drift_budget_signal.schema.json"
    assert schema_path.exists(), f"missing schema: {schema_path}"
    schema = json.loads(_read_text(schema_path))
    assert schema.get("$id") == "drift_budget_signal_v1", (
        f"Schema $id must be 'drift_budget_signal_v1', got {schema.get('$id')!r}"
    )


def test_drift_budget_signal_example_validates() -> None:
    """Example file must validate against the schema."""
    schema_path = _REPO_ROOT / "schemas" / "drift_budget_signal.schema.json"
    example_path = _REPO_ROOT / "schemas" / "drift_budget_signal.example.json"
    if not example_path.exists():
        return  # not required, but if present it must validate
    try:
        import jsonschema
    except ImportError:
        return  # soft skip if jsonschema not installed in test env
    schema = json.loads(_read_text(schema_path))
    example = json.loads(_read_text(example_path))
    jsonschema.validate(instance=example, schema=schema)


def test_drift_budget_signal_changes_require_signal_logic_version_bump() -> None:
    """
    Pre-emptive gate:
      - if any drift budget signal governance surface changes,
        signal_logic_version must be bumped and manifest refreshed.
    """
    missing = [f for f in _GOVERNED_FILES if not f.exists()]
    assert not missing, (
        f"Missing governed files: {[str(f) for f in missing]}"
    )

    current_signal_logic = _find_signal_logic_version()
    manifest = _load_manifest()

    manifest_ver = manifest.get("signal_logic_version")
    manifest_hash = manifest.get("composite_hash")

    assert isinstance(manifest_ver, str) and manifest_ver, (
        "Manifest missing non-empty 'signal_logic_version'"
    )
    assert isinstance(manifest_hash, str) and manifest_hash, (
        "Manifest missing non-empty 'composite_hash'"
    )

    current_hash = _composite_hash(_GOVERNED_FILES)

    # If version bumped, manifest must be refreshed too.
    assert manifest_ver == current_signal_logic, (
        "Drift budget signal manifest out of date for current signal_logic_version.\n"
        f"  current signal_logic_version: {current_signal_logic!r}\n"
        f"  manifest signal_logic_version: {manifest_ver!r}\n"
        "Fix:\n"
        "  python scripts/refresh_drift_budget_signal_manifest.py\n"
    )

    # Core enforcement: if hash changed, version must bump.
    if current_hash != manifest_hash:
        raise AssertionError(
            "Drift budget signal governance surface changed.\n"
            f"  manifest composite_hash: {manifest_hash}\n"
            f"  current  composite_hash: {current_hash}\n\n"
            "Hard rule: bump signal_logic_version, then refresh manifest:\n"
            "  python scripts/refresh_drift_budget_signal_manifest.py\n"
        )
