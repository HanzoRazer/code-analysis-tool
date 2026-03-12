"""Centralised contract version anchors.

Read-only accessor for ``versions.json`` — the single source of truth for
``signal_logic_version`` and other versioned contract knobs.

Usage::

    from code_audit.contracts.versions import signal_logic_version

    print(signal_logic_version())   # "signals_v2"
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_VERSIONS_FILE = Path(__file__).with_name("versions.json")


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    """Load and cache versions.json (immutable at runtime)."""
    if not _VERSIONS_FILE.exists():
        raise FileNotFoundError(
            f"Missing contract versions file: {_VERSIONS_FILE}\n"
            "This file is required for governance. Do not delete it."
        )
    return json.loads(_VERSIONS_FILE.read_text(encoding="utf-8"))


def signal_logic_version() -> str:
    """Return the canonical ``signal_logic_version`` string."""
    return _load()["signal_logic_version"]


def treesitter_manifest_version() -> int:
    """Return the canonical treesitter manifest version integer."""
    return _load()["treesitter_manifest_version"]


def contract_schema_version() -> str:
    """Return the contracts-versions schema identifier."""
    return _load()["contract_schema_version"]


def versions_file_path() -> Path:
    """Return the absolute path to versions.json (for hashing)."""
    return _VERSIONS_FILE.resolve()
