"""Canonical JSON serialization — single dump path for all CLI artifacts.

Guarantees:
  - Stable key ordering (``sort_keys=True``)
  - Trailing newline at EOF
  - ``Path`` objects → POSIX strings
  - Dataclasses → dicts (via ``dataclasses.asdict``)
  - Optional CI-mode float rounding (4 digits)
"""

from __future__ import annotations

import json
from dataclasses import is_dataclass, asdict
from pathlib import Path
from typing import Any, IO, Mapping, Sequence


def _to_builtin(obj: Any) -> Any:
    """Convert common non-JSON types into JSON-safe builtins."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, bool)):
        return obj
    if isinstance(obj, float):
        return obj
    if isinstance(obj, Path):
        return obj.as_posix()
    if is_dataclass(obj):
        return _to_builtin(asdict(obj))
    if isinstance(obj, Mapping):
        return {str(k): _to_builtin(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_to_builtin(v) for v in obj]
    # Fall back to string (keeps CLI resilient)
    return str(obj)


def _round_floats(obj: Any, *, ndigits: int = 4) -> Any:
    """Recursively round floats for cross-platform determinism."""
    if isinstance(obj, float):
        # Keep NaN/inf stable as strings (JSON has no native representation)
        if obj != obj or obj in (float("inf"), float("-inf")):
            return str(obj)
        return round(obj, ndigits)
    if isinstance(obj, Mapping):
        return {k: _round_floats(v, ndigits=ndigits) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round_floats(v, ndigits=ndigits) for v in obj]
    return obj


def stable_json_dumps(
    obj: Any,
    *,
    ci_mode: bool = False,
    indent: int | None = 2,
    _default: Any | None = None,
    **_ignored: Any,
) -> str:
    """
    Canonical JSON serialization used across the CLI and artifacts.

    Guarantees:
      - stable key ordering (sort_keys=True)
      - stable newline at EOF
      - optional float rounding in CI mode
      - defensive conversion of Paths/dataclasses/etc.
    """
    built = _to_builtin(obj)
    if ci_mode:
        built = _round_floats(built)
    s = json.dumps(
        built,
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
        separators=None,  # keep pretty output when indent is set
    )
    return s + "\n"


def stable_json_dump(
    obj: Any,
    fp: IO[str],
    *,
    ci_mode: bool = False,
    indent: int | None = 2,
    _default: Any | None = None,
    **_ignored: Any,
) -> None:
    fp.write(stable_json_dumps(obj, ci_mode=ci_mode, indent=indent))
