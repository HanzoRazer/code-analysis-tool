"""Scan configuration dataclass."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScanConfig:
    """Immutable scan configuration.

    Mirrors the seamless tree's ``pipeline/config.py`` for forward-compat.
    """

    root: Path
    out_dir: Path = Path("out")
    format: str = "json"          # json | text
    mode: str = "new"             # legacy | new | shadow (reserved)
    max_file_lines: int = 400
    max_func_lines: int = 60
