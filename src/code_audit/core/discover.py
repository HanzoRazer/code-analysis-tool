"""File discovery — find Python files respecting exclusion patterns."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# Default exclusion prefixes (relative to scan root).
_DEFAULT_EXCLUDES = frozenset(
    {
        ".git",
        ".github",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)

_DEFAULT_IGNORE_FILES = frozenset({".DS_Store"})


@dataclass(frozen=True)
class DiscoverConfig:
    """Configuration for file discovery, ported from the seamless tree.

    All parameters are optional and have sensible defaults.
    """

    root: Path = field(default_factory=lambda: Path("."))
    include_exts: tuple[str, ...] = (".py",)
    ignore_dirs: frozenset[str] = _DEFAULT_EXCLUDES
    ignore_files: frozenset[str] = _DEFAULT_IGNORE_FILES
    follow_symlinks: bool = False
    max_file_bytes: int = 2_000_000  # 2 MB safety limit


def iter_source_files(cfg: DiscoverConfig) -> Iterator[Path]:
    """Yield source files under *cfg.root* respecting all exclusion rules.

    This is the iterator-based API matching the seamless tree.
    """
    root = cfg.root
    if not root.exists():
        return
    for p in root.rglob("*"):
        try:
            if p.is_symlink() and not cfg.follow_symlinks:
                continue
            if p.is_dir():
                continue
            if not p.is_file():
                continue
            if p.name in cfg.ignore_files:
                continue
            if p.suffix.lower() not in cfg.include_exts:
                continue
            # skip if any parent is in ignore_dirs
            if any(part in cfg.ignore_dirs for part in p.relative_to(root).parts):
                continue
            try:
                if p.stat().st_size > cfg.max_file_bytes:
                    continue
            except OSError:
                continue
            yield p.resolve()
        except OSError:
            continue


def discover_py_files(
    root: Path,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[Path]:
    """Recursively find ``*.py`` files under *root*.

    Parameters
    ----------
    root:
        Directory to scan.
    include:
        Glob patterns to include.  Default: ``["**/*.py"]``.
    exclude:
        Directory basenames to skip.  Merged with built-in defaults.

    Returns
    -------
    Sorted list of absolute ``Path`` objects.
    """
    skip = _DEFAULT_EXCLUDES | set(exclude or [])
    patterns = include or ["**/*.py"]

    results: list[Path] = []
    for pat in patterns:
        for p in root.glob(pat):
            # Skip any path whose parents include an excluded directory.
            if any(part in skip for part in p.relative_to(root).parts):
                continue
            if p.is_file():
                results.append(p.resolve())

    return sorted(set(results))
