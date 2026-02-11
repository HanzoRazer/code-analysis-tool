"""File discovery — find Python files respecting exclusion patterns."""

from __future__ import annotations

from pathlib import Path

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
