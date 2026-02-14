"""Repo-root shim package for `python -m code_audit`.

This repository uses a `src/` layout. Some tests and workflows invoke
`python -m code_audit` without installing the package. This shim makes
that work by extending the package search path to include `src/code_audit`.
"""

from __future__ import annotations

from pathlib import Path
from pkgutil import extend_path

__all__ = [
    "__version__",
    "scan_project",
    "snapshot_debt",
    "compare_debt",
    "validate_instance",
]

# Keep in sync with `src/code_audit/__init__.py`.
__version__ = "0.1.0"

# Extend this package's search path to include the `src` implementation.
__path__ = extend_path(__path__, __name__)  # type: ignore[name-defined]

# Programmatic engine entrypoints (backend use) — see docs/CONTRACT.md §8.
from code_audit.api import (  # noqa: E402, F401
    compare_debt,
    scan_project,
    snapshot_debt,
    validate_instance,
)

_repo_root = Path(__file__).resolve().parents[1]
_src_pkg = _repo_root / "src" / "code_audit"
if _src_pkg.exists():
    __path__.append(str(_src_pkg))  # type: ignore[attr-defined]
