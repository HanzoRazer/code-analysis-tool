"""Repo-local shim.

This repo uses a `src/` layout. Some subprocess-based tests invoke
`python -m code_audit` without setting PYTHONPATH, which would normally fail.

This shim makes the package importable from the repo root by extending the
package path to include `src/code_audit/`.
"""

from __future__ import annotations

from pathlib import Path

# Make submodules (e.g. `code_audit.model`) resolve to the real implementation.
_REAL = Path(__file__).resolve().parent.parent / "src" / "code_audit"
if _REAL.exists():
    __path__.append(str(_REAL))  # type: ignore[name-defined]


# Expose __version__ expected by internal modules.
try:
    import runpy as _runpy
    _real_init = _REAL / "__init__.py"
    if _real_init.exists():
        _ns = _runpy.run_path(str(_real_init))
        if "__version__" in _ns:
            __version__ = _ns["__version__"]  # type: ignore[assignment]
except Exception:
    # If anything goes wrong, fall back to an obvious placeholder.
    __version__ = "0.0.0+shim"  # type: ignore[assignment]
