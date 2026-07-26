"""Shared guard: AST-hash manifests must be generated on the CI Python.

AST dumps (``ast.dump``) are **interpreter-sensitive** — the same source hashes
differently across Python minor versions. Manifests baked on one version (e.g.
a dev's 3.14) then fail the gate on CI's 3.11. Regenerating on a different
version does not fix the defect, it *relocates* it to the other version.

The durable cure is to record the context: manifest generation may happen
**only** on the CI Python, enforced here, and the paired gate tests skip on any
other interpreter (see ``_ci_python`` usage in tests). This matches the pattern
established for the BOM manifest in ``refresh_bom_manifest.py``.

Keep ``CI_PYTHON`` in sync with ``.github/workflows/pytest.yml`` (matrix
``python-version``).
"""
from __future__ import annotations

import sys

# Must match .github/workflows/pytest.yml matrix python-version.
CI_PYTHON: tuple[int, int] = (3, 11)


def require_ci_python(tool: str) -> None:
    """Refuse to run *tool* on any interpreter other than the CI Python.

    Call at the top of a manifest-refresh ``main()``. Raises ``SystemExit``
    with a copy-pasteable re-run command when the interpreter is wrong.
    """
    if sys.version_info[:2] != CI_PYTHON:
        ver = ".".join(str(x) for x in sys.version_info[:3])
        req = ".".join(str(x) for x in CI_PYTHON)
        raise SystemExit(
            f"[{tool}] Refusing to run on Python {ver}.\n"
            f"AST-hash manifests must be generated with Python {req} "
            f"(the CI gate version); regenerating on another version writes "
            f"hashes that fail CI.\n"
            f"Re-run: py -{req} scripts/{tool}.py  "
            f"(or: python{req} scripts/{tool}.py)"
        )
