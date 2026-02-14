"""Repo-root shim for `python -m code_audit`.

Executes the real CLI implementation from `src/code_audit/__main__.py`.
"""

from __future__ import annotations

from pathlib import Path
import importlib.util
import sys


def main(argv: list[str] | None = None) -> int:
    """Invoke the real CLI implementation from the `src/` tree.

    Some tests call `code_audit.__main__.main([...])` directly; match that
    signature here and forward to the implementation.
    """
    repo_root = Path(__file__).resolve().parents[1]
    cli_path = repo_root / "src" / "code_audit" / "__main__.py"

    spec = importlib.util.spec_from_file_location("_code_audit_cli", cli_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load CLI module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # The src CLI exposes `main(argv: list[str] | None) -> int`.
    return int(module.main(argv))


if __name__ == "__main__":
    raise SystemExit(main())
