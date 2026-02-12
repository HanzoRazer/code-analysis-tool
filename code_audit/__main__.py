from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

_ROOT = Path(__file__).resolve().parent.parent
_REAL_MAIN = _ROOT / "src" / "code_audit" / "__main__.py"


def _load_real_main() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_code_audit_real_main", _REAL_MAIN)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load real entrypoint at {_REAL_MAIN}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[arg-type]
    return mod


_real = _load_real_main()

# Re-export the real CLI entrypoint for in-process tests.
main: Callable[..., Any] = getattr(_real, "main")
_build_parser: Callable[..., Any] = getattr(_real, "_build_parser")
_handle_debt: Callable[..., Any] = getattr(_real, "_handle_debt")


if __name__ == "__main__":
    raise SystemExit(main())
