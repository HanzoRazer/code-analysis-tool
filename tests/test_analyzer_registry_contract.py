from __future__ import annotations

import inspect
import pkgutil
from types import ModuleType
from typing import Iterable

import code_audit.analyzers as analyzers_pkg
from code_audit.api import _DEFAULT_ANALYZERS


def _iter_analyzer_modules() -> Iterable[ModuleType]:
    """
    Import all modules under code_audit.analyzers.

    Deterministic order:
      - pkgutil.iter_modules order is filesystem-dependent, so we sort by module name.
    """
    infos = sorted(pkgutil.iter_modules(analyzers_pkg.__path__), key=lambda m: m.name)
    for info in infos:
        yield __import__(f"{analyzers_pkg.__name__}.{info.name}", fromlist=["_"])


def _is_concrete_analyzer_class(cls: type, module: ModuleType) -> bool:
    """
    Convention for an analyzer class:
      - defined in that module (not imported from elsewhere)
      - name ends with Analyzer
      - has required attributes and callable run() method
    """
    if cls.__module__ != module.__name__:
        return False
    if not cls.__name__.endswith("Analyzer"):
        return False

    # Required interface
    if not hasattr(cls, "id") or not isinstance(getattr(cls, "id"), str):
        return False
    if not hasattr(cls, "version") or not isinstance(getattr(cls, "version"), str):
        return False

    run = getattr(cls, "run", None)
    if run is None or not callable(run):
        return False

    # Skip abstract base classes if any are introduced later.
    if inspect.isabstract(cls):
        return False

    return True


def _discover_analyzers() -> set[type]:
    """
    Discover all concrete analyzer classes under code_audit.analyzers.
    """
    found: set[type] = set()
    for module in _iter_analyzer_modules():
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if _is_concrete_analyzer_class(obj, module):
                found.add(obj)
    return found


def test_default_analyzers_is_complete_and_exact() -> None:
    """
    Contract: code_audit.api._DEFAULT_ANALYZERS is the single source of truth.

    - Every concrete Analyzer in code_audit.analyzers must be listed in _DEFAULT_ANALYZERS.
    - _DEFAULT_ANALYZERS must not include any class that isn't discoverable under code_audit.analyzers.
    """
    discovered = _discover_analyzers()
    registered = set(_DEFAULT_ANALYZERS)

    missing = discovered - registered
    extra = registered - discovered

    def _fmt(classes: set[type]) -> str:
        return "\n".join(sorted(f"{c.__module__}.{c.__name__}" for c in classes))

    assert not missing, (
        "Analyzers exist but are NOT registered in code_audit.api._DEFAULT_ANALYZERS.\n"
        "Fix: add them to _DEFAULT_ANALYZERS (canonical scan surface).\n\n"
        f"Missing:\n{_fmt(missing)}"
    )

    assert not extra, (
        "Analyzers are registered in code_audit.api._DEFAULT_ANALYZERS but are NOT discoverable\n"
        "under code_audit.analyzers (stale/renamed/moved class).\n"
        "Fix: remove or update _DEFAULT_ANALYZERS.\n\n"
        f"Extra:\n{_fmt(extra)}"
    )
