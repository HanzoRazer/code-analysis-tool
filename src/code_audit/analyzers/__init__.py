"""Analyzers produce raw findings from source code.

Two calling conventions:

1. **Class-based** (``Analyzer`` protocol) — used by ``core.runner.run_scan``.
   Each analyzer exposes ``id``, ``version``, and
   ``run(root, files) -> list[Finding]``.

2. **Functional** — used by ``code_audit.run_result.build_run_result``.
   Plain functions that accept ``(path, *, root) -> list[dict]``
   returning dicts shaped to satisfy ``run_result.schema.json``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from code_audit.model.finding import Finding


class Analyzer(Protocol):
    """Every analyzer must expose ``id``, ``version``, and ``run()``."""

    id: str
    version: str

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        """Analyze *files* under *root* and return findings."""
        ...
