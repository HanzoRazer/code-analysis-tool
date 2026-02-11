"""Fence registry — loads, stores, and queries fence definitions.

Fence definitions can come from:

1. Built-in defaults (hard-coded in this module).
2. JSON/YAML config files (e.g. ``.fences/safety.json``).
3. Programmatic registration at runtime.

The registry is the single source of truth for "what fences exist" and
is consulted by CLI commands like ``code-audit fence list``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from code_audit.model.fence import FenceDefinition, FenceLevel, FenceType

# ── built-in fence definitions ──────────────────────────────────────

_BUILTIN_FENCES: list[FenceDefinition] = [
    FenceDefinition(
        fence_id="safety_001",
        name="No Bare Except",
        fence_type=FenceType.SAFETY,
        level=FenceLevel.ERROR,
        description=(
            "Bare except clauses hide bugs and can swallow "
            "KeyboardInterrupt. Always catch a specific exception type."
        ),
        enabled=True,
    ),
    FenceDefinition(
        fence_id="safety_002",
        name="Safety Critical Decorator",
        fence_type=FenceType.SAFETY,
        level=FenceLevel.CRITICAL,
        description=(
            "Functions that perform safety-critical operations (G-code, "
            "feed rates, toolpath validation) must be decorated with "
            "@safety_critical."
        ),
        enabled=True,
        config={
            "safety_patterns": [
                "generate_gcode",
                "calculate_feeds",
                "compute_feasibility",
                "validate_toolpath",
            ],
            "exclude_suffixes": ["_hash", "_stub"],
            "decorator_name": "safety_critical",
        },
    ),
]


class FenceRegistry:
    """In-memory registry of fence definitions.

    Usage::

        registry = FenceRegistry()           # loads built-ins
        registry.load_file(Path(".fences/custom.json"))  # overlay
        for fence in registry.list():
            print(fence.fence_id, fence.name)
    """

    def __init__(self, *, include_builtins: bool = True) -> None:
        self._fences: dict[str, FenceDefinition] = {}
        if include_builtins:
            for fence in _BUILTIN_FENCES:
                self.register(fence)

    # ── mutation ─────────────────────────────────────────────────────

    def register(self, fence: FenceDefinition) -> None:
        """Add or replace a fence definition."""
        self._fences[fence.fence_id] = fence

    def load_file(self, path: Path) -> int:
        """Load fence definitions from a JSON file.

        Returns the number of fences loaded.

        Expected format::

            {
              "fences": [
                {
                  "fence_id": "...",
                  "name": "...",
                  "fence_type": "safety",
                  "level": "error",
                  ...
                }
              ]
            }
        """
        data = json.loads(path.read_text(encoding="utf-8"))
        fences_data: list[dict[str, Any]] = data.get("fences", [])
        count = 0
        for fd in fences_data:
            fence = FenceDefinition(
                fence_id=fd["fence_id"],
                name=fd["name"],
                fence_type=FenceType(fd.get("fence_type", "custom")),
                level=FenceLevel(fd.get("level", "error")),
                description=fd.get("description", ""),
                enabled=fd.get("enabled", True),
                config=fd.get("config", {}),
            )
            self.register(fence)
            count += 1
        return count

    # ── queries ──────────────────────────────────────────────────────

    def list(
        self,
        *,
        enabled_only: bool = False,
        fence_type: FenceType | None = None,
    ) -> list[FenceDefinition]:
        """Return fence definitions, optionally filtered."""
        result = list(self._fences.values())
        if enabled_only:
            result = [f for f in result if f.enabled]
        if fence_type is not None:
            result = [f for f in result if f.fence_type == fence_type]
        return sorted(result, key=lambda f: f.fence_id)

    def get(self, fence_id: str) -> FenceDefinition | None:
        """Look up a single fence by ID."""
        return self._fences.get(fence_id)

    def __len__(self) -> int:
        return len(self._fences)

    def __contains__(self, fence_id: str) -> bool:
        return fence_id in self._fences
