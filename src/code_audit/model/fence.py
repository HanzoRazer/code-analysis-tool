"""Fence — data models for architectural boundary contracts.

A *fence* defines a rule that code must satisfy.  Fences are checked by
fence analyzers (e.g. ``SafetyFenceAnalyzer``) and violations are surfaced
as normal ``Finding`` objects through the standard pipeline.

Fence definitions can be loaded from YAML/JSON config files via the
``FenceRegistry``, or constructed programmatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FenceLevel(str, Enum):
    """How severely a fence violation should be treated.

    Maps to the repo's ``Severity`` enum at the analyzer layer:
      INFO    → Severity.INFO
      WARNING → Severity.LOW
      ERROR   → Severity.MEDIUM
      CRITICAL→ Severity.HIGH
      BLOCKER → Severity.CRITICAL
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    BLOCKER = "blocker"


class FenceType(str, Enum):
    """Broad classification of fence rules."""

    SAFETY = "safety"
    IMPORT = "import"
    ARCHITECTURE = "architecture"
    PATTERN = "pattern"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class FenceDefinition:
    """A single fence rule specification.

    Attributes:
        fence_id: Unique identifier, e.g. ``"safety_001"``.
        name: Human-readable name.
        fence_type: Classification (safety, import, architecture, …).
        level: Default severity when the fence is violated.
        description: Longer explanation shown in reports.
        enabled: Whether this fence is active (can be toggled per-profile).
        config: Rule-specific configuration (patterns, thresholds, etc.).
    """

    fence_id: str
    name: str
    fence_type: FenceType
    level: FenceLevel = FenceLevel.ERROR
    description: str = ""
    enabled: bool = True
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fence_id": self.fence_id,
            "name": self.name,
            "fence_type": self.fence_type.value,
            "level": self.level.value,
            "description": self.description,
            "enabled": self.enabled,
            "config": dict(self.config),
        }
