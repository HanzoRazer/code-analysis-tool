"""Enums shared across the engine and insight layers."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Internal severity — maps to three user-facing tiers via insights/."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    """User-facing vibe tier — maximum three levels."""

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


class Urgency(str, Enum):
    """How urgently the user should act."""

    OPTIONAL = "optional"
    RECOMMENDED = "recommended"
    IMPORTANT = "important"


class AnalyzerType(str, Enum):
    """Canonical analyzer identifiers."""

    COMPLEXITY = "complexity"
    EXCEPTIONS = "exceptions"
    SECURITY = "security"
    SAFETY = "safety"
    GLOBAL_STATE = "global_state"
    DEAD_CODE = "dead_code"
