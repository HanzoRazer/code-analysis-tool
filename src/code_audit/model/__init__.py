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
    """User-facing vibe tier.

    GREEN / YELLOW / RED are assessed tiers. INCONCLUSIVE means the scan
    could not assess the repository; it is not a fourth risk level.
    """

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"
    INCONCLUSIVE = "inconclusive"


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
    ROUTERS = "routers"
    SQL = "sql"
    JS_TS_SECURITY = "js_ts_security"
    CONTEXT_PINNED_HASH = "context_pinned_hash"
    MAXFAIL_MASKING = "maxfail_masking"
    CROSS_COPY_DRIFT = "cross_copy_drift"
    ORDER_DEPENDENCE = "order_dependence"
    UNPINNED_TOOLCHAIN = "unpinned_toolchain"
    PR_SCOPE = "pr_scope"
    NAMESPACE_AUTHORITY_DRIFT = "namespace_authority_drift"
    HOLLOW_GUARANTEE = "hollow_guarantee"
    GATE_WRONG_ARTIFACT = "gate_wrong_artifact"
