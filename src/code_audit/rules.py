"""Canonical rule ID registry.

Single source of truth for all rule IDs emitted by code-analysis-tool.
Downstream consumers (e.g., code-rescue-tool) vendor docs/rule_registry.json
which is generated from PUBLIC_RULE_IDS.

Structure:
  PUBLIC_RULE_IDS      - stable, supported, safe for downstream consumption
  EXPERIMENTAL_RULE_IDS - unstable, may change or be removed
  DEPRECATED_RULE_IDS   - scheduled for removal, do not add new usage
  ALL_RULE_IDS         - union of all buckets (internal use only)
"""

from __future__ import annotations

# ── Dead Code (public) ──────────────────────────────────────────────
DC_UNREACHABLE_001 = "DC_UNREACHABLE_001"
DC_IF_FALSE_001 = "DC_IF_FALSE_001"
DC_ASSERT_FALSE_001 = "DC_ASSERT_FALSE_001"

# ── Global State (public) ───────────────────────────────────────────
GST_MUTABLE_DEFAULT_001 = "GST_MUTABLE_DEFAULT_001"
GST_MUTABLE_MODULE_001 = "GST_MUTABLE_MODULE_001"
GST_GLOBAL_KEYWORD_001 = "GST_GLOBAL_KEYWORD_001"

# ── Security (public) ───────────────────────────────────────────────
SEC_HARDCODED_SECRET_001 = "SEC_HARDCODED_SECRET_001"
SEC_EVAL_001 = "SEC_EVAL_001"
SEC_SUBPROCESS_SHELL_001 = "SEC_SUBPROCESS_SHELL_001"
SEC_SQL_INJECTION_001 = "SEC_SQL_INJECTION_001"
SEC_PICKLE_LOAD_001 = "SEC_PICKLE_LOAD_001"
SEC_YAML_UNSAFE_001 = "SEC_YAML_UNSAFE_001"

# ── Buckets ─────────────────────────────────────────────────────────

PUBLIC_RULE_IDS: list[str] = [
    # Dead Code
    DC_UNREACHABLE_001,
    DC_IF_FALSE_001,
    DC_ASSERT_FALSE_001,
    # Global State
    GST_MUTABLE_DEFAULT_001,
    GST_MUTABLE_MODULE_001,
    GST_GLOBAL_KEYWORD_001,
    # Security
    SEC_HARDCODED_SECRET_001,
    SEC_EVAL_001,
    SEC_SUBPROCESS_SHELL_001,
    SEC_SQL_INJECTION_001,
    SEC_PICKLE_LOAD_001,
    SEC_YAML_UNSAFE_001,
]

EXPERIMENTAL_RULE_IDS: list[str] = [
    # Add experimental rules here as they're developed
    # Example: "EXP_UNUSED_IMPORT_001",
]

DEPRECATED_RULE_IDS: list[str] = [
    # Add deprecated rules here before removal
    # Example: "OLD_RULE_001",
]

# Union of all buckets (internal use only)
ALL_RULE_IDS: list[str] = (
    PUBLIC_RULE_IDS + EXPERIMENTAL_RULE_IDS + DEPRECATED_RULE_IDS
)
