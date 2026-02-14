"""Canonical rule ID registry.

Single source of truth for all rule IDs emitted by code-analysis-tool.
Downstream consumers (e.g., code-rescue-tool) vendor docs/rule_registry.json
which is generated from this module.
"""

from __future__ import annotations

# ── Dead Code ───────────────────────────────────────────────────────
DC_UNREACHABLE_001 = "DC_UNREACHABLE_001"
DC_IF_FALSE_001 = "DC_IF_FALSE_001"
DC_ASSERT_FALSE_001 = "DC_ASSERT_FALSE_001"

# ── Global State ────────────────────────────────────────────────────
GST_MUTABLE_DEFAULT_001 = "GST_MUTABLE_DEFAULT_001"
GST_MUTABLE_MODULE_001 = "GST_MUTABLE_MODULE_001"
GST_GLOBAL_KEYWORD_001 = "GST_GLOBAL_KEYWORD_001"

# ── Security ────────────────────────────────────────────────────────
SEC_HARDCODED_SECRET_001 = "SEC_HARDCODED_SECRET_001"
SEC_EVAL_001 = "SEC_EVAL_001"
SEC_SUBPROCESS_SHELL_001 = "SEC_SUBPROCESS_SHELL_001"
SEC_SQL_INJECTION_001 = "SEC_SQL_INJECTION_001"
SEC_PICKLE_LOAD_001 = "SEC_PICKLE_LOAD_001"
SEC_YAML_UNSAFE_001 = "SEC_YAML_UNSAFE_001"

# ── Canonical list (order: DC, GST, SEC) ────────────────────────────
ALL_RULE_IDS: list[str] = [
    DC_UNREACHABLE_001,
    DC_IF_FALSE_001,
    DC_ASSERT_FALSE_001,
    GST_MUTABLE_DEFAULT_001,
    GST_MUTABLE_MODULE_001,
    GST_GLOBAL_KEYWORD_001,
    SEC_HARDCODED_SECRET_001,
    SEC_EVAL_001,
    SEC_SUBPROCESS_SHELL_001,
    SEC_SQL_INJECTION_001,
    SEC_PICKLE_LOAD_001,
    SEC_YAML_UNSAFE_001,
]
