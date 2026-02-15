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

PUBLIC_RULE_IDS: list[str] = sorted([
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
])

EXPERIMENTAL_RULE_IDS: list[str] = sorted([
    # Add experimental rules here as they're developed
])

DEPRECATED_RULE_IDS: list[str] = sorted([
    # Add deprecated rules here before removal
])

# Union of all buckets (internal use only)
ALL_RULE_IDS: list[str] = sorted(set(
    PUBLIC_RULE_IDS
    + EXPERIMENTAL_RULE_IDS
    + DEPRECATED_RULE_IDS
))


def _assert_rule_registry_invariants() -> None:
    """Fail fast on invariant violations.

    Called at import time so CI and local runs catch issues immediately.
    """
    import re

    # Pattern matches multi-segment IDs like DC_ASSERT_FALSE_001
    rule_re = re.compile(r"^[A-Z]{2,4}_[A-Z][A-Z0-9_]*_[0-9]{3}$")

    def _check_bucket(name: str, ids: list[str]) -> None:
        if ids != sorted(ids):
            raise AssertionError(f"{name} must be sorted")
        if len(ids) != len(set(ids)):
            raise AssertionError(f"{name} must contain unique IDs")
        bad = [x for x in ids if not rule_re.match(x)]
        if bad:
            raise AssertionError(f"{name} contains invalid rule IDs: {bad}")

    _check_bucket("PUBLIC_RULE_IDS", PUBLIC_RULE_IDS)
    _check_bucket("EXPERIMENTAL_RULE_IDS", EXPERIMENTAL_RULE_IDS)
    _check_bucket("DEPRECATED_RULE_IDS", DEPRECATED_RULE_IDS)
    _check_bucket("ALL_RULE_IDS", ALL_RULE_IDS)

    # Buckets must be disjoint.
    pub = set(PUBLIC_RULE_IDS)
    exp = set(EXPERIMENTAL_RULE_IDS)
    dep = set(DEPRECATED_RULE_IDS)
    overlap = (pub & exp) | (pub & dep) | (exp & dep)
    if overlap:
        raise AssertionError(
            f"Rule ID buckets must be disjoint; overlaps: {sorted(overlap)}"
        )

    # ALL must be exact union.
    union = pub | exp | dep
    if set(ALL_RULE_IDS) != union:
        raise AssertionError(
            "ALL_RULE_IDS must equal union(PUBLIC, EXPERIMENTAL, DEPRECATED)"
        )


_assert_rule_registry_invariants()
