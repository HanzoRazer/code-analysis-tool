"""Signal translator — converts raw findings into schema-aligned signal dicts.

Produces objects matching ``$defs/signal_snapshot`` in run_result.schema.json:
  - signal_id   (stable, derived from fingerprint)
  - type        (analyzer type string)
  - risk_level  (green / yellow / red)
  - urgency     (optional / recommended / important)
  - evidence    (finding_ids + primary_location)
  - i18n copy keys: title_key, summary_key, why_key, action.text_key (type-level)
"""

from __future__ import annotations

from itertools import groupby
from operator import attrgetter

from code_audit.model import RiskLevel, Severity, AnalyzerType
from code_audit.model.finding import Finding

# ── copy-key contract (schema-adjacent, must be stable) ────────────────
# These constants make copy-key construction a policy lever even if code
# is refactored. The translator policy hash extractor includes EVIDENCE_*
# constants, so these are always tracked.
EVIDENCE_TITLE_KEY_FIELD = "title_key"
EVIDENCE_SUMMARY_KEY_FIELD = "summary_key"
EVIDENCE_WHY_KEY_FIELD = "why_key"
EVIDENCE_ACTION_FIELD = "action"
EVIDENCE_ACTION_TEXT_KEY_FIELD = "text_key"
EVIDENCE_I18N_TITLE_SUFFIX = ".title"
EVIDENCE_I18N_SUMMARY_SUFFIX = ".summary"
EVIDENCE_I18N_WHY_SUFFIX = ".why"
EVIDENCE_I18N_ACTION_TEXT_SUFFIX = ".action.text"

# ── deterministic severity ranking ───────────────────────────────────

def _severity_rank(s: Severity) -> int:
    """Explicit rank — avoids relying on Enum ordering."""
    if s == Severity.CRITICAL:
        return 4
    if s == Severity.HIGH:
        return 3
    if s == Severity.MEDIUM:
        return 2
    if s == Severity.LOW:
        return 1
    return 0  # INFO


def _risk_from_worst_severity(worst: Severity) -> str:
    """Map finding severity to signal risk level string.

    Policy: medium → yellow, high/critical → red, low/info → green.
    """
    if worst in (Severity.HIGH, Severity.CRITICAL):
        return "red"
    if worst == Severity.MEDIUM:
        return "yellow"
    return "green"


def _urgency_from_severity(worst: Severity) -> str:
    """Map worst severity to urgency string."""
    if worst in (Severity.CRITICAL, Severity.HIGH):
        return "important"
    if worst == Severity.MEDIUM:
        return "recommended"
    return "optional"

# ── i18n copy key prefix by analyzer type ─────────────────────────────
_COPY_PREFIX: dict[AnalyzerType, str] = {
    # Canonical i18n shape: i18n/en/signals.json -> {"signals": {"dead_code": {"title": ...}}}
    # Therefore copy keys must be: "signals.<type>.<field>" (plural, type-level).
    AnalyzerType.COMPLEXITY: "signals.complexity",
    AnalyzerType.EXCEPTIONS: "signals.exceptions",
    AnalyzerType.SECURITY: "signals.security",
    AnalyzerType.SAFETY: "signals.safety",
    AnalyzerType.GLOBAL_STATE: "signals.global_state",
    AnalyzerType.DEAD_CODE: "signals.dead_code",
}


def _prefix_for_type(t: AnalyzerType) -> str:
    return _COPY_PREFIX.get(t, f"signals.{t.value}")


def _worst_severity(findings: list[Finding]) -> Severity:
    """Return the highest severity from a group of findings.

    Deterministic: uses explicit rank, not list order or Enum ordering.
    """
    if not findings:
        return Severity.INFO
    return max((f.severity for f in findings), key=_severity_rank)


def _group_key(f: Finding) -> str:
    """Group by rule_id if available, else by type."""
    if f.metadata and "rule_id" in f.metadata:
        return f.metadata["rule_id"]
    return f.type.value


# ── rule ordering for global_state evidence ─────────────────────────
_GST_RULE_ORDER: dict[str, int] = {
    "GST_MUTABLE_DEFAULT_001": 0,
    "GST_MUTABLE_MODULE_001": 1,
    "GST_GLOBAL_KEYWORD_001": 2,
}
# ── rule ordering for dead_code evidence ─────────────────────────────
_DC_RULE_ORDER: dict[str, int] = {
    "DC_UNREACHABLE_001": 0,
    "DC_IF_FALSE_001": 1,
    "DC_ASSERT_FALSE_001": 2,
}
# ── rule ordering for security evidence ──────────────────────────────
_SEC_RULE_ORDER: dict[str, int] = {
    "SEC_HARDCODED_SECRET_001": 0,
    "SEC_EVAL_001": 1,
    "SEC_SUBPROCESS_SHELL_001": 2,
    "SEC_SQL_INJECTION_001": 3,
    "SEC_PICKLE_LOAD_001": 4,
    "SEC_YAML_UNSAFE_001": 5,
}




def _signal_from_global_state(findings: list[Finding]) -> dict:
    """Aggregate all global_state findings into a single signal."""
    worst = _worst_severity(findings)
    prefix = _prefix_for_type(AnalyzerType.GLOBAL_STATE)

    # Evidence ordering: mutable defaults first, then module mutables, then global keyword
    ordered = sorted(
        findings,
        key=lambda f: (
            _GST_RULE_ORDER.get((f.metadata or {}).get("rule_id", ""), 99),
            f.location.path,
            f.location.line_start,
        ),
    )
    first = ordered[0]

    mutable_default_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "GST_MUTABLE_DEFAULT_001"
    )
    module_mutable_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "GST_MUTABLE_MODULE_001"
    )
    global_keyword_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "GST_GLOBAL_KEYWORD_001"
    )

    return {
        "signal_id": f"sig_{first.fingerprint[:16]}",
        "type": "global_state",
        "risk_level": _risk_from_worst_severity(worst),
        "urgency": _urgency_from_severity(worst),
        "title_key": f"{prefix}.title",
        "summary_key": f"{prefix}.summary",
        "why_key": f"{prefix}.why",
        "action": {
            "text_key": f"{prefix}.action.text",
            "urgency": _urgency_from_severity(worst),
        },
        "footer_key": f"{prefix}.footer",
        "footer_icon_key": f"{prefix}.footer_icon",
        "evidence": {
            "finding_ids": [f.finding_id for f in ordered],
            "summary": {
                "mutable_default_count": mutable_default_count,
                "module_mutable_count": module_mutable_count,
                "global_keyword_count": global_keyword_count,
            },
            "primary_location": {
                "path": first.location.path,
                "line_start": first.location.line_start,
                "line_end": first.location.line_end,
            },
        },
    }




def _signal_from_dead_code(findings: list[Finding]) -> dict:
    """Aggregate all dead_code findings into a single signal."""
    worst = _worst_severity(findings)
    prefix = _prefix_for_type(AnalyzerType.DEAD_CODE)

    # Evidence ordering: unreachable first, then if_false, then assert_false
    ordered = sorted(
        findings,
        key=lambda f: (
            _DC_RULE_ORDER.get((f.metadata or {}).get("rule_id", ""), 99),
            f.location.path,
            f.location.line_start,
        ),
    )
    first = ordered[0]

    unreachable_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "DC_UNREACHABLE_001"
    )
    if_false_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "DC_IF_FALSE_001"
    )
    assert_false_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "DC_ASSERT_FALSE_001"
    )

    return {
        "signal_id": f"sig_{first.fingerprint[:16]}",
        "type": "dead_code",
        "risk_level": _risk_from_worst_severity(worst),
        "urgency": _urgency_from_severity(worst),
        "title_key": f"{prefix}.title",
        "summary_key": f"{prefix}.summary",
        "why_key": f"{prefix}.why",
        "action": {
            "text_key": f"{prefix}.action.text",
            "urgency": _urgency_from_severity(worst),
        },
        "footer_key": f"{prefix}.footer",
        "footer_icon_key": f"{prefix}.footer_icon",
        "evidence": {
            "finding_ids": [f.finding_id for f in ordered],
            "summary": {
                "unreachable_count": unreachable_count,
                "if_false_count": if_false_count,
            },
            "primary_location": {
                "path": first.location.path,
                "line_start": first.location.line_start,
                "line_end": first.location.line_end,
            },
        },
    }




def _signal_from_security(findings: list[Finding]) -> dict:
    """Aggregate all security findings into a single signal."""
    worst = _worst_severity(findings)
    prefix = _prefix_for_type(AnalyzerType.SECURITY)

    # Evidence ordering: secrets first, then eval, then others
    ordered = sorted(
        findings,
        key=lambda f: (
            _SEC_RULE_ORDER.get((f.metadata or {}).get("rule_id", ""), 99),
            f.location.path,
            f.location.line_start,
        ),
    )
    first = ordered[0]

    hardcoded_secret_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "SEC_HARDCODED_SECRET_001"
    )
    eval_exec_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "SEC_EVAL_001"
    )
    subprocess_shell_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "SEC_SUBPROCESS_SHELL_001"
    )
    sql_injection_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "SEC_SQL_INJECTION_001"
    )
    pickle_load_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "SEC_PICKLE_LOAD_001"
    )
    yaml_unsafe_count = sum(
        1 for f in findings
        if (f.metadata or {}).get("rule_id") == "SEC_YAML_UNSAFE_001"
    )

    return {
        "signal_id": f"sig_{first.fingerprint[:16]}",
        "type": "security",
        "risk_level": _risk_from_worst_severity(worst),
        "urgency": _urgency_from_severity(worst),
        "title_key": f"{prefix}.title",
        "summary_key": f"{prefix}.summary",
        "why_key": f"{prefix}.why",
        "action": {
            "text_key": f"{prefix}.action.text",
            "urgency": _urgency_from_severity(worst),
        },
        "footer_key": f"{prefix}.footer",
        "footer_icon_key": f"{prefix}.footer_icon",
        "evidence": {
            "finding_ids": [f.finding_id for f in ordered],
            "summary": {
                "hardcoded_secret_count": hardcoded_secret_count,
                "eval_exec_count": eval_exec_count,
                "subprocess_shell_count": subprocess_shell_count,
                "sql_injection_count": sql_injection_count,
                "pickle_load_count": pickle_load_count,
                "yaml_unsafe_count": yaml_unsafe_count,
            },
            "primary_location": {
                "path": first.location.path,
                "line_start": first.location.line_start,
                "line_end": first.location.line_end,
            },
        },
    }


def findings_to_signals(findings: list[Finding]) -> list[dict]:
    """Translate findings into schema-aligned signal snapshot dicts.

    Findings are grouped by rule_id so each signal aggregates related issues.
    Global-state findings are aggregated into a single signal.
    """
    if not findings:
        return []

    signals: list[dict] = []

    # Separate global_state, dead_code, and security findings for single-signal aggregation
    global_state_findings = [
        f for f in findings if f.type == AnalyzerType.GLOBAL_STATE
    ]
    dead_code_findings = [
        f for f in findings if f.type == AnalyzerType.DEAD_CODE
    ]
    security_findings = [
        f for f in findings if f.type == AnalyzerType.SECURITY
    ]
    other_findings = [
        f for f in findings
        if f.type not in (AnalyzerType.GLOBAL_STATE, AnalyzerType.DEAD_CODE, AnalyzerType.SECURITY)
    ]

    # Process non-global_state findings (one signal per rule_id)
    sorted_findings = sorted(other_findings, key=_group_key)

    for rule_id, group_iter in groupby(sorted_findings, key=_group_key):
        group = list(group_iter)
        worst = _worst_severity(group)
        first = group[0]
        # Default fallback also uses plural "signals" to match i18n.
        prefix = _COPY_PREFIX.get(first.type, f"signals.{first.type.value}")

        signal: dict = {
            "signal_id": f"sig_{first.fingerprint[:16]}",
            "type": first.type.value,
            "risk_level": _risk_from_worst_severity(worst),
            "urgency": _urgency_from_severity(worst),
            # i18n is type-level, not rule-level
            "title_key": f"{prefix}.title",
            "summary_key": f"{prefix}.summary",
            "why_key": f"{prefix}.why",
            "action": {
                # i18n/en/signals.json uses action.text
                "text_key": f"{prefix}.action.text",
                "urgency": _urgency_from_severity(worst),
            },
            "evidence": {
                "finding_ids": [f.finding_id for f in group],
                "summary": {
                    "swallowed_count": sum(
                        1 for f in group
                        if (f.metadata or {}).get("rule_id") in (
                            "EXC_SWALLOW_001", "EXC-SWALLOW-001"
                        )
                    ),
                    "logged_count": sum(
                        1 for f in group
                        if (f.metadata or {}).get("rule_id") in (
                            "EXC_BROAD_LOGGED_001", "EXC-BROAD-LOGGED-001"
                        )
                    ),
                },
                "primary_location": {
                    "path": first.location.path,
                    "line_start": first.location.line_start,
                    "line_end": first.location.line_end,
                },
            },
        }
        signals.append(signal)

    # Aggregate all global_state findings into one signal
    if global_state_findings:
        signals.append(_signal_from_global_state(global_state_findings))

    # Aggregate all dead_code findings into one signal
    if dead_code_findings:
        signals.append(_signal_from_dead_code(dead_code_findings))

    # Aggregate all security findings into one signal
    if security_findings:
        signals.append(_signal_from_security(security_findings))

    return signals
