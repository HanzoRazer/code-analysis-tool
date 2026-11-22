"""Builders for scan-integrity tests."""

from __future__ import annotations

from code_audit.core.scan_integrity import AnalyzerOutcome, AnalyzerStatus


def make_outcome(
    analyzer_id: str,
    status: AnalyzerStatus,
    critical: bool = False,
) -> AnalyzerOutcome:
    return AnalyzerOutcome(
        analyzer_id=analyzer_id,
        status=status,
        is_critical=critical,
    )
