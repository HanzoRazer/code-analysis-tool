"""Reports — consolidated technical-debt and audit reporting."""

from code_audit.reports.debt_report import generate_debt_report
from code_audit.reports.exporters import export_result
from code_audit.reports.dashboard import render_dashboard
from code_audit.reports.trend_analysis import compute_trend, load_trend_data

__all__ = [
    "generate_debt_report",
    "export_result",
    "render_dashboard",
    "compute_trend",
    "load_trend_data",
]
