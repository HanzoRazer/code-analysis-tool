"""Governance gates — enforce migration deadlines, import bans, legacy usage budgets, and SDK boundaries."""

from code_audit.governance.deprecation import DeprecationAnalyzer
from code_audit.governance.import_ban import ImportBanAnalyzer
from code_audit.governance.legacy_usage import LegacyUsageAnalyzer
from code_audit.governance.sdk_boundary import SdkBoundaryAnalyzer

__all__ = [
    "DeprecationAnalyzer",
    "ImportBanAnalyzer",
    "LegacyUsageAnalyzer",
    "SdkBoundaryAnalyzer",
]
