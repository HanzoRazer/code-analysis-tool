"""
Code Analysis Diagnostics Module
================================
Comprehensive diagnostic, validation, and auto-fix tools.
"""

from .validation_suite import (
    ValidationSuite,
    DiagnosticIssue,
    DiagnosticReport,
    FixResult,
    IssueSeverity,
    IssueCategory,
    FixStatus,
    BaseValidator,
    SQLInjectionValidator,
    ShellInjectionValidator,
    ORMSchemaValidator,
    MethodExistenceValidator,
    TypoValidator,
    FalsePositiveFilter,
    run_diagnosis,
)

__all__ = [
    "ValidationSuite",
    "DiagnosticIssue",
    "DiagnosticReport",
    "FixResult",
    "IssueSeverity",
    "IssueCategory",
    "FixStatus",
    "BaseValidator",
    "SQLInjectionValidator",
    "ShellInjectionValidator",
    "ORMSchemaValidator",
    "MethodExistenceValidator",
    "TypoValidator",
    "FalsePositiveFilter",
    "run_diagnosis",
]
