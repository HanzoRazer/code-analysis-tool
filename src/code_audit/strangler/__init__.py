"""Strangler Fig — systematic technical debt detection and elimination.

Modules
-------
debt_detector
    AST-based structural smell detection (God Class, God Function, Deep Nesting).
plan_generator
    Generates markdown refactoring plans from detected debt instances.
debt_registry
    Tracks debt snapshots over time for ratchet/progress comparison.
"""

from code_audit.strangler.debt_detector import DebtDetector
from code_audit.strangler.plan_generator import generate_plan
from code_audit.strangler.debt_registry import DebtRegistry

__all__ = ["DebtDetector", "generate_plan", "DebtRegistry"]
