"""DebtInstance — model for a detected structural-debt item.

Each ``DebtInstance`` represents a single structural smell discovered by
the ``DebtDetector``.  It carries:

*  **debt_type** — the category of smell (God Class, God Function, etc.)
*  **location** — where in the source it was found
*  **metrics** — quantitative measurements that triggered detection
*  **strategy** — a short recommended refactoring pattern (Extract Class, etc.)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DebtType(str, Enum):
    """Structural technical-debt categories (Fig Strangler taxonomy)."""

    GOD_CLASS = "god_class"
    GOD_FUNCTION = "god_function"
    DEEP_NESTING = "deep_nesting"
    FEATURE_ENVY = "feature_envy"
    LONG_PARAMETER_LIST = "long_parameter_list"
    DATA_CLUMP = "data_clump"


# Mapping from DebtType → recommended refactoring pattern
REFACTORING_STRATEGY: dict[DebtType, str] = {
    DebtType.GOD_CLASS: "Extract Class / Extract Interface",
    DebtType.GOD_FUNCTION: "Extract Method / Decompose Conditional",
    DebtType.DEEP_NESTING: "Extract Method / Replace Nested Conditional with Guard Clauses",
    DebtType.FEATURE_ENVY: "Move Method / Extract and Move",
    DebtType.LONG_PARAMETER_LIST: "Introduce Parameter Object / Preserve Whole Object",
    DebtType.DATA_CLUMP: "Extract Class / Introduce Parameter Object",
}


@dataclass(frozen=True, slots=True)
class DebtInstance:
    """A single structural-debt detection.

    Attributes
    ----------
    debt_type:
        Category of the smell.
    path:
        Workspace-relative path to the file.
    symbol:
        Fully-qualified name (e.g. ``MyClass``, ``MyClass.process``).
    line_start / line_end:
        Source range.
    metrics:
        Quantitative measurements (``methods_count``, ``nesting_depth``, etc.).
    strategy:
        Recommended refactoring approach.
    fingerprint:
        Deterministic hash for baseline comparison.
    """

    debt_type: DebtType
    path: str
    symbol: str
    line_start: int
    line_end: int
    metrics: dict[str, Any] = field(default_factory=dict)
    strategy: str = ""
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "debt_type": self.debt_type.value,
            "path": self.path,
            "symbol": self.symbol,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "metrics": dict(self.metrics),
            "strategy": self.strategy,
            "fingerprint": self.fingerprint,
        }


def make_debt_fingerprint(
    debt_type: str,
    path: str,
    symbol: str,
) -> str:
    """Deterministic fingerprint for a debt instance."""
    payload = "|".join([debt_type, path, symbol])
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
