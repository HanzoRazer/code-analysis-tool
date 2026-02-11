"""Debt detector — AST-based structural smell scanner.

Detects the following Fig Strangler debt patterns:

*  **God Class** — classes with too many methods or attributes.
*  **God Function** — functions/methods exceeding a line-count or
   cyclomatic-complexity threshold.
*  **Deep Nesting** — functions with excessively nested control flow.
*  **Long Parameter List** — functions with too many parameters.

Conforms to the ``Analyzer`` protocol (``id``, ``version``, ``run()``).
Findings map to ``AnalyzerType.COMPLEXITY``.
"""

from __future__ import annotations

import ast
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint
from code_audit.model.debt_instance import (
    DebtInstance,
    DebtType,
    REFACTORING_STRATEGY,
    make_debt_fingerprint,
)


# ── default thresholds ─────────────────────────────────────────────
_GOD_CLASS_METHODS = 10
_GOD_CLASS_ATTRS = 15
_GOD_FUNCTION_LINES = 60
_DEEP_NESTING_DEPTH = 5
_LONG_PARAM_COUNT = 6


def _count_methods(node: ast.ClassDef) -> int:
    """Count direct (non-nested) method definitions in a class."""
    return sum(
        1
        for child in node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _count_attributes(node: ast.ClassDef) -> int:
    """Count ``self.xxx = …`` attribute assignments in ``__init__``."""
    attrs: set[str] = set()
    for child in node.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if child.name == "__init__":
                for stmt in ast.walk(child):
                    if (
                        isinstance(stmt, ast.Assign)
                        and stmt.targets
                        and isinstance(stmt.targets[0], ast.Attribute)
                        and isinstance(stmt.targets[0].value, ast.Name)
                        and stmt.targets[0].value.id == "self"
                    ):
                        attrs.add(stmt.targets[0].attr)
    return len(attrs)


def _function_lines(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Approximate line count for a function body."""
    end = getattr(node, "end_lineno", node.lineno) or node.lineno
    return end - node.lineno + 1


def _max_nesting(node: ast.AST, *, _depth: int = 0) -> int:
    """Return the maximum nesting depth of control-flow constructs."""
    max_d = _depth
    control_types = (ast.If, ast.For, ast.While, ast.With, ast.Try)
    # Python 3.11+ has ast.TryStar
    try:
        control_types = (*control_types, ast.TryStar)  # type: ignore[attr-defined]
    except AttributeError:
        pass

    for child in ast.iter_child_nodes(node):
        if isinstance(child, control_types):
            max_d = max(max_d, _max_nesting(child, _depth=_depth + 1))
        else:
            max_d = max(max_d, _max_nesting(child, _depth=_depth))
    return max_d


def _param_count(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Count parameters excluding ``self`` and ``cls``."""
    args = node.args
    all_args = args.args + args.posonlyargs + args.kwonlyargs
    names = [a.arg for a in all_args]
    skip = {"self", "cls"}
    count = sum(1 for n in names if n not in skip)
    if args.vararg:
        count += 1
    if args.kwarg:
        count += 1
    return count


class DebtDetector:
    """AST-based structural-debt scanner.

    Conforms to the ``Analyzer`` protocol.

    Parameters
    ----------
    god_class_methods:
        Minimum method count to flag as God Class (default: 10).
    god_class_attrs:
        Minimum attribute count to flag as God Class (default: 15).
    god_function_lines:
        Minimum line count to flag as God Function (default: 60).
    deep_nesting_depth:
        Minimum nesting depth to flag (default: 5).
    long_param_count:
        Minimum parameter count to flag (default: 6).
    """

    id: str = "debt_detector"
    version: str = "1.0.0"

    def __init__(
        self,
        *,
        god_class_methods: int = _GOD_CLASS_METHODS,
        god_class_attrs: int = _GOD_CLASS_ATTRS,
        god_function_lines: int = _GOD_FUNCTION_LINES,
        deep_nesting_depth: int = _DEEP_NESTING_DEPTH,
        long_param_count: int = _LONG_PARAM_COUNT,
    ) -> None:
        self._gc_methods = god_class_methods
        self._gc_attrs = god_class_attrs
        self._gf_lines = god_function_lines
        self._nest_depth = deep_nesting_depth
        self._param_count = long_param_count

    # ── public interface ────────────────────────────────────────────

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        """Scan *files* for structural debt and return findings."""
        findings: list[Finding] = []
        debt_items: list[DebtInstance] = []

        for path in files:
            if path.suffix != ".py":
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                continue

            rel = str(path.relative_to(root))
            self._check_classes(tree, rel, findings, debt_items)
            self._check_functions(tree, rel, findings, debt_items)

        # Assign finding IDs
        for i, f in enumerate(findings):
            object.__setattr__(
                f, "finding_id", f"debt_{f.fingerprint[7:15]}_{i:04d}"
            )
        return findings

    def detect(self, root: Path, files: list[Path]) -> list[DebtInstance]:
        """Return raw ``DebtInstance`` objects (for plan generation)."""
        debt_items: list[DebtInstance] = []
        findings: list[Finding] = []

        for path in files:
            if path.suffix != ".py":
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                continue

            rel = str(path.relative_to(root))
            self._check_classes(tree, rel, findings, debt_items)
            self._check_functions(tree, rel, findings, debt_items)

        return debt_items

    # ── internal checks ─────────────────────────────────────────────

    def _check_classes(
        self,
        tree: ast.Module,
        rel: str,
        findings: list[Finding],
        debt_items: list[DebtInstance],
    ) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            methods = _count_methods(node)
            attrs = _count_attributes(node)
            end_line = getattr(node, "end_lineno", node.lineno) or node.lineno

            if methods >= self._gc_methods or attrs >= self._gc_attrs:
                strategy = REFACTORING_STRATEGY[DebtType.GOD_CLASS]
                fp = make_debt_fingerprint(
                    DebtType.GOD_CLASS.value, rel, node.name
                )
                reason_parts: list[str] = []
                if methods >= self._gc_methods:
                    reason_parts.append(f"{methods} methods (≥{self._gc_methods})")
                if attrs >= self._gc_attrs:
                    reason_parts.append(f"{attrs} attributes (≥{self._gc_attrs})")
                reason = ", ".join(reason_parts)

                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.COMPLEXITY,
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        message=(
                            f"God Class '{node.name}': {reason}. "
                            f"Strategy: {strategy}"
                        ),
                        location=Location(
                            path=rel,
                            line_start=node.lineno,
                            line_end=end_line,
                        ),
                        fingerprint=make_fingerprint(
                            "DEBT-GOD-CLASS", rel, node.name, str(methods)
                        ),
                        snippet=f"class {node.name}:",
                        metadata={
                            "rule_id": "DEBT-GOD-CLASS",
                            "debt_type": DebtType.GOD_CLASS.value,
                            "methods": methods,
                            "attributes": attrs,
                            "strategy": strategy,
                        },
                    )
                )
                debt_items.append(
                    DebtInstance(
                        debt_type=DebtType.GOD_CLASS,
                        path=rel,
                        symbol=node.name,
                        line_start=node.lineno,
                        line_end=end_line,
                        metrics={"methods": methods, "attributes": attrs},
                        strategy=strategy,
                        fingerprint=fp,
                    )
                )

    def _check_functions(
        self,
        tree: ast.Module,
        rel: str,
        findings: list[Finding],
        debt_items: list[DebtInstance],
    ) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            lines = _function_lines(node)
            depth = _max_nesting(node)
            params = _param_count(node)
            end_line = getattr(node, "end_lineno", node.lineno) or node.lineno

            # Determine parent class (if any)
            symbol = node.name

            # God Function
            if lines >= self._gf_lines:
                strategy = REFACTORING_STRATEGY[DebtType.GOD_FUNCTION]
                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.COMPLEXITY,
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        message=(
                            f"God Function '{symbol}': {lines} lines "
                            f"(≥{self._gf_lines}). Strategy: {strategy}"
                        ),
                        location=Location(
                            path=rel,
                            line_start=node.lineno,
                            line_end=end_line,
                        ),
                        fingerprint=make_fingerprint(
                            "DEBT-GOD-FUNC", rel, symbol, str(lines)
                        ),
                        snippet=f"def {symbol}(…):",
                        metadata={
                            "rule_id": "DEBT-GOD-FUNC",
                            "debt_type": DebtType.GOD_FUNCTION.value,
                            "lines": lines,
                            "strategy": strategy,
                        },
                    )
                )
                debt_items.append(
                    DebtInstance(
                        debt_type=DebtType.GOD_FUNCTION,
                        path=rel,
                        symbol=symbol,
                        line_start=node.lineno,
                        line_end=end_line,
                        metrics={"lines": lines},
                        strategy=strategy,
                        fingerprint=make_debt_fingerprint(
                            DebtType.GOD_FUNCTION.value, rel, symbol
                        ),
                    )
                )

            # Deep nesting
            if depth >= self._nest_depth:
                strategy = REFACTORING_STRATEGY[DebtType.DEEP_NESTING]
                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.COMPLEXITY,
                        severity=Severity.LOW,
                        confidence=0.80,
                        message=(
                            f"Deep nesting in '{symbol}': depth {depth} "
                            f"(≥{self._nest_depth}). Strategy: {strategy}"
                        ),
                        location=Location(
                            path=rel,
                            line_start=node.lineno,
                            line_end=end_line,
                        ),
                        fingerprint=make_fingerprint(
                            "DEBT-DEEP-NEST", rel, symbol, str(depth)
                        ),
                        snippet=f"def {symbol}(…):",
                        metadata={
                            "rule_id": "DEBT-DEEP-NEST",
                            "debt_type": DebtType.DEEP_NESTING.value,
                            "nesting_depth": depth,
                            "strategy": strategy,
                        },
                    )
                )
                debt_items.append(
                    DebtInstance(
                        debt_type=DebtType.DEEP_NESTING,
                        path=rel,
                        symbol=symbol,
                        line_start=node.lineno,
                        line_end=end_line,
                        metrics={"nesting_depth": depth},
                        strategy=strategy,
                        fingerprint=make_debt_fingerprint(
                            DebtType.DEEP_NESTING.value, rel, symbol
                        ),
                    )
                )

            # Long parameter list
            if params >= self._param_count:
                strategy = REFACTORING_STRATEGY[DebtType.LONG_PARAMETER_LIST]
                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.COMPLEXITY,
                        severity=Severity.LOW,
                        confidence=0.75,
                        message=(
                            f"Long parameter list in '{symbol}': {params} "
                            f"parameters (≥{self._param_count}). "
                            f"Strategy: {strategy}"
                        ),
                        location=Location(
                            path=rel,
                            line_start=node.lineno,
                            line_end=end_line,
                        ),
                        fingerprint=make_fingerprint(
                            "DEBT-LONG-PARAMS", rel, symbol, str(params)
                        ),
                        snippet=f"def {symbol}(…):",
                        metadata={
                            "rule_id": "DEBT-LONG-PARAMS",
                            "debt_type": DebtType.LONG_PARAMETER_LIST.value,
                            "param_count": params,
                            "strategy": strategy,
                        },
                    )
                )
                debt_items.append(
                    DebtInstance(
                        debt_type=DebtType.LONG_PARAMETER_LIST,
                        path=rel,
                        symbol=symbol,
                        line_start=node.lineno,
                        line_end=end_line,
                        metrics={"param_count": params},
                        strategy=strategy,
                        fingerprint=make_debt_fingerprint(
                            DebtType.LONG_PARAMETER_LIST.value, rel, symbol
                        ),
                    )
                )
