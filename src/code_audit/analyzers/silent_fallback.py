"""Silent fallback analyzer — detects incomplete dispatch on typed parameters.

Rules
-----
SF_INCOMPLETE_DISPATCH_001
    Function dispatches on Literal or Enum parameter but does not handle all
    declared values and lacks an explicit raise for unhandled cases.
"""

from __future__ import annotations

import ast
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint
from code_audit.rules import SF_INCOMPLETE_DISPATCH_001


# ── enum extraction helpers ─────────────────────────────────────────


_ENUM_BASE_NAMES = frozenset({
    "Enum", "IntEnum", "StrEnum", "Flag", "IntFlag",
    "enum.Enum", "enum.IntEnum", "enum.StrEnum", "enum.Flag", "enum.IntFlag",
})


def _extract_enum_classes(tree: ast.Module) -> dict[str, set[str]]:
    """Extract enum class names and their member names from the AST.

    Returns a dict mapping class name to set of member names.
    Only handles same-file enum definitions with recognizable base classes.
    """
    enums: dict[str, set[str]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        # Check if any base looks like an Enum
        is_enum = False
        for base in node.bases:
            base_name = _get_name(base)
            if base_name in _ENUM_BASE_NAMES:
                is_enum = True
                break

        if not is_enum:
            continue

        members: set[str] = set()
        for item in node.body:
            # Simple assignment: MEMBER = value
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        # Skip private/dunder members
                        if not name.startswith("_"):
                            members.add(name)
            # Annotated assignment: MEMBER: str = value
            elif isinstance(item, ast.AnnAssign):
                if isinstance(item.target, ast.Name):
                    name = item.target.id
                    if not name.startswith("_"):
                        members.add(name)

        if members:
            enums[node.name] = members

    return enums


def _get_name(node: ast.expr) -> str:
    """Extract a dotted name from an AST node (e.g., 'enum.Enum' or 'Enum')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value_name = _get_name(node.value)
        if value_name:
            return f"{value_name}.{node.attr}"
        return node.attr
    return ""


# ── literal extraction helpers ──────────────────────────────────────


def _extract_literal_values(annotation: ast.expr) -> set[str] | None:
    """Extract values from a Literal[...] type annotation.

    Returns None if this is not a Literal annotation or can't be parsed.
    """
    # Handle Literal[...] or typing.Literal[...]
    if isinstance(annotation, ast.Subscript):
        value_name = _get_name(annotation.value)
        if value_name in ("Literal", "typing.Literal"):
            return _extract_subscript_values(annotation.slice)
    return None


def _extract_subscript_values(node: ast.expr) -> set[str]:
    """Extract literal values from Literal subscript."""
    values: set[str] = set()

    if isinstance(node, ast.Tuple):
        for elt in node.elts:
            val = _extract_constant_value(elt)
            if val is not None:
                values.add(val)
    else:
        val = _extract_constant_value(node)
        if val is not None:
            values.add(val)

    return values


def _extract_constant_value(node: ast.expr) -> str | None:
    """Extract a string representation of a constant value."""
    if isinstance(node, ast.Constant):
        return str(node.value)
    return None


# ── dispatch detection helpers ──────────────────────────────────────


def _find_dispatch_on_param(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    param_name: str,
) -> set[str]:
    """Find values that param_name is dispatched against in if/elif chains and match statements.

    Returns the set of handled values (as strings).
    """
    handled: set[str] = set()

    for node in ast.walk(func):
        # Check if/elif chains
        if isinstance(node, ast.If):
            handled.update(_extract_if_chain_values(node, param_name))

        # Check match statements (Python 3.10+)
        if isinstance(node, ast.Match):
            handled.update(_extract_match_values(node, param_name))

    return handled


def _extract_if_chain_values(node: ast.If, param_name: str) -> set[str]:
    """Extract values compared against param_name in an if/elif chain."""
    values: set[str] = set()

    current: ast.If | None = node
    while current is not None:
        val = _extract_comparison_value(current.test, param_name)
        if val is not None:
            values.add(val)

        # Walk the elif chain
        if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
            current = current.orelse[0]
        else:
            current = None

    return values


def _extract_comparison_value(test: ast.expr, param_name: str) -> str | None:
    """Extract the value being compared to param_name in a comparison expression.

    Handles patterns like:
        - param == "value"
        - param == Enum.MEMBER
        - "value" == param
    """
    if not isinstance(test, ast.Compare):
        return None

    # Only handle simple equality comparisons
    if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
        return None

    left = test.left
    right = test.comparators[0]

    # Check both orderings: param == value and value == param
    if _is_param_reference(left, param_name):
        return _get_comparison_constant(right)
    if _is_param_reference(right, param_name):
        return _get_comparison_constant(left)

    return None


def _is_param_reference(node: ast.expr, param_name: str) -> bool:
    """Check if node is a reference to the parameter."""
    return isinstance(node, ast.Name) and node.id == param_name


def _get_comparison_constant(node: ast.expr) -> str | None:
    """Extract a constant value or enum member name from a comparison operand."""
    # String/number literal: "value" or 42
    if isinstance(node, ast.Constant):
        return str(node.value)

    # Enum member: Mode.REFINED or Enum.MEMBER
    if isinstance(node, ast.Attribute):
        return node.attr

    return None


def _extract_match_values(node: ast.Match, param_name: str) -> set[str]:
    """Extract values from a match statement dispatching on param_name.

    Only handles simple pattern matching on literals/enum members.
    Complex patterns (guards, OR, capture) are skipped.
    """
    values: set[str] = set()

    # Check if the match subject is our parameter
    if not _is_param_reference(node.subject, param_name):
        return values

    for case in node.cases:
        # Skip cases with guards
        if case.guard is not None:
            continue

        val = _extract_pattern_value(case.pattern)
        if val is not None:
            values.add(val)

    return values


def _extract_pattern_value(pattern: ast.pattern) -> str | None:
    """Extract a value from a simple match pattern."""
    # MatchValue: case "literal" or case Enum.MEMBER
    if isinstance(pattern, ast.MatchValue):
        if isinstance(pattern.value, ast.Constant):
            return str(pattern.value.value)
        if isinstance(pattern.value, ast.Attribute):
            return pattern.value.attr

    return None


# ── raise detection ─────────────────────────────────────────────────


def _has_fallback_raise(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if function ends with an unconditional raise or all paths raise.

    This is a simplified check: we look for a raise statement at the end of
    the function body or as the only statement after all if/elif branches.
    """
    if not func.body:
        return False

    last_stmt = func.body[-1]

    # Direct raise at end of function
    if isinstance(last_stmt, ast.Raise):
        return True

    # If/elif chain where the else raises
    if isinstance(last_stmt, ast.If):
        return _if_chain_ends_with_raise(last_stmt)

    # Match statement where default case raises
    if isinstance(last_stmt, ast.Match):
        return _match_has_wildcard_raise(last_stmt)

    return False


def _if_chain_ends_with_raise(node: ast.If) -> bool:
    """Check if an if/elif chain ends with else: raise."""
    current: ast.If | None = node
    while current is not None:
        if len(current.orelse) == 0:
            return False
        if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
            current = current.orelse[0]
        else:
            # This is the else block
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.Raise):
                return True
            return False
    return False


def _match_has_wildcard_raise(node: ast.Match) -> bool:
    """Check if match statement has a wildcard case that raises."""
    for case in node.cases:
        if isinstance(case.pattern, ast.MatchAs) and case.pattern.name is None:
            # Wildcard pattern: case _:
            if len(case.body) == 1 and isinstance(case.body[0], ast.Raise):
                return True
    return False


# ── parameter annotation analysis ───────────────────────────────────


def _get_param_type_info(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    enums: dict[str, set[str]],
) -> list[tuple[str, set[str]]]:
    """Get parameters with known value sets (Literal or Enum types).

    Returns list of (param_name, possible_values) tuples.
    """
    result: list[tuple[str, set[str]]] = []

    for arg in func.args.args + func.args.kwonlyargs:
        if arg.annotation is None:
            continue

        # Check for Literal[...]
        literal_values = _extract_literal_values(arg.annotation)
        if literal_values:
            result.append((arg.arg, literal_values))
            continue

        # Check for Enum type (same-file only)
        type_name = _get_name(arg.annotation)
        if type_name in enums:
            result.append((arg.arg, enums[type_name]))

    return result


# ── analyzer class ──────────────────────────────────────────────────


class SilentFallbackAnalyzer:
    """Detects incomplete dispatch on Literal/Enum typed parameters."""

    id: str = "silent_fallback"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                continue

            rel = path.relative_to(root).as_posix()

            # Extract enum definitions from this file
            enums = _extract_enum_classes(tree)

            # Check all functions
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                self._check_function(node, rel, enums, findings)

        # Assign stable finding IDs
        for i, f in enumerate(findings):
            object.__setattr__(f, "finding_id", f"sf_{f.fingerprint[7:15]}_{i:04d}")

        return findings

    def _check_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        rel: str,
        enums: dict[str, set[str]],
        findings: list[Finding],
    ) -> None:
        """Check a single function for incomplete dispatch."""
        # Get parameters with known value sets
        typed_params = _get_param_type_info(func, enums)
        if not typed_params:
            return

        for param_name, declared_values in typed_params:
            # Find which values are handled in dispatch
            handled = _find_dispatch_on_param(func, param_name)

            if not handled:
                # No dispatch found on this parameter
                continue

            # Find missing values
            missing = declared_values - handled

            if not missing:
                # All values handled
                continue

            # Check for fallback raise
            if _has_fallback_raise(func):
                continue

            # Emit finding
            end_line = getattr(func, "end_lineno", func.lineno) or func.lineno
            missing_str = ", ".join(sorted(missing))
            snippet = f"def {func.name}({param_name}: ...) # missing: {missing_str}"

            findings.append(
                Finding(
                    finding_id="",
                    type=AnalyzerType.SILENT_FALLBACK,
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    message=(
                        f"Function '{func.name}' dispatches on parameter '{param_name}' "
                        f"but does not handle value(s): {missing_str}. "
                        "Add explicit handler or raise NotImplementedError."
                    ),
                    location=Location(path=rel, line_start=func.lineno, line_end=end_line),
                    fingerprint=make_fingerprint(
                        SF_INCOMPLETE_DISPATCH_001, rel, func.name, snippet
                    ),
                    snippet=snippet,
                    metadata={
                        "rule_id": SF_INCOMPLETE_DISPATCH_001,
                        "param": param_name,
                        "missing_values": sorted(missing),
                        "handled_values": sorted(handled),
                    },
                )
            )
