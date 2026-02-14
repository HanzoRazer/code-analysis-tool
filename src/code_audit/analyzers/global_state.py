"""Global-state analyzer — detects module mutables, mutable defaults, and global keyword.

Rules
-----
GST_MUTABLE_MODULE_001
    Module-level assignment to mutable literal or constructor call.
GST_MUTABLE_DEFAULT_001
    Function argument with mutable default value.
GST_GLOBAL_KEYWORD_001
    ``global`` statement inside a function.
"""

from __future__ import annotations

import ast
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# ── mutable detection helpers ────────────────────────────────────────

_MUTABLE_CONSTRUCTOR_NAMES = frozenset({"list", "dict", "set", "defaultdict"})


def _is_mutable_literal(node: ast.expr) -> bool:
    """Return True for ``[]``, ``{}``, ``set()`` literals."""
    return isinstance(node, (ast.List, ast.Dict, ast.Set))


def _is_mutable_constructor_call(node: ast.expr) -> bool:
    """Return True for calls like ``list()``, ``dict()``, ``set()``, ``defaultdict(...)``."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id in _MUTABLE_CONSTRUCTOR_NAMES:
        return True
    # Support ``collections.defaultdict(...)``
    if isinstance(func, ast.Attribute) and func.attr in _MUTABLE_CONSTRUCTOR_NAMES:
        return True
    return False


def _is_mutable_value(node: ast.expr) -> bool:
    """Combined check for mutable literals and constructor calls."""
    return _is_mutable_literal(node) or _is_mutable_constructor_call(node)


# ── analyzer class ───────────────────────────────────────────────────


class GlobalStateAnalyzer:
    """Finds module-level mutable state, mutable default arguments, and global keyword usage."""

    id: str = "global_state"
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
            self._check_module_level(tree, rel, findings)
            self._check_functions(tree, rel, findings)

        # Assign stable finding IDs
        for i, f in enumerate(findings):
            object.__setattr__(f, "finding_id", f"gst_{f.fingerprint[7:15]}_{i:04d}")

        return findings

    # ── module-level mutable assignments ─────────────────────────────

    def _check_module_level(
        self,
        tree: ast.Module,
        rel: str,
        findings: list[Finding],
    ) -> None:
        """Detect module-level ``Assign`` / ``AnnAssign`` to mutable values."""
        for node in tree.body:
            if isinstance(node, ast.Assign):
                if node.value is not None and _is_mutable_value(node.value):
                    for target in node.targets:
                        name = _target_name(target)
                        snippet = f"{name} = {_value_repr(node.value)}"
                        self._emit_module_mutable(
                            rel, node.lineno, node.end_lineno, name, snippet, findings,
                        )

            elif isinstance(node, ast.AnnAssign):
                if node.value is not None and _is_mutable_value(node.value):
                    name = _target_name(node.target)
                    snippet = f"{name}: ... = {_value_repr(node.value)}"
                    self._emit_module_mutable(
                        rel, node.lineno, node.end_lineno, name, snippet, findings,
                    )

    def _emit_module_mutable(
        self,
        rel: str,
        line: int,
        end_line: int | None,
        symbol: str,
        snippet: str,
        findings: list[Finding],
    ) -> None:
        end = end_line or line
        rule_id = "GST_MUTABLE_MODULE_001"
        findings.append(
            Finding(
                finding_id="",
                type=AnalyzerType.GLOBAL_STATE,
                severity=Severity.MEDIUM,
                confidence=0.85,
                message=(
                    "Module-level mutable state can leak across imports and tests — "
                    "consider a factory function or class attribute instead."
                ),
                location=Location(path=rel, line_start=line, line_end=end),
                fingerprint=make_fingerprint(rule_id, rel, symbol, snippet),
                snippet=snippet,
                metadata={"rule_id": rule_id},
            )
        )

    # ── function-level checks (mutable defaults + global keyword) ────

    def _check_functions(
        self,
        tree: ast.Module,
        rel: str,
        findings: list[Finding],
    ) -> None:
        """Walk all function defs for mutable defaults and ``global`` statements."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            func_name = node.name

            # ── mutable default arguments ────────────────────────────
            for default in node.args.defaults + node.args.kw_defaults:
                if default is not None and _is_mutable_value(default):
                    end_line = getattr(default, "end_lineno", default.lineno) or default.lineno
                    snippet = f"def {func_name}(...={_value_repr(default)})"
                    rule_id = "GST_MUTABLE_DEFAULT_001"
                    findings.append(
                        Finding(
                            finding_id="",
                            type=AnalyzerType.GLOBAL_STATE,
                            severity=Severity.HIGH,
                            confidence=0.92,
                            message=(
                                "Mutable default arguments are shared between calls — "
                                "use None and create inside the function body instead."
                            ),
                            location=Location(
                                path=rel,
                                line_start=default.lineno,
                                line_end=end_line,
                            ),
                            fingerprint=make_fingerprint(rule_id, rel, func_name, snippet),
                            snippet=snippet,
                            metadata={"rule_id": rule_id},
                        )
                    )

            # ── global keyword ───────────────────────────────────────
            for child in ast.walk(node):
                if isinstance(child, ast.Global):
                    end_line = getattr(child, "end_lineno", child.lineno) or child.lineno
                    names_str = ", ".join(child.names)
                    snippet = f"global {names_str}"
                    rule_id = "GST_GLOBAL_KEYWORD_001"
                    findings.append(
                        Finding(
                            finding_id="",
                            type=AnalyzerType.GLOBAL_STATE,
                            severity=Severity.MEDIUM,
                            confidence=0.80,
                            message=(
                                "`global` introduces hidden coupling between function "
                                "and module scope — prefer passing values explicitly."
                            ),
                            location=Location(
                                path=rel,
                                line_start=child.lineno,
                                line_end=end_line,
                            ),
                            fingerprint=make_fingerprint(rule_id, rel, func_name, snippet),
                            snippet=snippet,
                            metadata={"rule_id": rule_id},
                        )
                    )


# ── helpers ──────────────────────────────────────────────────────────


def _target_name(node: ast.expr) -> str:
    """Best-effort name extraction from an assignment target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_target_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return f"{_target_name(node.value)}[...]"
    return "<unknown>"


def _value_repr(node: ast.expr) -> str:
    """Short human-readable representation of a mutable value node."""
    if isinstance(node, ast.List):
        return "[]"
    if isinstance(node, ast.Dict):
        return "{}"
    if isinstance(node, ast.Set):
        return "set()"
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return f"{func.id}()"
        if isinstance(func, ast.Attribute):
            return f"{func.attr}()"
    return "<mutable>"
