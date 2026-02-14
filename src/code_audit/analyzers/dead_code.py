"""Dead code analyzer — detects obviously unreachable code patterns.

v1 scope: high confidence, low false positives, single-file analysis.
Deferred: unused imports, unused functions/classes, unused locals (require cross-file analysis).
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint
from code_audit.rules import DC_UNREACHABLE_001, DC_IF_FALSE_001, DC_ASSERT_FALSE_001


# ── AST helpers ─────────────────────────────────────────────────────────


def _is_terminator(stmt: ast.stmt) -> bool:
    """Return True if stmt unconditionally exits the current block.

    Terminators: return, raise, break, continue.
    """
    if isinstance(stmt, (ast.Return, ast.Raise)):
        return True
    if isinstance(stmt, ast.Break):
        return True
    if isinstance(stmt, ast.Continue):
        return True
    return False


def _terminator_name(stmt: ast.stmt) -> str:
    """Return human-readable name of terminator."""
    if isinstance(stmt, ast.Return):
        return "return"
    if isinstance(stmt, ast.Raise):
        return "raise"
    if isinstance(stmt, ast.Break):
        return "break"
    if isinstance(stmt, ast.Continue):
        return "continue"
    return "terminator"


def _is_if_false(node: ast.If) -> bool:
    """Return True if condition is literal False."""
    if isinstance(node.test, ast.Constant):
        return node.test.value is False
    return False


def _is_while_false(node: ast.While) -> bool:
    """Return True if condition is literal False."""
    if isinstance(node.test, ast.Constant):
        return node.test.value is False
    return False


def _is_assert_false(node: ast.Assert) -> bool:
    """Return True if assertion is `assert False` or `assert 0`."""
    if isinstance(node.test, ast.Constant):
        # assert False or assert 0
        return node.test.value is False or node.test.value == 0
    return False


def _get_enclosing_function(tree: ast.AST, target: ast.AST) -> str:
    """Find the enclosing function name for a node, or '<module>'."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if child is target:
                    return node.name
    return "<module>"


def _stmt_repr(stmt: ast.stmt, max_len: int = 60) -> str:
    """Generate a short string representation of a statement."""
    if isinstance(stmt, ast.Return):
        return "return ..."
    if isinstance(stmt, ast.Raise):
        return "raise ..."
    if isinstance(stmt, ast.Expr):
        if isinstance(stmt.value, ast.Constant):
            val = repr(stmt.value.value)
            if len(val) > 20:
                val = val[:17] + "..."
            return val
        if isinstance(stmt.value, ast.Call):
            if isinstance(stmt.value.func, ast.Name):
                return f"{stmt.value.func.id}(...)"
            if isinstance(stmt.value.func, ast.Attribute):
                return f"....{stmt.value.func.attr}(...)"
    if isinstance(stmt, ast.Assign):
        return "... = ..."
    if isinstance(stmt, ast.If):
        return "if ...:"
    if isinstance(stmt, ast.For):
        return "for ...:"
    if isinstance(stmt, ast.While):
        return "while ...:"
    return "..."


# ── Analyzer class ──────────────────────────────────────────────────────


class DeadCodeAnalyzer:
    """Finds obviously unreachable code patterns.

    Rules:
      DC_UNREACHABLE_001: statements after return/raise/break/continue
      DC_IF_FALSE_001: if False: blocks
      DC_ASSERT_FALSE_001: assert False statements
    """

    id: str = "dead_code"
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

            # Detect unreachable code after terminators
            findings.extend(self._detect_unreachable(tree, rel, source))

            # Detect if False: blocks
            findings.extend(self._detect_if_false(tree, rel, source))

            # Detect assert False
            findings.extend(self._detect_assert_false(tree, rel, source))

        # Assign stable finding IDs (fingerprint-based)
        for i, f in enumerate(findings):
            object.__setattr__(f, "finding_id", f"dc_{f.fingerprint[7:15]}_{i:04d}")

        return findings

    def _detect_unreachable(
        self, tree: ast.AST, rel: str, source: str
    ) -> list[Finding]:
        """Detect statements after unconditional terminators."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            # Look for nodes with a body (functions, loops, if blocks, etc.)
            body: Optional[list[ast.stmt]] = None

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = node.body
            elif isinstance(node, ast.If):
                body = node.body
                # Also check else branch
                if node.orelse:
                    findings.extend(
                        self._check_body_for_unreachable(
                            node.orelse, tree, rel, source
                        )
                    )
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                body = node.body
            elif isinstance(node, ast.With):
                body = node.body
            elif isinstance(node, ast.Try):
                body = node.body
                # Check handlers, else, finally
                for handler in node.handlers:
                    findings.extend(
                        self._check_body_for_unreachable(
                            handler.body, tree, rel, source
                        )
                    )
                if node.orelse:
                    findings.extend(
                        self._check_body_for_unreachable(
                            node.orelse, tree, rel, source
                        )
                    )
                if node.finalbody:
                    findings.extend(
                        self._check_body_for_unreachable(
                            node.finalbody, tree, rel, source
                        )
                    )
            elif isinstance(node, ast.Module):
                body = node.body

            if body:
                findings.extend(
                    self._check_body_for_unreachable(body, tree, rel, source)
                )

        return findings

    def _check_body_for_unreachable(
        self,
        body: list[ast.stmt],
        tree: ast.AST,
        rel: str,
        source: str,
    ) -> list[Finding]:
        """Check a body for statements after a terminator."""
        findings: list[Finding] = []

        for i, stmt in enumerate(body):
            if _is_terminator(stmt) and i + 1 < len(body):
                # There are statements after this terminator
                unreachable_stmts = body[i + 1 :]
                first_unreachable = unreachable_stmts[0]
                last_unreachable = unreachable_stmts[-1]

                line_start = first_unreachable.lineno
                line_end = getattr(last_unreachable, "end_lineno", line_start) or line_start

                terminator = _terminator_name(stmt)
                symbol = _get_enclosing_function(tree, stmt)
                count = len(unreachable_stmts)

                snippet_parts = [f"# {count} unreachable statement(s) after {terminator}"]
                for us in unreachable_stmts[:3]:
                    snippet_parts.append(f"  {_stmt_repr(us)}")
                if count > 3:
                    snippet_parts.append(f"  # ... and {count - 3} more")
                snippet = "\n".join(snippet_parts)

                findings.append(
                    Finding(
                        finding_id="",  # filled later
                        type=AnalyzerType.DEAD_CODE,
                        severity=Severity.HIGH,
                        confidence=0.98,
                        message=f"{count} statement(s) after '{terminator}' will never execute",
                        location=Location(
                            path=rel, line_start=line_start, line_end=line_end
                        ),
                        fingerprint=make_fingerprint(
                            DC_UNREACHABLE_001, rel, symbol, snippet
                        ),
                        snippet=snippet,
                        metadata={
                            "rule_id": DC_UNREACHABLE_001,
                            "terminator": terminator,
                            "unreachable_count": count,
                            "context": symbol,
                        },
                    )
                )
                # Only report once per body (the first terminator)
                break

        return findings

    def _detect_if_false(
        self, tree: ast.AST, rel: str, source: str
    ) -> list[Finding]:
        """Detect `if False:` and `while False:` blocks."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.If) and _is_if_false(node):
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(tree, node)

                body_count = len(node.body)
                snippet = f"if False:  # {body_count} statement(s) never execute"

                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.DEAD_CODE,
                        severity=Severity.HIGH,
                        confidence=0.95,
                        message=f"'if False:' block contains {body_count} statement(s) that will never execute",
                        location=Location(
                            path=rel, line_start=line_start, line_end=line_end
                        ),
                        fingerprint=make_fingerprint(
                            DC_IF_FALSE_001, rel, symbol, snippet
                        ),
                        snippet=snippet,
                        metadata={
                            "rule_id": DC_IF_FALSE_001,
                            "block_type": "if",
                            "dead_statement_count": body_count,
                            "context": symbol,
                        },
                    )
                )

            elif isinstance(node, ast.While) and _is_while_false(node):
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(tree, node)

                body_count = len(node.body)
                snippet = f"while False:  # {body_count} statement(s) never execute"

                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.DEAD_CODE,
                        severity=Severity.HIGH,
                        confidence=0.95,
                        message=f"'while False:' block contains {body_count} statement(s) that will never execute",
                        location=Location(
                            path=rel, line_start=line_start, line_end=line_end
                        ),
                        fingerprint=make_fingerprint(
                            DC_IF_FALSE_001, rel, symbol, snippet
                        ),
                        snippet=snippet,
                        metadata={
                            "rule_id": DC_IF_FALSE_001,
                            "block_type": "while",
                            "dead_statement_count": body_count,
                            "context": symbol,
                        },
                    )
                )

        return findings

    def _detect_assert_false(
        self, tree: ast.AST, rel: str, source: str
    ) -> list[Finding]:
        """Detect `assert False` patterns."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assert) and _is_assert_false(node):
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(tree, node)

                snippet = "assert False  # always fails"

                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.DEAD_CODE,
                        severity=Severity.MEDIUM,
                        confidence=0.90,
                        message="'assert False' will always fail when reached",
                        location=Location(
                            path=rel, line_start=line_start, line_end=line_end
                        ),
                        fingerprint=make_fingerprint(
                            DC_ASSERT_FALSE_001, rel, symbol, snippet
                        ),
                        snippet=snippet,
                        metadata={
                            "rule_id": DC_ASSERT_FALSE_001,
                            "context": symbol,
                        },
                    )
                )

        return findings


# ── functional entrypoint (schema-shaped dicts for legacy pipeline) ──


def _posix_relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return path.as_posix()


def _truncate(s: str, max_len: int = 200) -> str:
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def analyze_dead_code(path: Path, *, root: Path) -> List[Dict[str, Any]]:
    """Functional analyzer: schema-shaped finding dicts.

    Mirrors ``analyze_exceptions`` in structure. Used by the legacy
    ``run_result.build_run_result()`` pipeline.
    """
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []

    rel = _posix_relpath(path, root)
    lines = src.replace("\r\n", "\n").split("\n")
    findings: List[Dict[str, Any]] = []

    def _emit(
        rule_id: str,
        node: ast.AST,
        *,
        severity: str,
        confidence: float,
        message: str,
    ) -> None:
        line_start = int(getattr(node, "lineno", 1) or 1)
        line_end = int(getattr(node, "end_lineno", line_start) or line_start)
        snippet = ""
        if 1 <= line_start <= len(lines):
            start = max(1, line_start - 1)
            end = min(len(lines), line_end + 1)
            snippet = "\n".join(lines[start - 1 : end])
        snippet = _truncate(snippet)
        fp_src = f"{rule_id}|{rel}|{line_start}|{line_end}|{message}"
        fp_hex = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()
        findings.append(
            {
                "finding_id": "f_" + fp_hex[:16],
                "type": "dead_code",
                "severity": severity,
                "confidence": confidence,
                "message": message,
                "location": {
                    "path": rel,
                    "line_start": line_start,
                    "line_end": line_end,
                },
                "fingerprint": "sha256:" + fp_hex,
                "snippet": snippet,
                "metadata": {"rule_id": rule_id},
            }
        )

    # DC_IF_FALSE_001
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _is_if_false(node):
            _emit(
                DC_IF_FALSE_001,
                node,
                severity="high",
                confidence=0.95,
                message="Dead branch: block is guarded by constant False",
            )
        elif isinstance(node, ast.While) and _is_while_false(node):
            _emit(
                DC_IF_FALSE_001,
                node,
                severity="high",
                confidence=0.95,
                message="Dead branch: block is guarded by constant False",
            )

    # DC_UNREACHABLE_001 — statements after terminators
    for node in ast.walk(tree):
        body: Optional[list] = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
        elif isinstance(node, ast.If):
            body = node.body
            if node.orelse:
                _scan_body_functional(node.orelse, rel, lines, findings)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            body = node.body
        elif isinstance(node, ast.With):
            body = node.body
        elif isinstance(node, ast.Try):
            body = node.body
            for handler in node.handlers:
                _scan_body_functional(handler.body, rel, lines, findings)
            if node.orelse:
                _scan_body_functional(node.orelse, rel, lines, findings)
            if node.finalbody:
                _scan_body_functional(node.finalbody, rel, lines, findings)
        elif isinstance(node, ast.Module):
            body = node.body

        if body:
            _scan_body_functional(body, rel, lines, findings)

    # DC_ASSERT_FALSE_001
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert) and _is_assert_false(node):
            _emit(
                DC_ASSERT_FALSE_001,
                node,
                severity="medium",
                confidence=0.90,
                message="'assert False' will always fail when reached",
            )

    return findings


def _scan_body_functional(
    body: list,
    rel: str,
    lines: list[str],
    findings: List[Dict[str, Any]],
) -> None:
    """Check a body for statements after a terminator (functional pipeline)."""
    for i, stmt in enumerate(body):
        if _is_terminator(stmt) and i + 1 < len(body):
            first_unreachable = body[i + 1]
            last_unreachable = body[-1]
            line_start = int(getattr(first_unreachable, "lineno", 1) or 1)
            line_end = int(
                getattr(last_unreachable, "end_lineno", line_start) or line_start
            )
            snippet = ""
            if 1 <= line_start <= len(lines):
                start = max(1, line_start - 1)
                end = min(len(lines), line_end + 1)
                snippet = "\n".join(lines[start - 1 : end])
            snippet = _truncate(snippet)
            count = len(body) - i - 1
            fp_src = (
                f"DC_UNREACHABLE_001|{rel}|{line_start}|{line_end}"
                f"|{count} statement(s) unreachable"
            )
            fp_hex = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()
            findings.append(
                {
                    "finding_id": "f_" + fp_hex[:16],
                    "type": "dead_code",
                    "severity": "high",
                    "confidence": 0.98,
                    "message": f"{count} statement(s) after terminator will never execute",
                    "location": {
                        "path": rel,
                        "line_start": line_start,
                        "line_end": line_end,
                    },
                    "fingerprint": "sha256:" + fp_hex,
                    "snippet": snippet,
                    "metadata": {
                        "rule_id": DC_UNREACHABLE_001,
                        "terminator": _terminator_name(stmt),
                        "unreachable_count": count,
                    },
                }
            )
            break
