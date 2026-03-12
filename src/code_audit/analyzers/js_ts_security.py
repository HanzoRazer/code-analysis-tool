"""JS/TS Security Preview Analyzer.

Detects security-relevant patterns in JavaScript and TypeScript
files using tree-sitter AST queries.

Rules:
- SEC_EVAL_JS_001: eval() calls
- SEC_NEW_FUNCTION_JS_001: new Function() calls
- EXC_EMPTY_CATCH_JS_001: empty catch blocks
- GST_GLOBAL_THIS_MUTATION_001: globalThis/window mutations
- SEC_DYNAMIC_MODULE_LOAD_JS_001: require/import with non-literal argument
"""

from __future__ import annotations

import logging
from pathlib import Path

from code_audit.analyzers.treesitter_base import SourceFile, TreeSitterAnalyzerBase
from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_logger = logging.getLogger(__name__)

# globalThis/window objects that indicate global mutation
_GLOBAL_OBJECTS = frozenset({"globalThis", "window"})

# Node types that represent literal module specifiers (safe for require/import)
_LITERAL_NODE_TYPES = frozenset({"string", "string_fragment", "string_literal", "template_string"})


def _walk_tree(node, callback):
    """Depth-first walk of all nodes, calling callback(node)."""
    callback(node)
    for child in node.children:
        _walk_tree(child, callback)


class JsTsSecurityPreviewAnalyzer(TreeSitterAnalyzerBase):
    """Preview analyzer for JS/TS security patterns."""

    id = "js_ts_security"
    version = "0.1.0"
    languages = ("js", "ts", "tsx")

    def analyze_file(self, source_file: SourceFile, root: Path) -> list[Finding]:
        """Analyze a single JS/TS file for security issues."""
        findings: list[Finding] = []
        tree = source_file.tree

        try:
            rel_path = source_file.path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel_path = source_file.path.name

        def visit(node):
            # SEC_EVAL_JS_001: eval(...) calls
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn is not None and fn.type == "identifier":
                    fn_text = fn.text
                    if isinstance(fn_text, bytes):
                        fn_text = fn_text.decode("utf-8", errors="replace")
                    if fn_text == "eval":
                        line = node.start_point[0] + 1  # 0-indexed -> 1-indexed
                        end_line = node.end_point[0] + 1
                        snippet = self._extract_line(source_file.text, line)
                        findings.append(Finding(
                            finding_id=make_fingerprint(
                                "SEC_EVAL_JS_001", rel_path, "eval", snippet,
                            ),
                            type=AnalyzerType.JS_TS_SECURITY,
                            severity=Severity.HIGH,
                            confidence=0.95,
                            message="eval() is a security risk — allows arbitrary code execution.",
                            location=Location(path=rel_path, line_start=line, line_end=end_line),
                            fingerprint=make_fingerprint(
                                "SEC_EVAL_JS_001", rel_path, "eval", snippet,
                            ),
                            snippet=snippet,
                            metadata={"rule_id": "SEC_EVAL_JS_001", "language": source_file.language},
                        ))

            # SEC_NEW_FUNCTION_JS_001: new Function(...)
            if node.type == "new_expression":
                ctor = node.child_by_field_name("constructor")
                if ctor is not None and ctor.type == "identifier":
                    ctor_text = ctor.text
                    if isinstance(ctor_text, bytes):
                        ctor_text = ctor_text.decode("utf-8", errors="replace")
                    if ctor_text == "Function":
                        line = node.start_point[0] + 1
                        end_line = node.end_point[0] + 1
                        snippet = self._extract_line(source_file.text, line)
                        findings.append(Finding(
                            finding_id=make_fingerprint(
                                "SEC_NEW_FUNCTION_JS_001", rel_path, "Function", snippet,
                            ),
                            type=AnalyzerType.JS_TS_SECURITY,
                            severity=Severity.HIGH,
                            confidence=0.95,
                            message="new Function() is a security risk — equivalent to eval().",
                            location=Location(path=rel_path, line_start=line, line_end=end_line),
                            fingerprint=make_fingerprint(
                                "SEC_NEW_FUNCTION_JS_001", rel_path, "Function", snippet,
                            ),
                            snippet=snippet,
                            metadata={"rule_id": "SEC_NEW_FUNCTION_JS_001", "language": source_file.language},
                        ))

            # EXC_EMPTY_CATCH_JS_001: empty catch blocks
            if node.type == "catch_clause":
                body = node.child_by_field_name("body")
                if body is not None and body.type == "statement_block":
                    # Check if the block has only whitespace/no statements
                    named = [c for c in body.named_children if c.type != "comment"]
                    if len(named) == 0:
                        line = node.start_point[0] + 1
                        end_line = node.end_point[0] + 1
                        snippet = self._extract_line(source_file.text, line)
                        findings.append(Finding(
                            finding_id=make_fingerprint(
                                "EXC_EMPTY_CATCH_JS_001", rel_path, "catch", snippet,
                            ),
                            type=AnalyzerType.JS_TS_SECURITY,
                            severity=Severity.MEDIUM,
                            confidence=0.90,
                            message="Empty catch block — errors are silently swallowed.",
                            location=Location(path=rel_path, line_start=line, line_end=end_line),
                            fingerprint=make_fingerprint(
                                "EXC_EMPTY_CATCH_JS_001", rel_path, "catch", snippet,
                            ),
                            snippet=snippet,
                            metadata={"rule_id": "EXC_EMPTY_CATCH_JS_001", "language": source_file.language},
                        ))

            # GST_GLOBAL_THIS_MUTATION_001: globalThis.x = ... / window.x = ...
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                if left is not None and left.type == "member_expression":
                    obj = left.child_by_field_name("object")
                    if obj is not None and obj.type == "identifier":
                        obj_text = obj.text
                        if isinstance(obj_text, bytes):
                            obj_text = obj_text.decode("utf-8", errors="replace")
                        if obj_text in _GLOBAL_OBJECTS:
                            line = node.start_point[0] + 1
                            end_line = node.end_point[0] + 1
                            snippet = self._extract_line(source_file.text, line)
                            findings.append(Finding(
                                finding_id=make_fingerprint(
                                    "GST_GLOBAL_THIS_MUTATION_001", rel_path, obj_text, snippet,
                                ),
                                type=AnalyzerType.JS_TS_SECURITY,
                                severity=Severity.MEDIUM,
                                confidence=0.85,
                                message=f"{obj_text}.* mutation — pollutes global namespace.",
                                location=Location(path=rel_path, line_start=line, line_end=end_line),
                                fingerprint=make_fingerprint(
                                    "GST_GLOBAL_THIS_MUTATION_001", rel_path, obj_text, snippet,
                                ),
                                snippet=snippet,
                                metadata={"rule_id": "GST_GLOBAL_THIS_MUTATION_001", "language": source_file.language},
                            ))

            # SEC_DYNAMIC_MODULE_LOAD_JS_001: require(<non-literal>) / import(<non-literal>)
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn is not None and fn.type == "identifier":
                    fn_text = fn.text
                    if isinstance(fn_text, bytes):
                        fn_text = fn_text.decode("utf-8", errors="replace")
                    if fn_text in ("require", "import"):
                        args = node.child_by_field_name("arguments")
                        if args is not None:
                            # Get first named argument
                            named = [c for c in (getattr(args, "named_children", None) or [])]
                            if not named:
                                named = [c for c in (getattr(args, "children", None) or []) if getattr(c, "is_named", False)]
                            arg0 = named[0] if named else None
                            # If first argument is NOT a literal string, flag it
                            if arg0 is None or str(getattr(arg0, "type", "")) not in _LITERAL_NODE_TYPES:
                                line = node.start_point[0] + 1
                                end_line = node.end_point[0] + 1
                                snippet = self._extract_line(source_file.text, line)
                                findings.append(Finding(
                                    finding_id=make_fingerprint(
                                        "SEC_DYNAMIC_MODULE_LOAD_JS_001", rel_path, fn_text, snippet,
                                    ),
                                    type=AnalyzerType.JS_TS_SECURITY,
                                    severity=Severity.HIGH,
                                    confidence=0.90,
                                    message=f"Dynamic module load detected via {fn_text}(<non-literal>) (JS/TS).",
                                    location=Location(path=rel_path, line_start=line, line_end=end_line),
                                    fingerprint=make_fingerprint(
                                        "SEC_DYNAMIC_MODULE_LOAD_JS_001", rel_path, fn_text, snippet,
                                    ),
                                    snippet=snippet,
                                    metadata={"rule_id": "SEC_DYNAMIC_MODULE_LOAD_JS_001", "language": source_file.language},
                                ))

        _walk_tree(tree.root_node, visit)
        return findings

    @staticmethod
    def _extract_line(text: str, line_number: int) -> str:
        """Extract a single line from source text (1-indexed)."""
        lines = text.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1].strip()
        return ""
