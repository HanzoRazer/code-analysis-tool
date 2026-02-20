#!/usr/bin/env python3
"""Semantic AST hashing for Python and Python stub (.pyi) files.

Provides deterministic, formatting-insensitive hashing:
  - .py  → AST semantic hash (strips docstrings + version literal assignments)
  - .pyi → AST semantic hash when possible; normalized-text fallback on SyntaxError

Used by confidence manifest refresh and contract gate tests.
"""
from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SemanticHashResult:
    """Result of a semantic hash computation."""

    sha256: str
    mode: str  # "ast" | "stub_norm"


# ── Version anchor names stripped from AST ───────────────────────────
# Bumping these literals is not a semantic logic change; stripping them
# avoids false-positive drift in contract manifests.

_VERSION_KEYS = {
    "version",
    "engine_version",
    "signal_logic_version",
    "confidence_logic_version",
    "CONFIDENCE_POLICY_VERSION",
}


# ── AST transformers ─────────────────────────────────────────────────


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    """Remove a leading docstring from a body list (module / class / function)."""
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


class _DocstringStripper(ast.NodeTransformer):
    """Remove docstrings from all scopes so formatting/doc changes don't hash."""

    def visit_Module(self, node: ast.Module) -> ast.AST:
        node.body = _strip_docstring(node.body)
        node.body = [
            s for s in (self.visit(stmt) for stmt in node.body) if s is not None
        ]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.body = _strip_docstring(node.body)
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.body = _strip_docstring(node.body)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.body = _strip_docstring(node.body)
        self.generic_visit(node)
        return node


class _VersionLiteralStripper(ast.NodeTransformer):
    """Strip assignments to known version anchor names.

    This ensures that bumping a version literal (e.g. ``version = "1.1.0"``)
    does not appear as a semantic logic change — that is the expected action
    *after* a real logic change.
    """

    def visit_Assign(self, node: ast.Assign) -> ast.AST | None:
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in _VERSION_KEYS:
                return None
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST | None:
        if isinstance(node.target, ast.Name) and node.target.id in _VERSION_KEYS:
            return None
        return node


# ── Fallback normalizer for stubs ────────────────────────────────────


def _fallback_stub_semantic_hash(text: str) -> str:
    """Fallback normalizer for stubs when ast.parse fails.

    - Remove comments
    - Collapse whitespace
    - Keep a stable representation that's resistant to formatting-only edits
    """
    # Remove inline comments
    lines = []
    for line in text.splitlines():
        # Strip everything after #
        if "#" in line:
            line = line.split("#", 1)[0]
        lines.append(line)
    s = "\n".join(lines)
    # Collapse whitespace (including newlines) to single spaces
    s = re.sub(r"\s+", " ", s).strip()
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ── Public API ───────────────────────────────────────────────────────


def semantic_hash_python_like_file(path: Path) -> SemanticHashResult:
    """Compute a semantic hash of a Python-like module (.py or .pyi).

    - strips docstrings
    - strips version literal assignment RHS for known version keys
    - ignores formatting/comments entirely (AST doesn't include them)

    For .pyi where parsing fails, falls back to a normalized-text semantic hash.
    """
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src)
        tree = _DocstringStripper().visit(tree)
        tree = _VersionLiteralStripper().visit(tree)
        ast.fix_missing_locations(tree)

        dumped = ast.dump(tree, include_attributes=False, annotate_fields=True)
        h = hashlib.sha256(dumped.encode("utf-8")).hexdigest()
        return SemanticHashResult(sha256=h, mode="ast")
    except SyntaxError:
        # Stubs sometimes contain grammar edge cases; keep the contract guarded anyway.
        return SemanticHashResult(sha256=_fallback_stub_semantic_hash(src), mode="stub_norm")


def is_python_file(rel_path: str) -> bool:
    """Check if a relative path is a Python or Python stub file."""
    return rel_path.endswith(".py") or rel_path.endswith(".pyi")
