"""Contract gate: confidence_score policy requires signal_logic_version bump.

Scope: semantic logic inside src/code_audit/insights/confidence.py
Trigger: AST-level semantic change (function bodies, thresholds, weights)
Requirement: bump signal_logic_version + refresh manifest

AST normalization:
  - Strips module and function docstrings
  - Strips CONFIDENCE_POLICY_VERSION assignment (bookkeeping only)
  - Hashes remaining AST dump
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from code_audit.model.run_result import RunResult

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "contracts" / "confidence_policy_manifest.json"

# Confidence module(s) — expand if logic spans multiple files.
CONFIDENCE_FILES = [
    ROOT / "src" / "code_audit" / "insights" / "confidence.py",
]


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    """Remove leading docstring from a body list."""
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


class _PolicyTransformer(ast.NodeTransformer):
    """Remove docstrings and CONFIDENCE_POLICY_VERSION from AST."""

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

    def visit_Assign(self, node: ast.Assign) -> ast.AST | None:
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id == "CONFIDENCE_POLICY_VERSION":
                return None
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST | None:
        if (
            isinstance(node.target, ast.Name)
            and node.target.id == "CONFIDENCE_POLICY_VERSION"
        ):
            return None
        return node


def _normalize_module_for_hash(src: str) -> str:
    """AST-normalize: strip docstrings + CONFIDENCE_POLICY_VERSION."""
    tree = ast.parse(src)
    tree = _PolicyTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree, include_attributes=False)


def _hash_confidence_logic() -> str:
    """Compute canonical hash across all confidence module(s)."""
    missing = [p for p in CONFIDENCE_FILES if not p.exists()]
    assert not missing, (
        "Missing confidence module(s):\n  - "
        + "\n  - ".join(str(p) for p in missing)
        + "\nUpdate CONFIDENCE_FILES in "
        "tests/test_confidence_policy_requires_signal_logic_bump.py"
    )

    parts: list[str] = []
    for p in CONFIDENCE_FILES:
        src = p.read_text(encoding="utf-8")
        parts.append(f"# {p.name}\n{_normalize_module_for_hash(src)}\n")

    canonical = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@pytest.mark.contract
def test_confidence_policy_requires_signal_logic_bump() -> None:
    """If confidence scoring logic changes, signal_logic_version must bump."""
    assert MANIFEST.exists(), (
        f"Missing manifest: {MANIFEST}.\n"
        "Run: python scripts/refresh_confidence_policy_manifest.py"
    )

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    prev_signal_logic = manifest["signal_logic_version"]
    prev_hash = manifest["confidence_policy_hash"]

    current_hash = _hash_confidence_logic()
    current_signal_logic = RunResult().signal_logic_version

    # Logic changed but signal version did not.
    if current_hash != prev_hash and current_signal_logic == prev_signal_logic:
        raise AssertionError(
            "confidence_score policy changed but signal_logic_version was not "
            "bumped.\n"
            f"  previous signal_logic_version: {prev_signal_logic}\n"
            f"  current  signal_logic_version: {current_signal_logic}\n"
            f"  manifest hash: {prev_hash}\n"
            f"  current  hash: {current_hash}\n"
            "\nRequired steps:\n"
            "  1) Bump signal_logic_version in "
            "src/code_audit/model/run_result.py\n"
            "  2) Refresh manifest: python "
            "scripts/refresh_confidence_policy_manifest.py\n"
        )

    # Signal version bumped or changes intended — manifest must be current.
    assert current_hash == prev_hash, (
        "confidence_policy_manifest.json is stale.\n"
        f"  manifest hash: {prev_hash}\n"
        f"  current  hash: {current_hash}\n"
        "Fix: python scripts/refresh_confidence_policy_manifest.py"
    )
