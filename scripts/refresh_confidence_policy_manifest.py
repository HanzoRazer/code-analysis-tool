#!/usr/bin/env python3
"""Refresh tests/contracts/confidence_policy_manifest.json.

Run whenever confidence scoring logic changes *and* you have already
bumped signal_logic_version in src/code_audit/model/run_result.py.

Usage:
    python scripts/refresh_confidence_policy_manifest.py
"""
from __future__ import annotations

import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "contracts" / "confidence_policy_manifest.json"

CONFIDENCE_FILES = [
    ROOT / "src" / "code_audit" / "insights" / "confidence.py",
]


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


class _PolicyTransformer(ast.NodeTransformer):
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
    tree = ast.parse(src)
    tree = _PolicyTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree, include_attributes=False)


def _hash_confidence_logic() -> str:
    parts: list[str] = []
    for p in CONFIDENCE_FILES:
        src = p.read_text(encoding="utf-8")
        parts.append(f"# {p.name}\n{_normalize_module_for_hash(src)}\n")
    canonical = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def main() -> None:
    from code_audit.model.run_result import RunResult

    current_hash = _hash_confidence_logic()
    current_version = RunResult().signal_logic_version

    payload = {
        "confidence_policy_hash": current_hash,
        "signal_logic_version": current_version,
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
    }

    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    print(f"✓ Wrote {MANIFEST.relative_to(ROOT)}")
    print(f"  confidence_policy_hash : {current_hash}")
    print(f"  signal_logic_version   : {current_version}")


if __name__ == "__main__":
    main()
