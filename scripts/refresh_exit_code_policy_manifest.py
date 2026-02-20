#!/usr/bin/env python3
"""Refresh the exit-code policy manifest.

Hashes only the governed policy surface (AST-normalized):
  - ExitCodePolicy (dataclass)
  - DEFAULT_POLICY
  - _SEV_RANK
  - _normalize_severity
  - exit_code_for_worst_severity
  - worst_severity_from_counts

Usage:
    python scripts/refresh_exit_code_policy_manifest.py
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "contracts" / "exit_code_policy_manifest.json"
POLICY_FILE = ROOT / "src" / "code_audit" / "policy" / "exit_codes.py"


def _read_signal_logic_version() -> str:
    candidates = [
        ROOT / "src" / "code_audit" / "model" / "run_result.py",
        ROOT / "src" / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        txt = p.read_text(encoding="utf-8")
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", txt)
        if m:
            return m.group(1)
    raise SystemExit("Could not locate signal_logic_version in src/code_audit/model/run_result.py")


def _strip_docstrings(tree: ast.AST) -> ast.AST:
    """Remove docstrings from module/class/function bodies so they don't affect the hash."""

    class Strip(ast.NodeTransformer):
        def _strip_body(self, body: list) -> list:
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                return body[1:]
            return body

        def visit_Module(self, node: ast.Module) -> ast.Module:
            node.body = self._strip_body(node.body)
            self.generic_visit(node)
            return node

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
            node.body = self._strip_body(node.body)
            self.generic_visit(node)
            return node

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
            node.body = self._strip_body(node.body)
            self.generic_visit(node)
            return node

    tree = Strip().visit(tree)
    ast.fix_missing_locations(tree)
    return tree


_KEEP_NAMES = {
    "ExitCodePolicy",
    "DEFAULT_POLICY",
    "_SEV_RANK",
    "_normalize_severity",
    "exit_code_for_worst_severity",
    "worst_severity_from_counts",
}


def _semantic_hash_policy_surface(path: Path) -> str:
    """Hash only the semantic policy surface (AST-normalized, docstrings stripped)."""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    tree = _strip_docstrings(tree)

    kept: list[ast.stmt] = []
    for node in tree.body:  # type: ignore[attr-defined]
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in _KEEP_NAMES:
                    kept.append(node)
                    break
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in _KEEP_NAMES:
                kept.append(node)
        elif isinstance(node, ast.ClassDef):
            if node.name in _KEEP_NAMES:
                kept.append(node)

    surface = ast.Module(body=kept, type_ignores=[])
    dumped = ast.dump(surface, include_attributes=False, annotate_fields=True)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def main() -> int:
    if not POLICY_FILE.exists():
        raise SystemExit(f"Missing policy file: {POLICY_FILE}")

    manifest = {
        "manifest_version": 1,
        "signal_logic_version": _read_signal_logic_version(),
        "policy_file": str(POLICY_FILE.relative_to(ROOT).as_posix()),
        "policy_surface_sha256": _semantic_hash_policy_surface(POLICY_FILE),
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
