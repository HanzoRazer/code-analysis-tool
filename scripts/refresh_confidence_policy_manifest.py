#!/usr/bin/env python3
"""Refresh tests/contracts/confidence_policy_manifest.json.

Uses dependency-closure hashing: starts from the confidence scoring
entrypoint(s) and recursively resolves all internal ``code_audit.*``
imports, producing a deterministic hash over the full closure.

Override entrypoints via:
    CONFIDENCE_ENTRYPOINTS="src/code_audit/insights/confidence.py,..."

Usage:
    python scripts/refresh_confidence_policy_manifest.py
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "contracts" / "confidence_policy_manifest.json"
SRC_ROOT = ROOT / "src" / "code_audit"


# ── CI enforcement ───────────────────────────────────────────────────


def _is_ci() -> bool:
    v = os.environ.get("CI", "").strip()
    return v.lower() in {"1", "true", "yes", "on"}


def _require_entrypoints_in_ci() -> None:
    if _is_ci() and not os.environ.get("CONFIDENCE_ENTRYPOINTS", "").strip():
        raise SystemExit(
            "CI requires CONFIDENCE_ENTRYPOINTS to be set "
            "(no default entrypoint mode)."
        )


# ── Entrypoint resolution ───────────────────────────────────────────


def _entrypoints() -> list[Path]:
    _require_entrypoints_in_ci()
    override = os.environ.get("CONFIDENCE_ENTRYPOINTS", "").strip()
    if override:
        eps = [ROOT / p.strip() for p in override.split(",") if p.strip()]
        return sorted(eps, key=lambda p: p.as_posix())
    return [SRC_ROOT / "insights" / "confidence.py"]


# ── Import resolution helpers ────────────────────────────────────────


def _is_internal_module(mod: str) -> bool:
    return mod == "code_audit" or mod.startswith("code_audit.")


def _module_to_path(mod: str) -> Path | None:
    if not _is_internal_module(mod):
        return None
    rel = mod.split(".", 1)[1] if mod != "code_audit" else ""
    base = SRC_ROOT / Path(*([p for p in rel.split(".") if p] or []))
    file_py = base.with_suffix(".py")
    pkg_init = base / "__init__.py"
    if file_py.exists():
        return file_py
    if pkg_init.exists():
        return pkg_init
    return None


def _resolve_from_import(module_file: Path, node: ast.ImportFrom) -> list[Path]:
    results: list[Path] = []
    if node.level and node.level > 0:
        rel_parts = module_file.relative_to(SRC_ROOT).parts
        pkg_parts = (
            rel_parts[:-1] if rel_parts[-1] != "__init__.py" else rel_parts[:-1]
        )
        up = node.level - 1
        base_parts = pkg_parts[:-up] if up and up <= len(pkg_parts) else pkg_parts
        base_mod = "code_audit" + (
            ("." + ".".join(base_parts)) if base_parts else ""
        )
        full_mod = base_mod + ("." + node.module if node.module else "")
    else:
        full_mod = node.module or ""

    if not full_mod:
        return results

    p = _module_to_path(full_mod)
    if p:
        results.append(p)

    for alias in node.names:
        if alias.name == "*":
            continue
        sp = _module_to_path(f"{full_mod}.{alias.name}")
        if sp:
            results.append(sp)

    return results


def _extract_internal_imports(module_file: Path, src: str) -> list[Path]:
    tree = ast.parse(src)
    deps: list[Path] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _is_internal_module(a.name):
                    p = _module_to_path(a.name)
                    if p:
                        deps.append(p)
        elif isinstance(node, ast.ImportFrom):
            deps.extend(_resolve_from_import(module_file, node))
    return sorted(set(deps), key=lambda p: p.as_posix())


# ── Dependency closure ───────────────────────────────────────────────


def _closure(entrypoints: Iterable[Path]) -> list[Path]:
    missing = [p for p in entrypoints if not p.exists()]
    if missing:
        raise SystemExit(
            "Missing confidence entrypoint(s):\n  - "
            + "\n  - ".join(str(p) for p in missing)
            + "\nSet CONFIDENCE_ENTRYPOINTS to valid paths."
        )

    seen: set[Path] = set()
    stack: list[Path] = sorted(set(entrypoints), key=lambda p: p.as_posix())
    out: list[Path] = []

    while stack:
        p = stack.pop(0)
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        src = p.read_text(encoding="utf-8")
        for d in _extract_internal_imports(p, src):
            if d not in seen and d not in stack:
                stack.append(d)
        stack.sort(key=lambda x: x.as_posix())

    return out


# ── AST normalization ────────────────────────────────────────────────


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

    _VERSION_ANCHORS = {"CONFIDENCE_POLICY_VERSION", "confidence_logic_version"}

    def visit_Assign(self, node: ast.Assign) -> ast.AST | None:
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in self._VERSION_ANCHORS:
                return None
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST | None:
        if (
            isinstance(node.target, ast.Name)
            and node.target.id in self._VERSION_ANCHORS
        ):
            return None
        return node


def _normalize_module_for_hash(src: str) -> str:
    tree = ast.parse(src)
    tree = _PolicyTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree, include_attributes=False)


# ── Hash computation ─────────────────────────────────────────────────


def _hash_confidence_logic() -> str:
    files = _closure(_entrypoints())

    parts: list[str] = []
    for p in files:
        src = p.read_text(encoding="utf-8")
        parts.append(f"# {p.as_posix()}\n{_normalize_module_for_hash(src)}\n")

    canonical = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ── Main ─────────────────────────────────────────────────────────────


def main() -> int:
    from code_audit.model.run_result import RunResult

    files = _closure(_entrypoints())
    current_version = RunResult().signal_logic_version

    payload = {
        "confidence_policy_hash": _hash_confidence_logic(),
        "discovery": {
            "mode": "dependency_closure_internal_imports",
            "override_env": "CONFIDENCE_ENTRYPOINTS",
            "root": "src/code_audit",
        },
        "hash_scope": "ast_normalized_dependency_closure_no_docstrings_no_CONFIDENCE_POLICY_VERSION",
        "paths": [
            str(p.relative_to(ROOT)).replace("\\", "/") for p in files
        ],
        "signal_logic_version": current_version,
    }

    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"✓ Wrote {MANIFEST.relative_to(ROOT)}")
    print(f"  confidence_policy_hash : {payload['confidence_policy_hash']}")
    print(f"  signal_logic_version   : {current_version}")
    print(f"  closure ({len(files)} files):")
    for p in files:
        print(f"    {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
