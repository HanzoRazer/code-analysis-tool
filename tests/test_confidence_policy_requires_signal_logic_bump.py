"""Contract gate: confidence_score policy requires signal_logic_version bump.

Scope: dependency closure of confidence scoring entrypoints
Trigger: AST-level semantic change in any module reachable from the
         confidence entrypoint(s) via internal imports
Requirement: bump signal_logic_version + refresh manifest

Dependency-closure hashing:
  - Starts from entrypoint(s) (default: insights/confidence.py)
  - Recursively resolves all `code_audit.*` imports
  - AST-normalizes each module (strips docstrings + CONFIDENCE_POLICY_VERSION)
  - Hashes the closure deterministically

Override:
  CONFIDENCE_ENTRYPOINTS="src/code_audit/insights/confidence.py,..."
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable

import pytest

from code_audit.model.run_result import RunResult

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "contracts" / "confidence_policy_manifest.json"
SRC_ROOT = ROOT / "src" / "code_audit"


# ── CI enforcement ───────────────────────────────────────────────────


def _is_ci() -> bool:
    """GitHub Actions and many CI systems set CI=true."""
    v = os.environ.get("CI", "").strip()
    return v.lower() in {"1", "true", "yes", "on"}


def _require_entrypoints_in_ci() -> None:
    if _is_ci() and not os.environ.get("CONFIDENCE_ENTRYPOINTS", "").strip():
        raise AssertionError(
            "CI requires CONFIDENCE_ENTRYPOINTS to be set to avoid default "
            "entrypoint mode.\n"
            "Example:\n"
            "  CONFIDENCE_ENTRYPOINTS=src/code_audit/insights/confidence.py\n"
        )


# ── Entrypoint resolution ───────────────────────────────────────────


def _entrypoints() -> list[Path]:
    """Return confidence scoring entrypoints.

    Override via CONFIDENCE_ENTRYPOINTS (comma-separated repo-relative paths).
    In CI, CONFIDENCE_ENTRYPOINTS must be explicitly set.
    """
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
    """Resolve code_audit.foo.bar → src/code_audit/foo/bar.py or …/__init__.py."""
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
    """Resolve ``from ... import ...`` into internal module file paths."""
    results: list[Path] = []
    if node.level and node.level > 0:
        # Relative import — compute package from file position.
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
    """Build deterministic dependency closure over internal modules."""
    missing = [p for p in entrypoints if not p.exists()]
    assert not missing, (
        "Missing confidence entrypoint(s):\n  - "
        + "\n  - ".join(str(p) for p in missing)
        + "\nSet CONFIDENCE_ENTRYPOINTS to valid paths."
    )

    seen: set[Path] = set()
    stack: list[Path] = sorted(set(entrypoints), key=lambda p: p.as_posix())
    out: list[Path] = []

    while stack:
        p = stack.pop(0)  # BFS for stability
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
    """AST-normalize: strip docstrings + CONFIDENCE_POLICY_VERSION."""
    tree = ast.parse(src)
    tree = _PolicyTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree, include_attributes=False)


# ── Hash computation ─────────────────────────────────────────────────


def _hash_confidence_logic() -> str:
    """Compute canonical hash over the dependency closure."""
    files = _closure(_entrypoints())

    normalized_parts: list[str] = []
    for p in files:
        src = p.read_text(encoding="utf-8")
        normalized_parts.append(
            f"# {p.as_posix()}\n{_normalize_module_for_hash(src)}\n"
        )

    canonical = "\n".join(normalized_parts).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ── Test ─────────────────────────────────────────────────────────────


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
