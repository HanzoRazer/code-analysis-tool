#!/usr/bin/env python3
"""Refresh tests/contracts/confidence_golden_manifest.json.

Combines dependency-closure hashing (AST-normalized, semantic-only)
with golden fixture hashing (bytes) under a confidence-specific
version anchor.

Usage:
    python scripts/refresh_confidence_golden_manifest.py

Override entrypoints via:
    CONFIDENCE_ENTRYPOINTS="src/code_audit/insights/confidence.py,..."
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "contracts" / "confidence_golden_manifest.json"
SRC_ROOT = ROOT / "src" / "code_audit"
CONFIDENCE_DIR = ROOT / "tests" / "fixtures" / "confidence"


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


# ── AST normalization (semantic-only hashing) ────────────────────────

_VERSION_ANCHORS = {"confidence_logic_version", "CONFIDENCE_POLICY_VERSION"}


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


class _GoldenTransformer(ast.NodeTransformer):
    """Strip docstrings and version anchor assignments for semantic hashing."""

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

    def visit_Assign(self, node: ast.Assign) -> ast.AST | None:
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in _VERSION_ANCHORS:
                return None
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST | None:
        if (
            isinstance(node.target, ast.Name)
            and node.target.id in _VERSION_ANCHORS
        ):
            return None
        return node


def _ast_hash(src: str) -> str:
    """AST-normalized hash: strips docstrings + version anchors."""
    tree = ast.parse(src)
    tree = _GoldenTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree, include_attributes=False)


def _sha256_bytes(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Version resolution (source parse, no imports) ────────────────────


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
    raise SystemExit("Could not locate signal_logic_version in run_result.py")


def _read_confidence_logic_version() -> str:
    p = ROOT / "src" / "code_audit" / "insights" / "confidence.py"
    txt = p.read_text(encoding="utf-8")
    m = re.search(r'\bconfidence_logic_version\s*=\s*["\']([^"\']+)["\']', txt)
    if not m:
        raise SystemExit(
            "Could not locate confidence_logic_version in "
            "src/code_audit/insights/confidence.py"
        )
    return m.group(1)


# ── Golden fixture discovery ─────────────────────────────────────────


def _discover_fixture_files() -> list[str]:
    """Discover confidence golden fixture files (cases.json + expected/*.json)."""
    files: list[str] = []
    cases = CONFIDENCE_DIR / "cases.json"
    expected_dir = CONFIDENCE_DIR / "expected"

    if not cases.exists():
        raise SystemExit(
            "Missing tests/fixtures/confidence/cases.json.\n"
            "Run: python scripts/refresh_golden_confidence.py"
        )
    files.append(str(cases.relative_to(ROOT)).replace("\\", "/"))

    if not expected_dir.exists():
        raise SystemExit(
            "Confidence golden contract incomplete:\n"
            "  cases.json exists but expected/ directory is missing.\n"
            "Run: python scripts/refresh_golden_confidence.py"
        )

    # Validate each expected file
    cases_data = json.loads(cases.read_bytes())
    case_names = [c["name"] for c in cases_data.get("cases", [])]
    if not case_names:
        raise SystemExit("cases.json contains no cases.")

    for name in case_names:
        ef = expected_dir / f"{name}.json"
        if not ef.exists():
            raise SystemExit(
                f"Missing expected file for case {name!r}:\n"
                f"  {ef.relative_to(ROOT)}\n"
                "Run: python scripts/refresh_golden_confidence.py"
            )
        payload = json.loads(ef.read_bytes())
        score = payload.get("expected_score")
        if score is None or not isinstance(score, int):
            raise SystemExit(
                f"Invalid expected_score in {ef.relative_to(ROOT)}.\n"
                "Run: python scripts/refresh_golden_confidence.py"
            )
        files.append(str(ef.relative_to(ROOT)).replace("\\", "/"))

    return sorted(files)


# ── Main ─────────────────────────────────────────────────────────────


def main() -> int:
    # Compute dependency closure
    closure_files = _closure(_entrypoints())

    # Discover golden fixture files
    fixture_rels = _discover_fixture_files()

    # Build file list: closure (AST hash) + fixtures (byte hash)
    closure_rels = [
        str(p.relative_to(ROOT)).replace("\\", "/") for p in closure_files
    ]

    all_rels = sorted(set(closure_rels + fixture_rels))

    hashes: dict[str, str] = {}
    hash_modes: dict[str, str] = {}

    for rel in all_rels:
        p = ROOT / rel
        if rel.endswith(".py"):
            # AST-normalized semantic hash
            src = p.read_text(encoding="utf-8")
            normalized = _ast_hash(src)
            h = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            hashes[rel] = h
            hash_modes[rel] = "ast"
        else:
            # Byte hash for JSON fixtures
            hashes[rel] = _sha256_bytes(p)
            hash_modes[rel] = "bytes"

    manifest = {
        "manifest_version": 1,
        "confidence_logic_version": _read_confidence_logic_version(),
        "signal_logic_version": _read_signal_logic_version(),
        "confidence_entrypoints": [
            str(p.relative_to(ROOT)).replace("\\", "/")
            for p in _entrypoints()
        ],
        "closure_files": closure_rels,
        "files": hashes,
        "hash_modes": hash_modes,
    }

    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote {MANIFEST.relative_to(ROOT)}")
    print(f"  confidence_logic_version: {manifest['confidence_logic_version']}")
    print(f"  signal_logic_version:     {manifest['signal_logic_version']}")
    print(f"  closure ({len(closure_rels)} files):")
    for r in closure_rels:
        print(f"    {r}  [{hash_modes[r]}]")
    print(f"  fixtures ({len(fixture_rels)} files):")
    for r in fixture_rels:
        print(f"    {r}  [{hash_modes[r]}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
