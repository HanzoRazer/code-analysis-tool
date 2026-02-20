#!/usr/bin/env python3
"""Refresh tests/contracts/confidence_golden_manifest.json.

Confidence-specific golden contract gate with dependency-closure hashing.
Hashes the confidence golden fixtures AND the full dependency-closure of
the confidence scoring module (AST-normalized, semantic-only).

Override entrypoints via:
    CONFIDENCE_ENTRYPOINTS="src/code_audit/insights/confidence.py,..."

Usage:
    python scripts/refresh_confidence_golden_manifest.py
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

# Ensure repo root on sys.path for sibling script imports.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.toml_subset_hash import canonical_toml_subset_hash  # noqa: E402

ROOT = _ROOT
OUT = ROOT / "tests" / "contracts" / "confidence_golden_manifest.json"
SRC_ROOT = ROOT / "src" / "code_audit"

CONFIDENCE_DIR = ROOT / "tests" / "fixtures" / "confidence"

# Controlled pyproject semantic surface for confidence scoring.
# Only include keys that can affect runtime scoring semantics.
# Start narrow: a dedicated confidence section.
PYPROJECT_ALLOWED_PATHS: list[list[str]] = [
    ["tool", "code_audit", "confidence"],
]


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


def _path_to_module(p: Path) -> str:
    """Convert a resolved file path back to a dotted module name."""
    rel = p.relative_to(SRC_ROOT)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1].removesuffix(".py").removesuffix(".pyi")
    return "code_audit" + ("." + ".".join(parts) if parts else "")


def _resolve_from_import(
    module_file: Path, node: ast.ImportFrom
) -> list[tuple[str, Path]]:
    """Resolve a from-import node to a list of (module_name, path) pairs."""
    results: list[tuple[str, Path]] = []
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
        results.append((full_mod, p))

    for alias in node.names:
        if alias.name == "*":
            continue
        sub_mod = f"{full_mod}.{alias.name}"
        sp = _module_to_path(sub_mod)
        if sp:
            results.append((sub_mod, sp))

    return results


def _extract_internal_imports(
    module_file: Path, src: str
) -> list[tuple[str, Path]]:
    """Extract internal imports as (target_module_name, resolved_path) pairs."""
    tree = ast.parse(src)
    deps: list[tuple[str, Path]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _is_internal_module(a.name):
                    p = _module_to_path(a.name)
                    if p:
                        deps.append((a.name, p))
        elif isinstance(node, ast.ImportFrom):
            deps.extend(_resolve_from_import(module_file, node))
    # Deduplicate by path, keeping first module name seen per path
    seen: set[Path] = set()
    unique: list[tuple[str, Path]] = []
    for mod_name, p in sorted(deps, key=lambda x: x[1].as_posix()):
        if p not in seen:
            seen.add(p)
            unique.append((mod_name, p))
    return unique


# ── Dependency closure ───────────────────────────────────────────────


class _ClosureResult:
    """Result of dependency closure computation."""

    def __init__(
        self,
        files: list[Path],
        edges: list[tuple[str, str]],
    ) -> None:
        self.files = files
        self.edges = edges


def _closure(entrypoints: Iterable[Path]) -> _ClosureResult:
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
    edges: set[tuple[str, str]] = set()

    while stack:
        p = stack.pop(0)
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        src = p.read_text(encoding="utf-8")
        src_mod = _path_to_module(p)
        for dep_mod, dep_path in _extract_internal_imports(p, src):
            # Track graph edge even if dep already visited; structure matters.
            edges.add((src_mod, dep_mod))
            if dep_path not in seen and dep_path not in stack:
                stack.append(dep_path)
        stack.sort(key=lambda x: x.as_posix())

    return _ClosureResult(files=out, edges=sorted(edges))


# ── AST normalization ────────────────────────────────────────────────

# Version anchor names to strip from the AST so that bumping them
# doesn't look like a semantic logic change.
_VERSION_KEYS = {
    "confidence_logic_version",
    "signal_logic_version",
    "CONFIDENCE_POLICY_VERSION",
}


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


class _SemanticTransformer(ast.NodeTransformer):
    """Remove docstrings and version anchor assignments from AST."""

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
            if isinstance(t, ast.Name) and t.id in _VERSION_KEYS:
                return None
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST | None:
        if (
            isinstance(node.target, ast.Name)
            and node.target.id in _VERSION_KEYS
        ):
            return None
        return node


def _fallback_stub_semantic_hash(text: str) -> str:
    """Fallback normalizer for stubs when ast.parse fails."""
    lines = []
    for line in text.splitlines():
        if "#" in line:
            line = line.split("#", 1)[0]
        lines.append(line)
    s = "\n".join(lines)
    s = re.sub(r"\s+", " ", s).strip()
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _normalize_module_for_hash(src: str) -> str:
    tree = ast.parse(src)
    tree = _SemanticTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree, include_attributes=False)


def _is_python_like(rel: str) -> bool:
    return rel.endswith(".py") or rel.endswith(".pyi")


# ── Hash computation ─────────────────────────────────────────────────


def _sha256_bytes(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def _hash_closure_ast(closure_files: list[Path]) -> str:
    """AST-normalized hash over the full dependency closure."""
    parts: list[str] = []
    for p in closure_files:
        src = p.read_text(encoding="utf-8")
        parts.append(f"# {p.as_posix()}\n{_normalize_module_for_hash(src)}\n")
    canonical = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _sha256_canonical_json(obj: object) -> str:
    """Deterministic SHA-256 over a canonical JSON serialization."""
    blob = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ── Version anchors ──────────────────────────────────────────────────


def _read_signal_logic_version() -> str:
    candidates = [
        ROOT / "src" / "code_audit" / "model" / "run_result.py",
        ROOT / "src" / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = p.read_text(encoding="utf-8")
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)
    raise SystemExit("Could not locate signal_logic_version")


def _read_confidence_logic_version() -> str:
    target = ROOT / "src" / "code_audit" / "insights" / "confidence.py"
    s = target.read_text(encoding="utf-8")
    m = re.search(r'\bconfidence_logic_version\s*=\s*["\']([^"\']+)["\']', s)
    if not m:
        raise SystemExit("Could not locate confidence_logic_version in confidence.py")
    return m.group(1)


# ── Fixture integrity checks ────────────────────────────────────────


def _check_fixture_integrity() -> None:
    """Hard-fail if confidence golden fixtures are incomplete."""
    cases_path = CONFIDENCE_DIR / "cases.json"
    expected_dir = CONFIDENCE_DIR / "expected"

    if not cases_path.exists():
        return  # No confidence fixtures yet — nothing to enforce

    if not expected_dir.exists():
        raise SystemExit(
            "Confidence golden contract incomplete:\n"
            "  cases.json exists but expected/ directory is missing.\n"
            "Run: python scripts/refresh_golden_confidence.py\n"
        )

    cases_data = json.loads(cases_path.read_bytes())
    case_names = [c["name"] for c in cases_data.get("cases", [])]
    if not case_names:
        raise SystemExit(
            "cases.json contains no cases — cannot build golden contract.\n"
        )

    for name in case_names:
        ef = expected_dir / f"{name}.json"
        if not ef.exists():
            raise SystemExit(
                f"Missing expected file for case {name!r}:\n"
                f"  {ef.relative_to(ROOT)}\n"
                f"Run: python scripts/refresh_golden_confidence.py\n"
            )
        payload = json.loads(ef.read_bytes())
        score = payload.get("expected_score")
        if not isinstance(score, int):
            raise SystemExit(
                f"expected_score must be int in {ef.relative_to(ROOT)}, "
                f"got {type(score).__name__}\n"
                f"Run: python scripts/refresh_golden_confidence.py\n"
            )


# ── Collect fixture files ────────────────────────────────────────────


def _fixture_files() -> list[Path]:
    """Return sorted list of confidence fixture files to hash."""
    files: list[Path] = []
    cases_path = CONFIDENCE_DIR / "cases.json"
    expected_dir = CONFIDENCE_DIR / "expected"

    if cases_path.exists():
        files.append(cases_path)
    if expected_dir.exists():
        files.extend(sorted(expected_dir.glob("*.json")))
    return files


def _discover_pyi_files() -> list[Path]:
    """Return sorted list of all .pyi stub files under src/code_audit/."""
    return sorted(SRC_ROOT.rglob("*.pyi"))


# ── Main ─────────────────────────────────────────────────────────────


def main() -> int:
    _check_fixture_integrity()

    # Dependency closure (files + edges)
    closure = _closure(_entrypoints())
    closure_files = closure.files
    closure_edges = closure.edges

    # Collect all files to hash: closure (AST) + .pyi stubs + fixtures (bytes)
    fixture_files = _fixture_files()
    pyi_files = _discover_pyi_files()

    # Build per-file hashes
    file_hashes: dict[str, str] = {}
    hash_modes: dict[str, str] = {}

    for p in closure_files:
        rel = str(p.relative_to(ROOT)).replace("\\", "/")
        src = p.read_text(encoding="utf-8")
        norm = _normalize_module_for_hash(src)
        file_hashes[rel] = hashlib.sha256(
            f"# {p.as_posix()}\n{norm}\n".encode("utf-8")
        ).hexdigest()
        hash_modes[rel] = "ast"

    # Hash .pyi stubs — AST when possible, normalized-text fallback otherwise
    for p in pyi_files:
        rel = str(p.relative_to(ROOT)).replace("\\", "/")
        if rel in file_hashes:
            continue  # already in closure
        src = p.read_text(encoding="utf-8")
        try:
            norm = _normalize_module_for_hash(src)
            file_hashes[rel] = hashlib.sha256(
                f"# {p.as_posix()}\n{norm}\n".encode("utf-8")
            ).hexdigest()
            hash_modes[rel] = "ast"
        except SyntaxError:
            file_hashes[rel] = _fallback_stub_semantic_hash(src)
            hash_modes[rel] = "stub_norm"

    for p in fixture_files:
        rel = str(p.relative_to(ROOT)).replace("\\", "/")
        file_hashes[rel] = _sha256_bytes(p)
        hash_modes[rel] = "bytes"

    # Add derived pyproject subset hash as a synthetic manifest entry
    pyproject_path = ROOT / "pyproject.toml"
    pyproject_subset = None
    if pyproject_path.exists():
        py_h, pyproject_subset = canonical_toml_subset_hash(
            pyproject_path, PYPROJECT_ALLOWED_PATHS
        )
        synth_key = "pyproject.toml::confidence_scoring_keys_v1"
        file_hashes[synth_key] = py_h
        hash_modes[synth_key] = "toml_subset"

    # Composite hash over entire closure (AST-normalized)
    closure_hash = _hash_closure_ast(closure_files)

    # Canonical closure graph hash (edges)
    # Tracks import rewires even if closure node set stays identical.
    entrypoint_mods = [
        _path_to_module(p) for p in _entrypoints()
    ]
    closure_graph = {
        "version": 1,
        "entrypoints": entrypoint_mods,
        "edges": [list(e) for e in closure_edges],
    }
    closure_graph_sha256 = _sha256_canonical_json(closure_graph)

    manifest = {
        "manifest_version": 1,
        "confidence_logic_version": _read_confidence_logic_version(),
        "signal_logic_version": _read_signal_logic_version(),
        "closure_hash": closure_hash,
        "closure_files": [
            str(p.relative_to(ROOT)).replace("\\", "/") for p in closure_files
        ],
        "closure_edges": [list(e) for e in closure_edges],
        "closure_graph_sha256": closure_graph_sha256,
        "files": file_hashes,
        "hash_modes": hash_modes,
        "pyproject_subset": pyproject_subset,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote {OUT.relative_to(ROOT)}")
    print(f"  confidence_logic_version : {manifest['confidence_logic_version']}")
    print(f"  signal_logic_version     : {manifest['signal_logic_version']}")
    print(f"  closure_hash             : {closure_hash}")
    print(f"  closure_graph_sha256     : {closure_graph_sha256}")
    print(f"  closure ({len(closure_files)} files):")
    for p in closure_files:
        print(f"    {p.relative_to(ROOT)}")
    print(f"  closure edges ({len(closure_edges)}):")
    for src_mod, dst_mod in closure_edges:
        print(f"    {src_mod} -> {dst_mod}")
    print(f"  fixture files ({len(fixture_files)}):")
    for p in fixture_files:
        print(f"    {p.relative_to(ROOT)}")
    print(f"  .pyi stubs ({len(pyi_files)}):")
    for p in pyi_files:
        print(f"    {p.relative_to(ROOT)}")
    if pyproject_subset is not None:
        print(f"  pyproject subset: {json.dumps(pyproject_subset, indent=2)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
