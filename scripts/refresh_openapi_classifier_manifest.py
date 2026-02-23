"""Refresh the OpenAPI classifier manifest file.

This script computes semantic (AST-based) hashes of the classifier
source files, resolves their internal import closure, derives the edge
graph, and writes the result to tests/contracts/openapi_classifier_manifest.json.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
MANIFEST_PATH = ROOT / "tests" / "contracts" / "openapi_classifier_manifest.json"

ENTRYPOINT_FILES = [
    ROOT / "src" / "code_audit" / "web_api" / "openapi_normalize.py",
    ROOT / "src" / "code_audit" / "web_api" / "openapi_diff.py",
    ROOT / "src" / "code_audit" / "web_api" / "schema_semver.py",
]

# Import from the existing AST semantic hash helper
sys.path.insert(0, str(ROOT / "scripts"))
from ast_semantic_hash import semantic_hash_python_like_file  # type: ignore


# --- Version anchor ----------------------------------------------------------

_VERSION_KEYS = {"openapi_classifier_version"}


class _StripDocstrings(ast.NodeTransformer):
    def visit_Expr(self, node: ast.Expr) -> Any:
        if isinstance(node.value, (ast.Constant,)) and isinstance(node.value.value, str):
            return None
        return self.generic_visit(node)


class _NeutralizeVersionLiterals(ast.NodeTransformer):
    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in _VERSION_KEYS:
                node.value = ast.Constant(value="__NEUTRALIZED__")
                return node
        return self.generic_visit(node)


# --- Import closure resolution -----------------------------------------------


def _module_to_candidate_paths(module: str, base: Path) -> List[Path]:
    parts = module.split(".")
    candidates = [
        SRC_ROOT / Path(*parts).with_suffix(".py"),
        SRC_ROOT / Path(*parts) / "__init__.py",
    ]
    return candidates


def _resolve_relative(module: str, level: int, base: Path) -> str | None:
    pkg = base.parent
    for _ in range(level - 1):
        pkg = pkg.parent
    rel = pkg.relative_to(SRC_ROOT)
    parts = list(rel.parts)
    if module:
        parts.append(module)
    return ".".join(parts)


def _collect_import_modules(path: Path) -> Set[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    modules: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                modules.add(node.module)
            elif node.level > 0:
                resolved = _resolve_relative(node.module or "", node.level, path)
                if resolved:
                    modules.add(resolved)
    return modules


def _resolve_internal_imports(path: Path) -> Set[Path]:
    modules = _collect_import_modules(path)
    found: Set[Path] = set()
    for mod in modules:
        for candidate in _module_to_candidate_paths(mod, path):
            if candidate.exists():
                found.add(candidate.resolve())
                break
    return found


def _compute_internal_closure(entrypoints: List[Path]) -> Tuple[List[Path], Dict[str, List[str]]]:
    """BFS over internal imports starting from entrypoints."""
    visited: Set[Path] = set()
    queue = list(entrypoints)
    edges: Dict[str, List[str]] = {}

    for ep in entrypoints:
        visited.add(ep.resolve())

    while queue:
        current = queue.pop(0)
        current_resolved = current.resolve()
        rel = str(current_resolved.relative_to(ROOT))
        imports = _resolve_internal_imports(current_resolved)
        edge_list = []
        for imp in sorted(imports, key=lambda p: str(p)):
            imp_rel = str(imp.relative_to(ROOT))
            edge_list.append(imp_rel)
            if imp not in visited:
                visited.add(imp)
                queue.append(imp)
        if edge_list:
            edges[rel] = edge_list

    return sorted(visited, key=lambda p: str(p.relative_to(ROOT))), edges


def _compute_internal_edges(closure_files: List[Path]) -> List[Tuple[str, str]]:
    """Return sorted unique directed edges (from_rel, to_rel)."""
    edge_set: Set[Tuple[str, str]] = set()
    for f in closure_files:
        f_resolved = f.resolve()
        f_rel = str(f_resolved.relative_to(ROOT))
        imports = _resolve_internal_imports(f_resolved)
        for imp in imports:
            imp_rel = str(imp.relative_to(ROOT))
            edge_set.add((f_rel, imp_rel))
    return sorted(edge_set)


def _hash_edges(edges: List[Tuple[str, str]]) -> str:
    canonical = json.dumps(edges, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def main() -> int:
    # Resolve closure
    closure_files, closure_graph = _compute_internal_closure(ENTRYPOINT_FILES)

    # Hash entrypoints
    file_entries: Dict[str, Dict[str, str]] = {}
    for ep in ENTRYPOINT_FILES:
        result = semantic_hash_python_like_file(ep)
        rel = str(ep.resolve().relative_to(ROOT))
        file_entries[rel] = {
            "sha256": result.sha256,
            "sha256_short": result.sha256[:12],
            "mode": result.mode,
        }

    # Hash closure files
    closure_entries: Dict[str, Dict[str, str]] = {}
    for f in closure_files:
        result = semantic_hash_python_like_file(f)
        rel = str(f.resolve().relative_to(ROOT))
        closure_entries[rel] = {
            "sha256": result.sha256,
            "sha256_short": result.sha256[:12],
            "mode": result.mode,
        }

    # Edge graph hash
    all_edges = _compute_internal_edges(closure_files)
    edge_graph_hash = _hash_edges(all_edges)

    manifest: Dict[str, Any] = {
        "version": 1,
        "entrypoints": [str(ep.resolve().relative_to(ROOT)) for ep in ENTRYPOINT_FILES],
        "files": file_entries,
        "closure_graph": {
            "files": closure_entries,
            "edge_graph_sha256": edge_graph_hash,
            "edge_graph_sha256_short": edge_graph_hash[:12],
        },
        "edges": {str(k): v for k, v in closure_graph.items()},
    }

    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"[refresh-classifier-manifest] Wrote {MANIFEST_PATH}")
    print(f"  entrypoints: {len(ENTRYPOINT_FILES)}")
    print(f"  closure files: {len(closure_files)}")
    print(f"  edge_graph_sha256_short: {edge_graph_hash[:12]}")
    for k, v in sorted(file_entries.items()):
        print(f"  {k}: {v['sha256_short']} ({v['mode']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
