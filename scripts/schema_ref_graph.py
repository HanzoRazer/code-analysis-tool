"""Schema $ref graph traversal, edge building, and closure computation.

Single source of truth for:
- Local $ref resolution policy (reject remote, reject fragment-only)
- Schema graph traversal (BFS)
- Edge discovery with dual-kind + trace
- Closure file computation
- dist schema graph record building
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

from scripts.schema_ref_kind import (
    canonicalize_ref_edges,
    collect_ref_targets_with_trace,
    ref_edges_sha256,
)


@dataclass(frozen=True)
class SchemaGraphEdge:
    from_path: Path
    to_path: Path
    kind_structural: str
    kind_semantic: str
    kind_trace_compact: Tuple[str, ...]
    kind_trace_sha256_short: str


def _is_remote_ref(ref: str) -> bool:
    pr = urlparse(ref)
    return pr.scheme in ("http", "https")


def resolve_local_ref(ref: str, base_file: Path) -> Path:
    """Resolve a local $ref into an absolute file path.

    - Rejects http/https refs (policy: shipped schemas must be self-contained).
    - Ignores JSON pointer fragments (#/...) for closure/edges.
    - Rejects fragment-only refs (e.g., "#/$defs/X") because there is no file edge.
    """
    if _is_remote_ref(ref):
        raise RuntimeError(f"Remote $ref is not allowed in shipped schemas: {ref}")
    ref_path = ref.split("#", 1)[0]
    if not ref_path:
        # Fragment-only ref (e.g., "#/$defs/X") — no file dependency edge.
        raise RuntimeError(f"Unsupported $ref (fragment-only): {ref}")
    return (base_file.parent / ref_path).resolve()


def load_schema_json(path: Path) -> dict:
    """Load and parse a JSON schema file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(f"Failed to load schema JSON: {path}") from e


def _sha256_canonical_json_obj(obj: Any) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def _canonical_sha256_json_file(path: Path) -> str:
    obj = load_schema_json(path)
    return _sha256_canonical_json_obj(obj)


def schema_ref_graph_edges(top_schema_file: Path) -> List[SchemaGraphEdge]:
    """Recursively traverse local $ref and return all discovered edges with dual-kind + trace.

    Fragment-only refs (e.g., #/$defs/X) are silently skipped (no file-level edge).
    Deterministic output: sorted by (from,to,kind_structural,kind_semantic,trace,trace_short).
    """
    top = top_schema_file.resolve()
    seen_files: Set[Path] = set()
    q: List[Path] = [top]
    edges: Set[SchemaGraphEdge] = set()

    while q:
        cur = q.pop(0)
        cur = cur.resolve()
        if cur in seen_files:
            continue
        seen_files.add(cur)

        obj = load_schema_json(cur)
        ref_items = collect_ref_targets_with_trace(obj)
        for ref, ks, km, trace, sha12 in ref_items:
            try:
                dep = resolve_local_ref(ref, cur)
            except RuntimeError:
                # Skip fragment-only or unsupported refs — no file-level edge
                continue
            if dep == cur:
                continue
            e = SchemaGraphEdge(
                from_path=cur,
                to_path=dep,
                kind_structural=ks,
                kind_semantic=km,
                kind_trace_compact=tuple(trace),
                kind_trace_sha256_short=sha12,
            )
            edges.add(e)
            if dep not in seen_files:
                q.append(dep)

    return sorted(
        edges,
        key=lambda e: (
            str(e.from_path),
            str(e.to_path),
            e.kind_structural,
            e.kind_semantic,
            list(e.kind_trace_compact),
            e.kind_trace_sha256_short,
        ),
    )


def schema_ref_closure_files(top_schema_file: Path) -> List[Path]:
    """Return sorted unique set of referenced schema files excluding the top schema itself."""
    top = top_schema_file.resolve()
    edges = schema_ref_graph_edges(top)
    deps: Set[Path] = set()
    for e in edges:
        if e.to_path.resolve() != top:
            deps.add(e.to_path.resolve())
    return sorted(deps, key=lambda p: str(p))


def build_dist_schema_graph_records(
    *,
    root: Path,
    top_dist_schema: Path,
) -> Dict[str, Any]:
    """Build closure + edge records for a dist schema file.

    The result is ready to be embedded into a Release BOM schema artifact entry.

    Returns:
        {
            "ref_closure": [{path, canonical_sha256, canonical_sha256_short}, ...],
            "ref_closure_sha256": "...",
            "ref_edges": [{from,to,kind_structural,kind_semantic,kind_trace_compact,kind_trace_sha256_short}, ...],
            "ref_edges_sha256": "...",
            "counts": {"closure_files": N, "edges": M}
        }
    """
    root = root.resolve()
    top = top_dist_schema.resolve()

    # Closure files (dist paths)
    closure_files = schema_ref_closure_files(top)
    closure_files = [p.resolve() for p in closure_files]

    # Closure records: path + canonical hash
    ref_closure: List[Dict[str, Any]] = []
    for p in sorted(closure_files, key=lambda x: str(x)):
        h = _canonical_sha256_json_file(p)
        ref_closure.append({
            "path": str(p.relative_to(root)).replace("\\", "/"),
            "canonical_sha256": h,
            "canonical_sha256_short": h[:12],
        })

    ref_closure_sha256 = _sha256_canonical_json_obj(ref_closure)

    # Edges (dist->dist)
    graph_edges = schema_ref_graph_edges(top)
    ref_edges_list: List[Dict[str, Any]] = []
    for e in graph_edges:
        fp = e.from_path.resolve()
        tp = e.to_path.resolve()
        ref_edges_list.append({
            "from": str(fp.relative_to(root)).replace("\\", "/"),
            "to": str(tp.relative_to(root)).replace("\\", "/"),
            "kind_structural": e.kind_structural,
            "kind_semantic": e.kind_semantic,
            "kind_trace_compact": list(e.kind_trace_compact),
            "kind_trace_sha256_short": e.kind_trace_sha256_short,
        })

    # Canonicalize + hash edges
    ref_edges_list = canonicalize_ref_edges(
        ref_edges_list, strict_duplicates=True, strict_short_hash=True
    )
    ref_edges_sha = ref_edges_sha256(ref_edges_list)

    return {
        "ref_closure": ref_closure,
        "ref_closure_sha256": ref_closure_sha256,
        "ref_edges": ref_edges_list,
        "ref_edges_sha256": ref_edges_sha,
        "counts": {"closure_files": len(ref_closure), "edges": len(ref_edges_list)},
    }
