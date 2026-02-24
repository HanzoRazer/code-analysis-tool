"""Schema $ref edge kind classification, priority table, canonicalization, and hashing.

Single source of truth for:
- Edge kind enum tokens
- KIND_PRIORITY table (most-specific-wins)
- Nearest / semantic / dual-kind classification
- Trace compact computation
- Trace short hash
- Edge identity key + sort key
- Edge list canonicalization (sort + dedupe + validate)
- Edge list attestation hash (excluding derived per-edge short hash)
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple


# Stable enum tokens (must stay aligned with the BOM schema enum).
EDGE_KIND_KEYS: Set[str] = {
    "direct",
    "allOf", "anyOf", "oneOf",
    "not", "if", "then", "else",
    "items", "additionalProperties",
    "properties", "patternProperties",
    "dependentSchemas",
    "definitions", "$defs",
    "unknown",
}


# "Most specific wins" priority table.
# Smaller number = more specific = wins.
KIND_PRIORITY: Dict[str, int] = {
    # leaf-like / strongest specificity
    "properties": 10,
    "patternProperties": 12,
    "dependentSchemas": 14,
    "items": 20,
    "additionalProperties": 22,
    # conditional constructs
    "if": 30,
    "then": 32,
    "else": 34,
    "not": 36,
    # combinators (broader)
    "allOf": 50,
    "oneOf": 52,
    "anyOf": 54,
    # definitional containers (broad)
    "$defs": 80,
    "definitions": 82,
    # base / fallback
    "direct": 900,
    "unknown": 1000,
}


def normalize_kind(key: Optional[str]) -> str:
    """Normalize a container key to a recognized kind token."""
    if key is None:
        return "direct"
    if key in KIND_PRIORITY:
        return key
    return "unknown"


def choose_nearest_kind(context_keys: List[Optional[str]]) -> str:
    """Nearest container wins (closest / last key in the stack)."""
    if not context_keys:
        return "direct"
    return normalize_kind(context_keys[-1])


def choose_most_specific_kind(context_keys: List[Optional[str]]) -> str:
    """Most-specific-wins by KIND_PRIORITY across all nested container keys."""
    kinds = [normalize_kind(k) for k in context_keys]
    if not kinds:
        return "direct"
    best = min(kinds, key=lambda k: (KIND_PRIORITY.get(k, 1000), k))
    return best


def trace_compact(context_keys: List[Optional[str]]) -> List[str]:
    """Compact recognized context keys, deduped in-order (outer -> inner).
    Excludes 'direct'. Includes 'unknown' when an unrecognized key occurs."""
    out: List[str] = []
    seen: Set[str] = set()
    for k in context_keys:
        nk = normalize_kind(k)
        if nk == "direct":
            continue
        if nk not in seen:
            seen.add(nk)
            out.append(nk)
    return out


def trace_sha256_short(trace: List[str]) -> str:
    """First 12 hex chars of SHA-256 of canonical JSON of the trace list."""
    b = json.dumps(trace, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()[:12]


def collect_ref_targets_with_trace(
    node: Any,
) -> List[Tuple[str, str, str, List[str], str]]:
    """Walk schema JSON and collect $ref targets with dual-kind + trace.

    Returns list of (ref, kind_structural, kind_semantic, kind_trace_compact, kind_trace_sha256_short).
    """
    out: List[Tuple[str, str, str, List[str], str]] = []

    def walk(n: Any, stack: List[Optional[str]]) -> None:
        if isinstance(n, dict):
            ref = n.get("$ref")
            if isinstance(ref, str):
                ks = choose_nearest_kind(stack)
                km = choose_most_specific_kind(stack)
                kt = trace_compact(stack)
                out.append((ref, ks, km, kt, trace_sha256_short(kt)))
            for k, v in n.items():
                walk(v, stack + [k])
        elif isinstance(n, list):
            for it in n:
                walk(it, stack)

    walk(node, [])
    return out


# ── Edge canonicalization ──────────────────────────────────────

def edge_identity_key(e: Dict[str, Any]) -> Tuple[Any, ...]:
    """Strict edge identity key (excludes derived short hash)."""
    trace = e.get("kind_trace_compact")
    trace_t = tuple(trace) if isinstance(trace, list) else ()
    return (
        e.get("from"),
        e.get("to"),
        e.get("kind_structural"),
        e.get("kind_semantic"),
        trace_t,
    )


def edge_sort_key(e: Dict[str, Any]) -> Tuple[Any, ...]:
    """Canonical sort key. Identity key + derived short hash as tie-breaker."""
    return edge_identity_key(e) + (e.get("kind_trace_sha256_short"),)


def canonicalize_ref_edges(
    edge_recs: List[Dict[str, Any]],
    *,
    strict_duplicates: bool = True,
    strict_short_hash: bool = True,
) -> List[Dict[str, Any]]:
    """Canonicalize edges: validate/repair short hash, sort, enforce uniqueness."""
    edges = list(edge_recs)

    # Validate/repair derived trace short hash
    for e in edges:
        trace = e.get("kind_trace_compact")
        if not isinstance(trace, list):
            raise RuntimeError(f"Invalid kind_trace_compact in edge: {e}")
        want_short = trace_sha256_short(trace)
        got_short = e.get("kind_trace_sha256_short")
        if got_short is None:
            e["kind_trace_sha256_short"] = want_short
        elif got_short != want_short:
            if strict_short_hash:
                raise RuntimeError(
                    f"Edge trace short hash mismatch for {e.get('from')} -> {e.get('to')}: "
                    f"got={got_short} want={want_short}"
                )
            e["kind_trace_sha256_short"] = want_short

    # Sort
    edges = sorted(edges, key=edge_sort_key)

    # De-dupe by identity (excluding derived short hash)
    out: List[Dict[str, Any]] = []
    seen: Set[Tuple[Any, ...]] = set()
    for e in edges:
        ident = edge_identity_key(e)
        if ident in seen:
            if strict_duplicates:
                raise RuntimeError(f"Duplicate ref edge identity encountered: {ident}")
            continue
        seen.add(ident)
        out.append(e)

    return out


def edges_sha256_excluding_trace_short(edges: List[Dict[str, Any]]) -> str:
    """Hash the edge list excluding per-edge derived short hash fields."""
    normalized = []
    for e in edges:
        normalized.append({
            "from": e["from"],
            "to": e["to"],
            "kind_structural": e["kind_structural"],
            "kind_semantic": e["kind_semantic"],
            "kind_trace_compact": e["kind_trace_compact"],
        })
    b = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def ref_edges_sha256(edge_recs: List[Dict[str, Any]]) -> str:
    """Canonical list hash over normalized edge view (excludes per-edge derived short hash)."""
    return edges_sha256_excluding_trace_short(edge_recs)
