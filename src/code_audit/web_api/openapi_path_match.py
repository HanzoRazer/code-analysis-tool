"""OpenAPI path template normalization for release gate matching.

Provides deterministic normalization so template variable names do not
affect path matching:

    /items/{id}      -> /items/{}
    /a/{x}/b/{y}     -> /a/{}/b/{}

This keeps matching unambiguous — only structure matters, not param names.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


_PARAM_RE = re.compile(r"^\{[^/{}]+\}$")


def _is_param(seg: str) -> bool:
    return bool(_PARAM_RE.match(seg))


def normalize_openapi_path_template(path: str) -> str:
    """Canonicalize an OpenAPI path so template variable names do not matter.

    Examples:
      /items/{id}      -> /items/{}
      /a/{x}/b/{y}     -> /a/{}/b/{}

    Notes:
      - Only segments that exactly match '{name}' are treated as params.
      - Does not attempt to normalize wildcards or regex-like patterns.
    """
    if not path.startswith("/"):
        path = "/" + path
    segs = path.split("/")
    out = []
    for s in segs:
        if s == "":
            out.append("")
        elif _is_param(s):
            out.append("{}")
        else:
            out.append(s)
    norm = "/".join(out)
    return norm if norm.startswith("/") else "/" + norm


def paths_equivalent_by_template(a: str, b: str) -> bool:
    """True if two OpenAPI paths are equivalent under template-name normalization."""
    return normalize_openapi_path_template(a) == normalize_openapi_path_template(b)


@dataclass(frozen=True)
class TemplateMatch:
    registry_path: str
    snapshot_path: str
    normalized: str


def find_template_match(registry_path: str, snapshot_paths: Iterable[str]) -> TemplateMatch | None:
    """Attempt to match registry_path to one of snapshot_paths by normalized template shape.

    Returns the first match in stable iteration order (caller should pass sorted paths).
    """
    target = normalize_openapi_path_template(registry_path)
    for sp in snapshot_paths:
        if normalize_openapi_path_template(sp) == target:
            return TemplateMatch(registry_path=registry_path, snapshot_path=sp, normalized=target)
    return None
