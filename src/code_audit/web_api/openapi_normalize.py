"""OpenAPI normalized model extractor for semantic diffing.

Produces a deterministic, scrubbed, normalized model specifically
shaped for breaking-change classification.

Key responsibilities:
- Volatility scrub (servers, externalDocs, build-time stamps)
- Path template normalization via openapi_path_match
- Operation extraction keyed as "METHOD /normalized/path/{}"
- Schema signature extraction with $ref resolution (cycle-safe)
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from code_audit.web_api.openapi_path_match import normalize_openapi_path_template


# ----------------------------
# Volatility scrub defaults
# ----------------------------

DEFAULT_VOLATILE_TOPLEVEL_KEYS = {
    "servers",
    "externalDocs",
}

DEFAULT_VOLATILE_INFO_KEYS = {
    "x-generated-at",
    "x_build_time",
    "x-build-time",
    "buildTime",
    "generatedAt",
}


def _deepcopy(obj: Any) -> Any:
    return copy.deepcopy(obj)


def _is_ref(obj: Any) -> bool:
    return isinstance(obj, dict) and "$ref" in obj and isinstance(obj["$ref"], str)


_REF_RE = re.compile(r"^#/components/schemas/(?P<name>[^/]+)$")


def _ref_name(ref: str) -> str | None:
    m = _REF_RE.match(ref)
    if not m:
        return None
    return m.group("name")


def _stable_sorted_list(values: Iterable[Any]) -> List[Any]:
    return sorted(values, key=lambda x: repr(x))


def _stable_dict(d: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: d[k] for k in sorted(d.keys())}


def _strip_none(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


# ----------------------------
# Schema signature extraction
# ----------------------------

@dataclass(frozen=True)
class SchemaSig:
    """Normalized, semver-relevant schema signature for diffing.

    Intentionally lossy: excludes descriptions/examples, focuses on constraints.
    """
    sig: Dict[str, Any]


def schema_signature(
    schema: Any,
    *,
    components_schemas: Mapping[str, Any] | None,
    treat_format_as_semantic: bool = False,
    treat_pattern_as_semantic: bool = False,
) -> SchemaSig:
    """Produce a deterministic signature for an OpenAPI/JSON Schema node.

    - Resolves $ref within #/components/schemas/*
    - Cycle-safe: emits {"$ref_cycle": "<name>"} at cycle points
    - Drops non-semantic fields: title, description, examples, deprecated
    - Canonicalizes ordering: required/enum sorted; properties sorted
    """
    comps = dict(components_schemas or {})
    visiting: set[str] = set()

    def sig_node(node: Any) -> Dict[str, Any]:
        if node is None:
            return {"type": "null"}
        if isinstance(node, bool):
            return {"bool_schema": node}
        if not isinstance(node, dict):
            return {"unknown_schema": type(node).__name__}

        if _is_ref(node):
            ref = node["$ref"]
            name = _ref_name(ref)
            if name is None:
                return {"$ref": ref, "ref_kind": "external_or_unsupported"}
            if name in visiting:
                return {"$ref_cycle": name}
            target = comps.get(name)
            if target is None:
                return {"$ref": ref, "ref_kind": "missing_component"}
            visiting.add(name)
            out = sig_node(target)
            visiting.remove(name)
            return {"$ref_resolved": name, "target": out}

        t = node.get("type")
        nullable = node.get("nullable")
        enum = node.get("enum")

        out: Dict[str, Any] = {}

        if isinstance(t, str):
            out["type"] = t
        elif isinstance(t, list):
            out["type"] = _stable_sorted_list([x for x in t if isinstance(x, str)])

        if isinstance(nullable, bool):
            out["nullable"] = nullable

        if isinstance(enum, list):
            out["enum"] = _stable_sorted_list(enum)

        # String constraints
        for k in ("minLength", "maxLength"):
            v = node.get(k)
            if isinstance(v, int):
                out[k] = v
        if treat_pattern_as_semantic:
            v = node.get("pattern")
            if isinstance(v, str):
                out["pattern"] = v
        if treat_format_as_semantic:
            v = node.get("format")
            if isinstance(v, str):
                out["format"] = v

        # Numeric constraints
        for k in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"):
            v = node.get(k)
            if isinstance(v, (int, float)):
                out[k] = v

        # Array constraints
        for k in ("minItems", "maxItems"):
            v = node.get(k)
            if isinstance(v, int):
                out[k] = v
        v = node.get("uniqueItems")
        if isinstance(v, bool):
            out["uniqueItems"] = v
        if "items" in node:
            out["items"] = sig_node(node.get("items"))

        # Object constraints
        req = node.get("required")
        if isinstance(req, list):
            out["required"] = _stable_sorted_list([x for x in req if isinstance(x, str)])

        props = node.get("properties")
        if isinstance(props, dict):
            out_props: Dict[str, Any] = {}
            for pk in sorted(props.keys()):
                out_props[pk] = sig_node(props[pk])
            out["properties"] = out_props

        if "additionalProperties" in node:
            ap = node.get("additionalProperties")
            if isinstance(ap, bool):
                out["additionalProperties"] = ap
            else:
                out["additionalProperties"] = sig_node(ap)

        # Composition
        for comp_key in ("oneOf", "anyOf", "allOf"):
            comp = node.get(comp_key)
            if isinstance(comp, list):
                comp_sigs = [sig_node(x) for x in comp]
                out[comp_key] = sorted(comp_sigs, key=lambda x: repr(x))

        return _stable_dict(out)

    return SchemaSig(sig=sig_node(schema))


# ----------------------------
# OpenAPI normalization
# ----------------------------

@dataclass(frozen=True)
class NormalizedParam:
    in_: str
    name: str
    required: bool | None
    schema: Dict[str, Any] | None


@dataclass(frozen=True)
class NormalizedMedia:
    content_type: str
    schema: Dict[str, Any] | None


@dataclass(frozen=True)
class NormalizedRequestBody:
    present: bool
    required: bool | None
    contents: List[NormalizedMedia]


@dataclass(frozen=True)
class NormalizedResponse:
    status: str
    contents: List[NormalizedMedia]


@dataclass(frozen=True)
class NormalizedOperation:
    op: str  # e.g. "GET /items/{}"
    method: str
    normalized_path: str
    source_paths: List[str]
    params: List[NormalizedParam]
    request_body: NormalizedRequestBody
    responses: List[NormalizedResponse]


@dataclass(frozen=True)
class NormalizedOpenAPI:
    """Deterministic, semver-oriented OpenAPI view for diffing."""
    version: int
    operations: List[NormalizedOperation]
    meta: Dict[str, Any]


Scrubber = Callable[[Dict[str, Any]], Dict[str, Any]]


def normalize_openapi(
    openapi: Dict[str, Any],
    *,
    scrubber: Scrubber | None = None,
    treat_format_as_semantic: bool = False,
    treat_pattern_as_semantic: bool = False,
) -> NormalizedOpenAPI:
    """Normalize an OpenAPI document into a deterministic, semver-relevant model."""
    doc = _deepcopy(openapi)
    if scrubber is not None:
        doc = scrubber(doc)
    else:
        doc = _default_scrub(doc)

    components = doc.get("components") if isinstance(doc.get("components"), dict) else {}
    components_schemas = components.get("schemas") if isinstance(components.get("schemas"), dict) else {}

    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    meta: Dict[str, Any] = {}
    if isinstance(info.get("title"), str):
        meta["title"] = info["title"]
    if isinstance(info.get("version"), str):
        meta["version"] = info["version"]
    meta = _stable_dict(meta)

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return NormalizedOpenAPI(version=1, operations=[], meta=meta)

    norm_path_map: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    for source_path, path_item in paths.items():
        if not isinstance(source_path, str) or not isinstance(path_item, dict):
            continue
        norm = normalize_openapi_path_template(source_path)
        norm_path_map.setdefault(norm, []).append((source_path, path_item))

    ops: List[NormalizedOperation] = []
    for norm_path in sorted(norm_path_map.keys()):
        entries = norm_path_map[norm_path]
        entries = sorted(entries, key=lambda x: x[0])
        source_paths = [p for (p, _) in entries]

        method_to_op: Dict[str, Dict[str, Any]] = {}
        method_to_source: Dict[str, List[str]] = {}

        for sp, item in entries:
            for method, op_obj in item.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options", "trace"):
                    continue
                if not isinstance(op_obj, dict):
                    continue
                m = method.upper()
                method_to_source.setdefault(m, []).append(sp)
                if m not in method_to_op:
                    method_to_op[m] = op_obj

        for method in sorted(method_to_op.keys()):
            op_obj = method_to_op[method]
            op_key = f"{method} {norm_path}"

            params = _extract_parameters(
                op_obj,
                components_schemas=components_schemas,
                treat_format_as_semantic=treat_format_as_semantic,
                treat_pattern_as_semantic=treat_pattern_as_semantic,
            )
            req = _extract_request_body(
                op_obj,
                components_schemas=components_schemas,
                treat_format_as_semantic=treat_format_as_semantic,
                treat_pattern_as_semantic=treat_pattern_as_semantic,
            )
            resps = _extract_responses(
                op_obj,
                components_schemas=components_schemas,
                treat_format_as_semantic=treat_format_as_semantic,
                treat_pattern_as_semantic=treat_pattern_as_semantic,
            )

            ops.append(
                NormalizedOperation(
                    op=op_key,
                    method=method,
                    normalized_path=norm_path,
                    source_paths=_stable_sorted_list(method_to_source.get(method, source_paths)),
                    params=params,
                    request_body=req,
                    responses=resps,
                )
            )

    ops = sorted(ops, key=lambda o: o.op)
    return NormalizedOpenAPI(version=1, operations=ops, meta=meta)


def _default_scrub(doc: Dict[str, Any]) -> Dict[str, Any]:
    for k in list(doc.keys()):
        if k in DEFAULT_VOLATILE_TOPLEVEL_KEYS:
            doc.pop(k, None)

    info = doc.get("info")
    if isinstance(info, dict):
        for k in list(info.keys()):
            if k in DEFAULT_VOLATILE_INFO_KEYS:
                info.pop(k, None)
        doc["info"] = info

    return doc


def _extract_parameters(
    op_obj: Dict[str, Any],
    *,
    components_schemas: Mapping[str, Any],
    treat_format_as_semantic: bool,
    treat_pattern_as_semantic: bool,
) -> List[NormalizedParam]:
    params = op_obj.get("parameters")
    out: List[NormalizedParam] = []
    if isinstance(params, list):
        for p in params:
            if not isinstance(p, dict):
                continue
            in_ = p.get("in")
            name = p.get("name")
            if not isinstance(in_, str) or not isinstance(name, str):
                continue
            required = p.get("required")
            req_bool = required if isinstance(required, bool) else None
            sch = p.get("schema")
            sch_sig = None
            if sch is not None:
                sch_sig = schema_signature(
                    sch,
                    components_schemas=components_schemas,
                    treat_format_as_semantic=treat_format_as_semantic,
                    treat_pattern_as_semantic=treat_pattern_as_semantic,
                ).sig
            out.append(NormalizedParam(in_=in_, name=name, required=req_bool, schema=sch_sig))

    out = sorted(out, key=lambda x: (x.in_, x.name))
    return out


def _extract_request_body(
    op_obj: Dict[str, Any],
    *,
    components_schemas: Mapping[str, Any],
    treat_format_as_semantic: bool,
    treat_pattern_as_semantic: bool,
) -> NormalizedRequestBody:
    rb = op_obj.get("requestBody")
    if not isinstance(rb, dict):
        return NormalizedRequestBody(present=False, required=None, contents=[])

    required = rb.get("required")
    req_bool = required if isinstance(required, bool) else None
    content = rb.get("content")
    contents: List[NormalizedMedia] = []

    if isinstance(content, dict):
        for ctype in sorted(content.keys()):
            cobj = content.get(ctype)
            if not isinstance(cobj, dict):
                continue
            sch = None
            if isinstance(cobj.get("schema"), (dict, bool)) or cobj.get("schema") is None:
                sch = cobj.get("schema")
            sch_sig = None
            if sch is not None:
                sch_sig = schema_signature(
                    sch,
                    components_schemas=components_schemas,
                    treat_format_as_semantic=treat_format_as_semantic,
                    treat_pattern_as_semantic=treat_pattern_as_semantic,
                ).sig
            contents.append(NormalizedMedia(content_type=ctype, schema=sch_sig))

    return NormalizedRequestBody(present=True, required=req_bool, contents=contents)


def _extract_responses(
    op_obj: Dict[str, Any],
    *,
    components_schemas: Mapping[str, Any],
    treat_format_as_semantic: bool,
    treat_pattern_as_semantic: bool,
) -> List[NormalizedResponse]:
    responses = op_obj.get("responses")
    out: List[NormalizedResponse] = []
    if not isinstance(responses, dict):
        return out

    for status in sorted(responses.keys(), key=lambda s: str(s)):
        robj = responses.get(status)
        if not isinstance(robj, dict):
            continue
        content = robj.get("content")
        contents: List[NormalizedMedia] = []
        if isinstance(content, dict):
            for ctype in sorted(content.keys()):
                cobj = content.get(ctype)
                if not isinstance(cobj, dict):
                    continue
                sch = cobj.get("schema")
                sch_sig = None
                if sch is not None:
                    sch_sig = schema_signature(
                        sch,
                        components_schemas=components_schemas,
                        treat_format_as_semantic=treat_format_as_semantic,
                        treat_pattern_as_semantic=treat_pattern_as_semantic,
                    ).sig
                contents.append(NormalizedMedia(content_type=ctype, schema=sch_sig))

        out.append(NormalizedResponse(status=str(status), contents=contents))

    return out
