from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from code_audit.web_api.openapi_normalize import (
    NormalizedOpenAPI,
    NormalizedOperation,
    NormalizedParam,
    NormalizedRequestBody,
    NormalizedResponse,
)
from code_audit.web_api.schema_semver import compare_schema_semver


# ----------------------------
# Diff report model
# ----------------------------


@dataclass(frozen=True)
class Change:
    kind: str
    op: str | None = None
    path: str | None = None
    location: str | None = None
    detail: str | None = None
    before: Any | None = None
    after: Any | None = None


@dataclass(frozen=True)
class DiffSummary:
    breaking_count: int
    non_breaking_count: int
    unknown_count: int


@dataclass(frozen=True)
class OpenAPIDiffReport:
    breaking: bool
    breaking_changes: List[Change]
    non_breaking_changes: List[Change]
    unknown_changes: List[Change]
    summary: DiffSummary
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        def ch(c: Change) -> Dict[str, Any]:
            d: Dict[str, Any] = {"kind": c.kind}
            if c.op is not None:
                d["op"] = c.op
            if c.path is not None:
                d["path"] = c.path
            if c.location is not None:
                d["location"] = c.location
            if c.detail is not None:
                d["detail"] = c.detail
            if c.before is not None:
                d["before"] = c.before
            if c.after is not None:
                d["after"] = c.after
            return d

        # Deterministic ordering: caller already sorts lists; still stable if used directly.
        return {
            "version": self.version,
            "breaking": self.breaking,
            "summary": {
                "breaking_count": self.summary.breaking_count,
                "non_breaking_count": self.summary.non_breaking_count,
                "unknown_count": self.summary.unknown_count,
            },
            "breaking_changes": [ch(x) for x in self.breaking_changes],
            "non_breaking_changes": [ch(x) for x in self.non_breaking_changes],
            "unknown_changes": [ch(x) for x in self.unknown_changes],
        }


# ----------------------------
# Core classifier (Scope-3 foundation)
# ----------------------------


DEFAULT_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}

PolicyItem = Dict[str, Any]
Policy = Dict[str, Any]


def diff_openapi_core(
    before: NormalizedOpenAPI,
    after: NormalizedOpenAPI,
    *,
    success_status_prefixes: Tuple[str, ...] = ("2",),  # treat only 2xx as success by default
    treat_nullable_tightening_as_breaking: bool = True,
    treat_format_as_semantic: bool = False,
    treat_pattern_as_semantic: bool = False,
) -> OpenAPIDiffReport:
    """
    Core OpenAPI semantic diff classifier:
      - added/removed operations (path+method)
      - parameter removed / required tightened (breaking)
      - parameter added (non-breaking if optional; unknown if required and no baseline)
      - requestBody presence/required changes
      - responses: success status removed (breaking); media type removed (breaking)
      - schema narrowing/widening/unknown integrated via schema_semver comparator
    """
    b_ops = {op.op: op for op in before.operations}
    a_ops = {op.op: op for op in after.operations}

    breaking: List[Change] = []
    non_breaking: List[Change] = []
    unknown: List[Change] = []

    b_keys = set(b_ops.keys())
    a_keys = set(a_ops.keys())

    removed_ops = sorted(b_keys - a_keys)
    added_ops = sorted(a_keys - b_keys)

    for op in removed_ops:
        breaking.append(Change(kind="removed_operation", op=op, detail="Operation removed"))

    for op in added_ops:
        non_breaking.append(Change(kind="added_operation", op=op, detail="Operation added"))

    # Compare shared operations
    for op_key in sorted(b_keys & a_keys):
        b = b_ops[op_key]
        a = a_ops[op_key]
        _diff_operation_core(
            op_key,
            b,
            a,
            breaking,
            non_breaking,
            unknown,
            success_status_prefixes=success_status_prefixes,
            treat_nullable_tightening_as_breaking=treat_nullable_tightening_as_breaking,
            treat_format_as_semantic=treat_format_as_semantic,
            treat_pattern_as_semantic=treat_pattern_as_semantic,
        )

    # Deterministic sort
    breaking = sorted(breaking, key=_change_sort_key)
    non_breaking = sorted(non_breaking, key=_change_sort_key)
    unknown = sorted(unknown, key=_change_sort_key)

    report = OpenAPIDiffReport(
        breaking=len(breaking) > 0,
        breaking_changes=breaking,
        non_breaking_changes=non_breaking,
        unknown_changes=unknown,
        summary=DiffSummary(
            breaking_count=len(breaking),
            non_breaking_count=len(non_breaking),
            unknown_count=len(unknown),
        ),
    )
    return report


def _change_sort_key(c: Change) -> tuple:
    return (
        c.kind or "",
        c.op or "",
        c.path or "",
        c.location or "",
        c.detail or "",
        repr(c.before) if c.before is not None else "",
        repr(c.after) if c.after is not None else "",
    )


def _param_key(p: NormalizedParam) -> tuple[str, str]:
    return (p.in_, p.name)


def _param_map(params: List[NormalizedParam]) -> Dict[tuple[str, str], NormalizedParam]:
    return {_param_key(p): p for p in params}


def _diff_operation_core(
    op_key: str,
    before: NormalizedOperation,
    after: NormalizedOperation,
    breaking: List[Change],
    non_breaking: List[Change],
    unknown: List[Change],
    *,
    success_status_prefixes: Tuple[str, ...],
    treat_nullable_tightening_as_breaking: bool,
    treat_format_as_semantic: bool,
    treat_pattern_as_semantic: bool,
) -> None:
    # ---- Parameters ----
    bmap = _param_map(before.params)
    amap = _param_map(after.params)

    bkeys = set(bmap.keys())
    akeys = set(amap.keys())

    for k in sorted(bkeys - akeys):
        p = bmap[k]
        breaking.append(
            Change(
                kind="removed_parameter",
                op=op_key,
                location=f"parameters.{p.in_}.{p.name}",
                detail="Parameter removed",
                before={"in": p.in_, "name": p.name, "required": p.required},
                after=None,
            )
        )

    for k in sorted(akeys - bkeys):
        p = amap[k]
        # Adding an optional param is non-breaking. Adding a required param is generally breaking,
        # but OpenAPI required flags can be absent; if required is True, call it breaking.
        if p.required is True:
            breaking.append(
                Change(
                    kind="added_required_parameter",
                    op=op_key,
                    location=f"parameters.{p.in_}.{p.name}",
                    detail="Required parameter added",
                    before=None,
                    after={"in": p.in_, "name": p.name, "required": p.required},
                )
            )
        else:
            non_breaking.append(
                Change(
                    kind="added_optional_parameter",
                    op=op_key,
                    location=f"parameters.{p.in_}.{p.name}",
                    detail="Optional parameter added",
                    before=None,
                    after={"in": p.in_, "name": p.name, "required": p.required},
                )
            )

    for k in sorted(bkeys & akeys):
        bp = bmap[k]
        ap = amap[k]
        # required tightened: False/None -> True is breaking
        if (bp.required is False or bp.required is None) and ap.required is True:
            breaking.append(
                Change(
                    kind="parameter_required_tightened",
                    op=op_key,
                    location=f"parameters.{ap.in_}.{ap.name}.required",
                    detail="Parameter became required",
                    before={"required": bp.required},
                    after={"required": ap.required},
                )
            )

        # schema narrowing/widening/unknown (if both schemas present)
        if bp.schema is not None and ap.schema is not None and bp.schema != ap.schema:
            delta = compare_schema_semver(
                bp.schema,
                ap.schema,
                treat_nullable_tightening_as_breaking=treat_nullable_tightening_as_breaking,
                treat_format_as_semantic=treat_format_as_semantic,
                treat_pattern_as_semantic=treat_pattern_as_semantic,
            )
            loc = f"parameters.{ap.in_}.{ap.name}.schema"
            if delta.breaking:
                breaking.append(
                    Change(
                        kind="parameter_schema_narrowed",
                        op=op_key,
                        location=loc,
                        detail="; ".join(delta.breaking),
                        before=bp.schema,
                        after=ap.schema,
                    )
                )
            elif delta.non_breaking:
                non_breaking.append(
                    Change(
                        kind="parameter_schema_widened",
                        op=op_key,
                        location=loc,
                        detail="; ".join(delta.non_breaking),
                        before=bp.schema,
                        after=ap.schema,
                    )
                )
            elif delta.unknown:
                unknown.append(
                    Change(
                        kind="parameter_schema_changed_unknown",
                        op=op_key,
                        location=loc,
                        detail="; ".join(delta.unknown),
                        before=bp.schema,
                        after=ap.schema,
                    )
                )

    # ---- Request body presence/required ----
    _diff_request_body(
        op_key,
        before.request_body,
        after.request_body,
        breaking,
        non_breaking,
        unknown,
        treat_nullable_tightening_as_breaking=treat_nullable_tightening_as_breaking,
        treat_format_as_semantic=treat_format_as_semantic,
        treat_pattern_as_semantic=treat_pattern_as_semantic,
    )

    # ---- Responses presence (status code + media types) ----
    _diff_responses_presence(
        op_key,
        before.responses,
        after.responses,
        breaking,
        non_breaking,
        unknown,
        success_status_prefixes=success_status_prefixes,
        treat_nullable_tightening_as_breaking=treat_nullable_tightening_as_breaking,
        treat_format_as_semantic=treat_format_as_semantic,
        treat_pattern_as_semantic=treat_pattern_as_semantic,
    )


def _diff_request_body(
    op_key: str,
    before: NormalizedRequestBody,
    after: NormalizedRequestBody,
    breaking: List[Change],
    non_breaking: List[Change],
    unknown: List[Change],
    *,
    treat_nullable_tightening_as_breaking: bool,
    treat_format_as_semantic: bool,
    treat_pattern_as_semantic: bool,
) -> None:
    if before.present and not after.present:
        breaking.append(
            Change(
                kind="removed_request_body",
                op=op_key,
                location="requestBody",
                detail="Request body removed",
                before={"present": True, "required": before.required},
                after={"present": False},
            )
        )
        return

    if not before.present and after.present:
        # If request body newly appears and is required, that is breaking.
        if after.required is True:
            breaking.append(
                Change(
                    kind="added_required_request_body",
                    op=op_key,
                    location="requestBody",
                    detail="Required request body added",
                    before={"present": False},
                    after={"present": True, "required": True},
                )
            )
        else:
            non_breaking.append(
                Change(
                    kind="added_optional_request_body",
                    op=op_key,
                    location="requestBody",
                    detail="Optional request body added",
                    before={"present": False},
                    after={"present": True, "required": after.required},
                )
            )
        return

    if before.present and after.present:
        # Required tightened: False/None -> True is breaking
        if (before.required is False or before.required is None) and after.required is True:
            breaking.append(
                Change(
                    kind="request_body_required_tightened",
                    op=op_key,
                    location="requestBody.required",
                    detail="Request body became required",
                    before={"required": before.required},
                    after={"required": after.required},
                )
            )

        # Media type removals/additions (presence only; schema narrowing later)
        b_ct = {m.content_type for m in before.contents}
        a_ct = {m.content_type for m in after.contents}

        for ct in sorted(b_ct - a_ct):
            breaking.append(
                Change(
                    kind="removed_request_media_type",
                    op=op_key,
                    location=f"requestBody.content.{ct}",
                    detail="Request media type removed",
                    before={"content_type": ct},
                    after=None,
                )
            )
        for ct in sorted(a_ct - b_ct):
            non_breaking.append(
                Change(
                    kind="added_request_media_type",
                    op=op_key,
                    location=f"requestBody.content.{ct}",
                    detail="Request media type added",
                    before=None,
                    after={"content_type": ct},
                )
            )

        # Schema compare for shared media types (presence already handled)
        b_by_ct = {m.content_type: m for m in before.contents}
        a_by_ct = {m.content_type: m for m in after.contents}
        for ct in sorted(b_ct & a_ct):
            bsch = b_by_ct[ct].schema
            asch = a_by_ct[ct].schema
            if bsch is None or asch is None or bsch == asch:
                continue
            delta = compare_schema_semver(
                bsch,
                asch,
                treat_nullable_tightening_as_breaking=treat_nullable_tightening_as_breaking,
                treat_format_as_semantic=treat_format_as_semantic,
                treat_pattern_as_semantic=treat_pattern_as_semantic,
            )
            loc = f"requestBody.content.{ct}.schema"
            if delta.breaking:
                breaking.append(
                    Change(
                        kind="request_schema_narrowed",
                        op=op_key,
                        location=loc,
                        detail="; ".join(delta.breaking),
                        before=bsch,
                        after=asch,
                    )
                )
            elif delta.non_breaking:
                non_breaking.append(
                    Change(
                        kind="request_schema_widened",
                        op=op_key,
                        location=loc,
                        detail="; ".join(delta.non_breaking),
                        before=bsch,
                        after=asch,
                    )
                )
            elif delta.unknown:
                unknown.append(
                    Change(
                        kind="request_schema_changed_unknown",
                        op=op_key,
                        location=loc,
                        detail="; ".join(delta.unknown),
                        before=bsch,
                        after=asch,
                    )
                )


def _diff_responses_presence(
    op_key: str,
    before: List[NormalizedResponse],
    after: List[NormalizedResponse],
    breaking: List[Change],
    non_breaking: List[Change],
    unknown: List[Change],
    *,
    success_status_prefixes: Tuple[str, ...],
    treat_nullable_tightening_as_breaking: bool,
    treat_format_as_semantic: bool,
    treat_pattern_as_semantic: bool,
) -> None:
    bmap = {r.status: r for r in before}
    amap = {r.status: r for r in after}
    bkeys = set(bmap.keys())
    akeys = set(amap.keys())

    def is_success(status: str) -> bool:
        return any(status.startswith(p) for p in success_status_prefixes)

    for status in sorted(bkeys - akeys):
        if is_success(status):
            breaking.append(
                Change(
                    kind="removed_success_response_status",
                    op=op_key,
                    location=f"responses.{status}",
                    detail="Success response status removed",
                    before={"status": status},
                    after=None,
                )
            )
        else:
            # Removing non-success responses might be non-breaking; keep as unknown until policy decides.
            unknown.append(
                Change(
                    kind="removed_non_success_response_status",
                    op=op_key,
                    location=f"responses.{status}",
                    detail="Non-success response status removed",
                    before={"status": status},
                    after=None,
                )
            )

    for status in sorted(akeys - bkeys):
        # Adding responses is usually non-breaking
        non_breaking.append(
            Change(
                kind="added_response_status",
                op=op_key,
                location=f"responses.{status}",
                detail="Response status added",
                before=None,
                after={"status": status},
            )
        )

    for status in sorted(bkeys & akeys):
        br = bmap[status]
        ar = amap[status]
        b_ct = {m.content_type for m in br.contents}
        a_ct = {m.content_type for m in ar.contents}

        for ct in sorted(b_ct - a_ct):
            # Removing response media types for success is breaking; for non-success unknown.
            if is_success(status):
                breaking.append(
                    Change(
                        kind="removed_success_response_media_type",
                        op=op_key,
                        location=f"responses.{status}.content.{ct}",
                        detail="Success response media type removed",
                        before={"status": status, "content_type": ct},
                        after=None,
                    )
                )
            else:
                unknown.append(
                    Change(
                        kind="removed_non_success_response_media_type",
                        op=op_key,
                        location=f"responses.{status}.content.{ct}",
                        detail="Non-success response media type removed",
                        before={"status": status, "content_type": ct},
                        after=None,
                    )
                )

        for ct in sorted(a_ct - b_ct):
            non_breaking.append(
                Change(
                    kind="added_response_media_type",
                    op=op_key,
                    location=f"responses.{status}.content.{ct}",
                    detail="Response media type added",
                    before=None,
                    after={"status": status, "content_type": ct},
                )
            )

        # Schema compare for shared media types
        b_by_ct = {m.content_type: m for m in br.contents}
        a_by_ct = {m.content_type: m for m in ar.contents}
        for ct in sorted(b_ct & a_ct):
            bsch = b_by_ct[ct].schema
            asch = a_by_ct[ct].schema
            if bsch is None or asch is None or bsch == asch:
                continue
            delta = compare_schema_semver(
                bsch,
                asch,
                treat_nullable_tightening_as_breaking=treat_nullable_tightening_as_breaking,
                treat_format_as_semantic=treat_format_as_semantic,
                treat_pattern_as_semantic=treat_pattern_as_semantic,
            )
            loc = f"responses.{status}.content.{ct}.schema"
            if any(str(status).startswith(p) for p in success_status_prefixes):
                if delta.breaking:
                    breaking.append(
                        Change(
                            kind="success_response_schema_narrowed",
                            op=op_key,
                            location=loc,
                            detail="; ".join(delta.breaking),
                            before=bsch,
                            after=asch,
                        )
                    )
                elif delta.non_breaking:
                    non_breaking.append(
                        Change(
                            kind="success_response_schema_widened",
                            op=op_key,
                            location=loc,
                            detail="; ".join(delta.non_breaking),
                            before=bsch,
                            after=asch,
                        )
                    )
                elif delta.unknown:
                    unknown.append(
                        Change(
                            kind="success_response_schema_changed_unknown",
                            op=op_key,
                            location=loc,
                            detail="; ".join(delta.unknown),
                            before=bsch,
                            after=asch,
                        )
                    )
            else:
                # Non-success schema changes are typically not contract-critical; keep unknown
                if delta.breaking or delta.non_breaking or delta.unknown:
                    unknown.append(
                        Change(
                            kind="non_success_response_schema_changed",
                            op=op_key,
                            location=loc,
                            detail="; ".join(delta.breaking + delta.non_breaking + delta.unknown),
                            before=bsch,
                            after=asch,
                        )
                    )


# ----------------------------
# Allowlist policy application
# ----------------------------


def apply_allowlist_policy(
    report: OpenAPIDiffReport,
    *,
    policy: Policy | None,
) -> OpenAPIDiffReport:
    """
    Apply allowlist policy deterministically.

    - allow_unknown: unknown -> non-breaking (kind becomes 'allowed_unknown') with annotation
    - allow_breaking: breaking -> unknown by default (kind becomes 'allowed_breaking_to_unknown')
        - if allow_breaking_to_non_breaking=true: breaking -> non-breaking (kind becomes 'allowed_breaking')

    Strict match:
      - kind must match
      - op OR path must match (policy entry must include one)
      - if policy entry includes location, it must match; otherwise location is not required
    """
    if not policy:
        return report

    allow_unknown = policy.get("allow_unknown") or []
    allow_breaking = policy.get("allow_breaking") or []
    allow_break_to_nb = bool(policy.get("allow_breaking_to_non_breaking", False))

    def index(items: Iterable[PolicyItem]) -> Dict[tuple, PolicyItem]:
        out: Dict[tuple, PolicyItem] = {}
        for it in items:
            if not isinstance(it, dict):
                continue
            kind = it.get("kind")
            op = it.get("op")
            path = it.get("path")
            loc = it.get("location")
            if not isinstance(kind, str) or not kind:
                continue
            key = (
                kind,
                str(op) if op is not None else None,
                str(path) if path is not None else None,
                str(loc) if loc is not None else None,
            )
            out[key] = it
        return out

    allow_u = index(allow_unknown)
    allow_b = index(allow_breaking)

    def match_keys(c: Change) -> List[tuple]:
        loc = c.location if c.location is not None else None
        keys: List[tuple] = []
        if c.op is not None:
            keys.append((c.kind, c.op, None, loc))
            keys.append((c.kind, c.op, None, None))
        if c.path is not None:
            keys.append((c.kind, None, c.path, loc))
            keys.append((c.kind, None, c.path, None))
        return keys

    def annotate(c: Change, it: PolicyItem, *, new_kind: str) -> Change:
        reason = it.get("reason")
        reason_s = reason if isinstance(reason, str) else "allowed_by_policy"
        prefix = f"allowed_by_policy: {reason_s}"
        detail = (c.detail or "").strip()
        merged_detail = prefix if not detail else f"{prefix} | {detail}"
        return Change(
            kind=new_kind,
            op=c.op,
            path=c.path,
            location=c.location,
            detail=merged_detail,
            before=c.before,
            after=c.after,
        )

    # unknown -> allowed_unknown (non-breaking)
    new_unknown: List[Change] = []
    new_non_breaking: List[Change] = list(report.non_breaking_changes)
    for c in report.unknown_changes:
        it = None
        for k in match_keys(c):
            if k in allow_u:
                it = allow_u[k]
                break
        if it is None:
            new_unknown.append(c)
        else:
            new_non_breaking.append(annotate(c, it, new_kind="allowed_unknown"))

    # breaking -> allowed_breaking_to_unknown (default) OR allowed_breaking (if enabled)
    new_breaking: List[Change] = []
    for c in report.breaking_changes:
        it = None
        for k in match_keys(c):
            if k in allow_b:
                it = allow_b[k]
                break
        if it is None:
            new_breaking.append(c)
            continue

        if allow_break_to_nb:
            new_non_breaking.append(annotate(c, it, new_kind="allowed_breaking"))
        else:
            new_unknown.append(annotate(c, it, new_kind="allowed_breaking_to_unknown"))

    # Deterministic sort
    new_breaking = sorted(new_breaking, key=_change_sort_key)
    new_non_breaking = sorted(new_non_breaking, key=_change_sort_key)
    new_unknown = sorted(new_unknown, key=_change_sort_key)

    return OpenAPIDiffReport(
        breaking=len(new_breaking) > 0,
        breaking_changes=new_breaking,
        non_breaking_changes=new_non_breaking,
        unknown_changes=new_unknown,
        summary=DiffSummary(
            breaking_count=len(new_breaking),
            non_breaking_count=len(new_non_breaking),
            unknown_count=len(new_unknown),
        ),
        version=report.version,
    )
