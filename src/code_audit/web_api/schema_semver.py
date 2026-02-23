from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class SchemaDelta:
    breaking: List[str]
    non_breaking: List[str]
    unknown: List[str]

    @property
    def is_breaking(self) -> bool:
        return len(self.breaking) > 0

    @property
    def is_unknown(self) -> bool:
        return (not self.is_breaking) and len(self.unknown) > 0

    @property
    def is_non_breaking(self) -> bool:
        return (not self.is_breaking) and (not self.is_unknown) and len(self.non_breaking) > 0


def compare_schema_semver(
    before: Dict[str, Any] | None,
    after: Dict[str, Any] | None,
    *,
    treat_nullable_tightening_as_breaking: bool = True,
    treat_format_as_semantic: bool = False,
    treat_pattern_as_semantic: bool = False,
) -> SchemaDelta:
    """
    Compare two schema signatures (from openapi_normalize.schema_signature()) and classify:
      - breaking (narrowing / incompatibility)
      - non-breaking (widening / additive)
      - unknown (complex change we refuse to guess)

    Inputs are signature dicts, not raw OpenAPI schema.
    """
    b = before or {}
    a = after or {}

    breaking: List[str] = []
    non_breaking: List[str] = []
    unknown: List[str] = []

    # If either side indicates external/unsupported ref, treat as unknown unless identical.
    if b.get("ref_kind") in ("external_or_unsupported",) or a.get("ref_kind") in ("external_or_unsupported",):
        if b == a:
            return SchemaDelta(breaking=[], non_breaking=[], unknown=[])
        return SchemaDelta(breaking=[], non_breaking=[], unknown=["external_or_unsupported_ref_change"])

    # Handle boolean schema forms if present
    if "bool_schema" in b or "bool_schema" in a:
        if b == a:
            return SchemaDelta(breaking=[], non_breaking=[], unknown=[])
        # True/False schema semantics can be tricky; conservatively unknown
        return SchemaDelta(breaking=[], non_breaking=[], unknown=["boolean_schema_change"])

    # If resolved refs differ, compare target payloads but keep ref identity for diagnostics
    b_target = b.get("target") if isinstance(b.get("target"), dict) else b
    a_target = a.get("target") if isinstance(a.get("target"), dict) else a

    # Composition is complex; if present and not identical after normalization, treat as unknown.
    # (Normalization already sorts composition lists deterministically.)
    for comp in ("oneOf", "anyOf", "allOf"):
        if comp in b_target or comp in a_target:
            if b_target.get(comp) == a_target.get(comp):
                continue
            return SchemaDelta(breaking=[], non_breaking=[], unknown=[f"{comp}_change"])

    # Type changes
    b_type = b_target.get("type")
    a_type = a_target.get("type")
    if b_type != a_type:
        # Some OpenAPI forms use list type; if both are lists, we can compare set inclusion
        if isinstance(b_type, list) and isinstance(a_type, list):
            bset = set([x for x in b_type if isinstance(x, str)])
            aset = set([x for x in a_type if isinstance(x, str)])
            if aset.issuperset(bset):
                non_breaking.append("type_widened")
            elif aset.issubset(bset):
                breaking.append("type_narrowed")
            else:
                unknown.append("type_changed_incompatible_union")
        else:
            breaking.append("type_changed")

    # Nullable tightening
    if treat_nullable_tightening_as_breaking:
        b_null = b_target.get("nullable")
        a_null = a_target.get("nullable")
        if b_null is True and a_null is False:
            breaking.append("nullable_tightened")
        elif b_null is False and a_null is True:
            non_breaking.append("nullable_widened")

    # Enum changes
    b_enum = b_target.get("enum")
    a_enum = a_target.get("enum")
    if isinstance(b_enum, list) or isinstance(a_enum, list):
        bset = set(b_enum or [])
        aset = set(a_enum or [])
        if bset and aset:
            if aset.issubset(bset) and aset != bset:
                breaking.append("enum_narrowed")
            elif aset.issuperset(bset) and aset != bset:
                non_breaking.append("enum_widened")
            elif aset != bset:
                unknown.append("enum_changed_non_subset")
        elif bset and not aset:
            # Removing enum restriction is widening (non-breaking)
            non_breaking.append("enum_removed")
        elif not bset and aset:
            # Adding enum restriction is narrowing (breaking)
            breaking.append("enum_added")

    # Numeric constraints (tightening/widening)
    _compare_bounds(b_target, a_target, breaking, non_breaking, unknown)

    # String constraints
    _compare_string_constraints(
        b_target,
        a_target,
        breaking,
        non_breaking,
        unknown,
        treat_format_as_semantic=treat_format_as_semantic,
        treat_pattern_as_semantic=treat_pattern_as_semantic,
    )

    # Object constraints: required / properties / additionalProperties
    _compare_object_constraints(b_target, a_target, breaking, non_breaking, unknown)

    # Array constraints
    _compare_array_constraints(b_target, a_target, breaking, non_breaking, unknown)

    return SchemaDelta(breaking=breaking, non_breaking=non_breaking, unknown=unknown)


def _compare_bounds(
    b: Dict[str, Any],
    a: Dict[str, Any],
    breaking: List[str],
    non_breaking: List[str],
    unknown: List[str],
) -> None:
    # minimum: higher => narrower (breaking), lower => wider (non-breaking)
    for k in ("minimum", "exclusiveMinimum"):
        if k in b or k in a:
            bmin = b.get(k)
            amin = a.get(k)
            if isinstance(bmin, (int, float)) and isinstance(amin, (int, float)):
                if amin > bmin:
                    breaking.append(f"{k}_tightened")
                elif amin < bmin:
                    non_breaking.append(f"{k}_widened")
            elif bmin is None and isinstance(amin, (int, float)):
                breaking.append(f"{k}_added")
            elif isinstance(bmin, (int, float)) and amin is None:
                non_breaking.append(f"{k}_removed")

    # maximum: lower => narrower (breaking), higher => wider (non-breaking)
    for k in ("maximum", "exclusiveMaximum"):
        if k in b or k in a:
            bmax = b.get(k)
            amax = a.get(k)
            if isinstance(bmax, (int, float)) and isinstance(amax, (int, float)):
                if amax < bmax:
                    breaking.append(f"{k}_tightened")
                elif amax > bmax:
                    non_breaking.append(f"{k}_widened")
            elif bmax is None and isinstance(amax, (int, float)):
                breaking.append(f"{k}_added")
            elif isinstance(bmax, (int, float)) and amax is None:
                non_breaking.append(f"{k}_removed")

    # multipleOf: adding is narrowing; removing is widening; changing is unknown unless divisible
    if "multipleOf" in b or "multipleOf" in a:
        bm = b.get("multipleOf")
        am = a.get("multipleOf")
        if isinstance(bm, (int, float)) and isinstance(am, (int, float)):
            if am == bm:
                return
            # If am is a multiple of bm, it's narrowing (fewer valid numbers)
            try:
                if (am / bm).is_integer():
                    breaking.append("multipleOf_tightened")
                elif (bm / am).is_integer():
                    non_breaking.append("multipleOf_widened")
                else:
                    unknown.append("multipleOf_changed")
            except Exception:
                unknown.append("multipleOf_changed")
        elif bm is None and isinstance(am, (int, float)):
            breaking.append("multipleOf_added")
        elif isinstance(bm, (int, float)) and am is None:
            non_breaking.append("multipleOf_removed")


def _compare_string_constraints(
    b: Dict[str, Any],
    a: Dict[str, Any],
    breaking: List[str],
    non_breaking: List[str],
    unknown: List[str],
    *,
    treat_format_as_semantic: bool,
    treat_pattern_as_semantic: bool,
) -> None:
    # minLength: higher => narrower
    if "minLength" in b or "minLength" in a:
        bm = b.get("minLength")
        am = a.get("minLength")
        if isinstance(bm, int) and isinstance(am, int):
            if am > bm:
                breaking.append("minLength_tightened")
            elif am < bm:
                non_breaking.append("minLength_widened")
        elif bm is None and isinstance(am, int):
            breaking.append("minLength_added")
        elif isinstance(bm, int) and am is None:
            non_breaking.append("minLength_removed")

    # maxLength: lower => narrower
    if "maxLength" in b or "maxLength" in a:
        bx = b.get("maxLength")
        ax = a.get("maxLength")
        if isinstance(bx, int) and isinstance(ax, int):
            if ax < bx:
                breaking.append("maxLength_tightened")
            elif ax > bx:
                non_breaking.append("maxLength_widened")
        elif bx is None and isinstance(ax, int):
            breaking.append("maxLength_added")
        elif isinstance(bx, int) and ax is None:
            non_breaking.append("maxLength_removed")

    if treat_pattern_as_semantic and ("pattern" in b or "pattern" in a):
        if b.get("pattern") != a.get("pattern"):
            unknown.append("pattern_changed")

    if treat_format_as_semantic and ("format" in b or "format" in a):
        if b.get("format") != a.get("format"):
            unknown.append("format_changed")


def _compare_object_constraints(
    b: Dict[str, Any],
    a: Dict[str, Any],
    breaking: List[str],
    non_breaking: List[str],
    unknown: List[str],
) -> None:
    b_req = set(b.get("required") or []) if isinstance(b.get("required"), list) else set()
    a_req = set(a.get("required") or []) if isinstance(a.get("required"), list) else set()
    if a_req != b_req:
        if a_req.issuperset(b_req) and a_req != b_req:
            breaking.append("required_keys_added")
        elif a_req.issubset(b_req) and a_req != b_req:
            non_breaking.append("required_keys_removed")
        else:
            unknown.append("required_keys_changed")

    b_props = b.get("properties") if isinstance(b.get("properties"), dict) else {}
    a_props = a.get("properties") if isinstance(a.get("properties"), dict) else {}

    # Adding properties is usually non-breaking; removing properties can be breaking if required.
    # Here we only classify explicit removals as breaking if the removed key was required.
    removed = set(b_props.keys()) - set(a_props.keys())
    added = set(a_props.keys()) - set(b_props.keys())
    if added:
        non_breaking.append("properties_added")
    if removed:
        # If any removed prop was required in before, it's breaking.
        if any(k in b_req for k in removed):
            breaking.append("required_property_removed")
        else:
            # Optional property removal is often breaking for consumers but not strictly per schema;
            # keep it unknown (Scope 3 conservative).
            unknown.append("optional_property_removed")

    # additionalProperties tightening:
    if "additionalProperties" in b or "additionalProperties" in a:
        bap = b.get("additionalProperties")
        aap = a.get("additionalProperties")
        if isinstance(bap, bool) and isinstance(aap, bool):
            if bap is True and aap is False:
                breaking.append("additionalProperties_tightened")
            elif bap is False and aap is True:
                non_breaking.append("additionalProperties_widened")
        elif bap != aap:
            # Schema-vs-bool or schema change: too complex; unknown
            unknown.append("additionalProperties_changed")


def _compare_array_constraints(
    b: Dict[str, Any],
    a: Dict[str, Any],
    breaking: List[str],
    non_breaking: List[str],
    unknown: List[str],
) -> None:
    # minItems: higher => narrower
    if "minItems" in b or "minItems" in a:
        bm = b.get("minItems")
        am = a.get("minItems")
        if isinstance(bm, int) and isinstance(am, int):
            if am > bm:
                breaking.append("minItems_tightened")
            elif am < bm:
                non_breaking.append("minItems_widened")
        elif bm is None and isinstance(am, int):
            breaking.append("minItems_added")
        elif isinstance(bm, int) and am is None:
            non_breaking.append("minItems_removed")

    # maxItems: lower => narrower
    if "maxItems" in b or "maxItems" in a:
        bx = b.get("maxItems")
        ax = a.get("maxItems")
        if isinstance(bx, int) and isinstance(ax, int):
            if ax < bx:
                breaking.append("maxItems_tightened")
            elif ax > bx:
                non_breaking.append("maxItems_widened")
        elif bx is None and isinstance(ax, int):
            breaking.append("maxItems_added")
        elif isinstance(bx, int) and ax is None:
            non_breaking.append("maxItems_removed")

    if "uniqueItems" in b or "uniqueItems" in a:
        bu = b.get("uniqueItems")
        au = a.get("uniqueItems")
        if isinstance(bu, bool) and isinstance(au, bool) and bu != au:
            # uniqueItems true is more restrictive than false
            if bu is False and au is True:
                breaking.append("uniqueItems_tightened")
            elif bu is True and au is False:
                non_breaking.append("uniqueItems_widened")

    # items: if different, we can attempt a recursive compare only if both are dicts and neither has composition.
    b_items = b.get("items")
    a_items = a.get("items")
    if isinstance(b_items, dict) or isinstance(a_items, dict):
        if b_items == a_items:
            return
        # Too complex to recurse here without context/policy; treat unknown for now.
        unknown.append("items_changed")
