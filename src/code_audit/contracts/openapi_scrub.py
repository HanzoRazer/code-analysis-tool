"""OpenAPI golden fixture volatility scrubber.

Recursively walks JSON objects and removes volatile fields (timestamps,
UUIDs, request IDs, durations, etc.) before they can enter golden
fixtures.  Both the fixture *refresh* script and the fixture *compare*
test import this module so the same deterministic normalisation is
applied on both sides.

Policy is loaded from ``tests/contracts/openapi_golden_scrub_policy.json``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple


@dataclass(frozen=True)
class ScrubPolicy:
    """Declarative scrub policy loaded from JSON."""

    mode: str  # "remove" or "fail"
    volatile_key_patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    volatile_value_patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    allowlist_paths: frozenset[str] = field(default_factory=frozenset)
    allowlist_keys: frozenset[str] = field(default_factory=frozenset)


class ScrubEvent(NamedTuple):
    """A single volatile-field removal recorded during scrubbing."""

    json_path: str
    key: str
    value_preview: str
    reason: str


# ── loader ───────────────────────────────────────────────────────


def load_scrub_policy(path: Path) -> ScrubPolicy:
    """Parse a scrub-policy JSON file into a ``ScrubPolicy``."""
    data = json.loads(path.read_text(encoding="utf-8"))

    ver = data.get("version")
    if ver != 1:
        raise ValueError(f"Unsupported scrub policy version {ver!r} (expected 1)")

    mode = str(data.get("mode") or "remove").strip().lower()
    if mode not in ("remove", "fail"):
        raise ValueError(f"Scrub policy mode must be 'remove' or 'fail', got {mode!r}")

    key_pats = tuple(
        re.compile(p, flags=re.IGNORECASE)
        for p in (data.get("volatile_key_patterns") or [])
    )
    val_pats = tuple(
        re.compile(p)
        for p in (data.get("volatile_value_patterns") or [])
    )
    allowlist_paths = frozenset(data.get("allowlist_paths") or [])
    allowlist_keys = frozenset(
        k.strip() for k in (data.get("allowlist_keys") or []) if k and k.strip()
    )

    return ScrubPolicy(
        mode=mode,
        volatile_key_patterns=key_pats,
        volatile_value_patterns=val_pats,
        allowlist_paths=allowlist_paths,
        allowlist_keys=allowlist_keys,
    )


# ── internals ────────────────────────────────────────────────────


def _path_join(base: str, token: str) -> str:
    if base == "":
        return f"/{token}"
    return f"{base}/{token}"


def _is_volatile_key(policy: ScrubPolicy, key: str) -> bool:
    if key in policy.allowlist_keys:
        return False
    return any(p.search(key) for p in policy.volatile_key_patterns)


def _is_volatile_value(policy: ScrubPolicy, value: Any) -> bool:
    if isinstance(value, str):
        return any(p.search(value) for p in policy.volatile_value_patterns)
    return False


# ── public API ───────────────────────────────────────────────────


def scrub_json(
    obj: Any,
    policy: ScrubPolicy,
    path: str = "",
    events: list[ScrubEvent] | None = None,
) -> Any:
    """Recursively scrub *obj* according to *policy*.

    * Dict keys matching ``volatile_key_patterns`` (or whose values match
      ``volatile_value_patterns``) are **removed** unless allowlisted by
      exact path or key name.
    * In ``fail`` mode a ``ValueError`` is raised instead of silently
      removing.
    * Lists are traversed by index, preserving order.
    * Scalars pass through unchanged.
    * If *events* is provided, each removal is recorded as a
      ``ScrubEvent`` so callers can build audit reports.
    """
    if events is None:
        events = []

    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            k_str = str(k)
            child_path = _path_join(path, k_str)

            # Allowlist takes precedence — always keep.
            if child_path in policy.allowlist_paths or k_str in policy.allowlist_keys:
                out[k_str] = scrub_json(v, policy, child_path, events)
                continue

            volatile_key = _is_volatile_key(policy, k_str)
            volatile_val = _is_volatile_value(policy, v)
            volatile = volatile_key or volatile_val
            if volatile:
                if policy.mode == "fail":
                    raise ValueError(
                        f"Volatile field detected at {child_path}: "
                        f"key={k_str!r} value={v!r}"
                    )
                reason = "volatile_key_pattern" if volatile_key else "volatile_value_pattern"
                preview = repr(v)
                if len(preview) > 120:
                    preview = preview[:117] + "..."
                events.append(ScrubEvent(
                    json_path=child_path,
                    key=k_str,
                    value_preview=preview,
                    reason=reason,
                ))
                # "remove" mode — drop
                continue

            out[k_str] = scrub_json(v, policy, child_path, events)
        return out

    if isinstance(obj, list):
        return [
            scrub_json(v, policy, _path_join(path, str(i)), events)
            for i, v in enumerate(obj)
        ]

    # Scalars pass through.
    return obj
