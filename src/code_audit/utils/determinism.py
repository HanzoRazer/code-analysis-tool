"""Determinism utilities for CI-reproducible output.

When --ci / --deterministic mode is enabled:
- Timestamps are fixed to a known epoch
- Run IDs are derived from repo content hash
- Paths are normalized and sorted
- Random seeds are fixed
- Floating point values are rounded

This ensures identical JSON output across machines and runs.
"""

from __future__ import annotations

import hashlib
import os
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

# Fixed timestamp for CI mode (ISO 8601 with timezone)
FIXED_TIMESTAMP = "2000-01-01T00:00:00+00:00"

# Fixed seed for random number generators
FIXED_SEED = 42

# Module-level state for ci_mode (set by CLI)
_ci_mode: bool = False


def set_ci_mode(enabled: bool) -> None:
    """Set the global CI mode flag.

    Called by CLI when --ci or --deterministic is passed.
    """
    global _ci_mode
    _ci_mode = enabled


def is_ci_mode(args: Any | None = None) -> bool:
    """Check if CI/deterministic mode is enabled.

    Checks in order:
    1. Explicit args.ci_mode if provided
    2. Environment variable CI_MODE=1 or DETERMINISTIC=1
    3. Global _ci_mode state (set by CLI)
    """
    # Check args first
    if args is not None and hasattr(args, "ci_mode"):
        return bool(args.ci_mode)

    # Check environment
    if os.environ.get("CI_MODE", "").lower() in ("1", "true", "yes"):
        return True
    if os.environ.get("DETERMINISTIC", "").lower() in ("1", "true", "yes"):
        return True

    # Fall back to global state
    return _ci_mode


def seed_random(ci_mode: bool = False) -> None:
    """Seed the random module for deterministic ML/sampling.

    In CI mode, uses FIXED_SEED. Otherwise uses system entropy.
    """
    if ci_mode or is_ci_mode():
        random.seed(FIXED_SEED)
    else:
        random.seed()  # System entropy


def deterministic_timestamp(ci_mode: bool = False) -> str:
    """Return a timestamp string.

    In CI mode, returns FIXED_TIMESTAMP.
    Otherwise returns current UTC time in ISO 8601 format.
    """
    if ci_mode or is_ci_mode():
        return FIXED_TIMESTAMP
    return datetime.now(timezone.utc).isoformat()


def deterministic_run_id(root: Path, ci_mode: bool = False) -> str:
    """Generate a run ID.

    In CI mode, derives ID from repo content hash for reproducibility.
    Otherwise generates a UUID-based ID.
    """
    if ci_mode or is_ci_mode():
        # Hash the repo root path (normalized) for reproducibility
        # In a real implementation, you might hash file contents too
        normalized = normalize_path(root.resolve(), root.resolve())
        content = normalized.encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()[:16]
        return f"ci-{digest}"
    else:
        import uuid
        return f"run-{uuid.uuid4().hex[:16]}"


def normalize_path(path: Path, root: Path) -> str:
    """Convert a path to repo-relative, POSIX-normalized string.

    Ensures consistent paths across Windows/Linux/macOS.
    """
    try:
        # Make relative to root
        rel = path.resolve().relative_to(root.resolve())
        # Convert to POSIX style (forward slashes)
        return rel.as_posix()
    except ValueError:
        # Path is not under root, return absolute POSIX
        return path.resolve().as_posix()


def round_float(value: float, places: int = 4) -> float:
    """Round a float to fixed decimal places for stability.

    Prevents floating point representation differences across platforms.
    """
    return round(value, places)


T = TypeVar("T")


def sort_items(
    items: list[T],
    key: Callable[[T], Any] | None = None,
) -> list[T]:
    """Sort items for deterministic output ordering.

    Returns a new sorted list. Original is not modified.
    """
    return sorted(items, key=key)


def sort_findings(findings: list[Any], root: Path | None = None) -> list[Any]:
    """Sort findings by (path, line_start, rule_id) for determinism."""
    def key(f: Any) -> tuple:
        path = getattr(f, "path", "") or ""
        if root and isinstance(path, Path):
            path = normalize_path(path, root)
        elif isinstance(path, Path):
            path = path.as_posix()
        line = getattr(f, "line_start", 0) or 0
        rule = getattr(f, "rule_id", "") or getattr(f, "finding_id", "") or ""
        return (str(path), line, rule)
    return sorted(findings, key=key)


def sort_signals(signals: list[dict]) -> list[dict]:
    """Sort signals by (signal_id, severity) for determinism."""
    def key(s: dict) -> tuple:
        return (s.get("signal_id", ""), s.get("severity", ""))
    return sorted(signals, key=key)


def sort_debt_items(items: list[Any]) -> list[Any]:
    """Sort debt items by (path, line_start, symbol) for determinism."""
    def key(d: Any) -> tuple:
        path = getattr(d, "path", "") or ""
        if isinstance(path, Path):
            path = path.as_posix()
        line = getattr(d, "line_start", 0) or 0
        symbol = getattr(d, "symbol", "") or ""
        return (str(path), line, symbol)
    return sorted(items, key=key)


def make_deterministic_dict(
    data: dict,
    ci_mode: bool = False,
    timestamp_keys: tuple[str, ...] = ("created_at", "timestamp", "computed_at"),
    float_keys: tuple[str, ...] = ("confidence_score", "score", "value"),
) -> dict:
    """Process a dict for deterministic output.

    - Replaces timestamp values with FIXED_TIMESTAMP if ci_mode
    - Rounds float values for stability
    - Sorts dict keys for consistent ordering
    """
    if not ci_mode and not is_ci_mode():
        return data

    result = {}
    for key in sorted(data.keys()):
        value = data[key]

        if key in timestamp_keys and isinstance(value, str):
            result[key] = FIXED_TIMESTAMP
        elif key in float_keys and isinstance(value, (int, float)):
            result[key] = round_float(float(value))
        elif isinstance(value, dict):
            result[key] = make_deterministic_dict(
                value, ci_mode=True,
                timestamp_keys=timestamp_keys,
                float_keys=float_keys,
            )
        elif isinstance(value, list):
            result[key] = [
                make_deterministic_dict(v, ci_mode=True, timestamp_keys=timestamp_keys, float_keys=float_keys)
                if isinstance(v, dict) else v
                for v in value
            ]
        else:
            result[key] = value

    return result
