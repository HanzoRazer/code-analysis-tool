"""Generate a governed drift_budget_signal_v1 JSON artifact.

Reads episode state from a structured handoff JSON file and writes
a deterministic, schema-compliant JSON file.

Usage (CI):
    python scripts/generate_drift_budget_signal.py \\
        --in  artifacts/drift_budget_handoff.json \\
        --out artifacts/drift_budget_signal.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _require(data: dict, key: str) -> str:
    val = data.get(key)
    if val is None:
        raise SystemExit(f"error: missing required field '{key}'")
    return str(val).strip()


def _require_int(data: dict, key: str, default: int = 0) -> int:
    raw = data.get(key, default)
    try:
        return int(raw)
    except (ValueError, TypeError):
        print(f"warning: {key}={raw!r} is not an integer, using default={default}", file=sys.stderr)
        return default


def _require_bool(data: dict, key: str, default: bool = False) -> bool:
    raw = data.get(key, default)
    if isinstance(raw, bool):
        return raw
    s = str(raw).lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no", ""):
        return default
    return default


def _human_duration(seconds: int) -> str:
    """Deterministic human-readable duration: '2d 1h 1m', '0m'."""
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def build_signal(handoff: dict) -> dict:
    """Build the drift_budget_signal_v1 payload from a handoff dict."""
    producer = handoff.get("producer", {})
    episode = handoff.get("episode", {})
    provenance = handoff.get("provenance", {})
    rotation = provenance.get("rotation", {})

    unresolved_sec = _require_int(episode, "unresolved_seconds", 0)

    return {
        "schema_version": "drift_budget_signal_v1",
        "producer": {
            "repo": _require(producer, "repo"),
            "workflow": _require(producer, "workflow"),
            "run_id": _require(producer, "run_id"),
            "run_attempt": _require_int(producer, "run_attempt", 1),
            "run_url": _require(producer, "run_url"),
            "sha": _require(producer, "sha"),
        },
        "episode": {
            "group_key": _require(episode, "group_key"),
            "first_detected_iso": _require(episode, "first_detected_iso"),
            "last_resolved_iso": episode.get("last_resolved_iso") or None,
            "status": _require(episode, "status"),
            "unresolved_seconds": unresolved_sec,
            "unresolved_human": _human_duration(unresolved_sec),
            "budget_hours": _require_int(episode, "budget_hours", 48),
            "breached": _require_bool(episode, "breached", False),
            "breach_seconds": _require_int(episode, "breach_seconds", 0),
        },
        "provenance": {
            "ci_mode": _require_bool(provenance, "ci_mode", False),
            "rotation": {
                "config_sha12": _require(rotation, "config_sha12"),
                "schema_sha12": _require(rotation, "schema_sha12"),
                "schema_version": _require(rotation, "schema_version"),
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate drift_budget_signal_v1 artifact")
    parser.add_argument("--in", dest="infile", required=True, help="Handoff JSON input path")
    parser.add_argument("--out", required=True, help="Output path for JSON artifact")
    args = parser.parse_args()

    handoff_path = Path(args.infile)
    if not handoff_path.exists():
        print(f"error: handoff file not found: {handoff_path}", file=sys.stderr)
        return 1

    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    signal = build_signal(handoff)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(signal, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
