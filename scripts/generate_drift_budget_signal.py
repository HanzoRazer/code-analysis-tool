"""Generate a governed drift_budget_signal_v1 JSON artifact.

Reads episode state from environment variables (set by the observer workflow)
and writes a deterministic, schema-compliant JSON file.

Usage (CI):
    python scripts/generate_drift_budget_signal.py --out artifacts/drift_budget_signal.json

All inputs come from environment variables — no "current time" drift.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _env_int(key: str, default: int = 0) -> int:
    raw = _env(key)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"warning: {key}={raw!r} is not an integer, using default={default}", file=sys.stderr)
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    raw = _env(key).lower()
    if raw in ("true", "1", "yes"):
        return True
    if raw in ("false", "0", "no", ""):
        return default
    return default


def build_signal() -> dict:
    """Build the drift_budget_signal_v1 payload from environment variables."""

    repo = _env("GITHUB_REPOSITORY", "unknown/unknown")
    server_url = _env("GITHUB_SERVER_URL", "https://github.com")
    run_id = _env("GITHUB_RUN_ID", "0")
    run_attempt = _env_int("GITHUB_RUN_ATTEMPT", 1)
    sha = _env("GITHUB_SHA", "0000000")

    run_url = f"{server_url}/{repo}/actions/runs/{run_id}"

    return {
        "schema_version": "drift_budget_signal_v1",
        "producer": {
            "repo": repo,
            "workflow": "contract-parity-main-observer",
            "run_id": run_id,
            "run_attempt": run_attempt,
            "run_url": run_url,
            "sha": sha,
        },
        "episode": {
            "group_key": _env("DRIFT_GROUP_KEY", "contracts"),
            "first_detected_iso": _env("DRIFT_FIRST_DETECTED_ISO", "unknown"),
            "last_resolved_iso": _env("DRIFT_LAST_RESOLVED_ISO") or None,
            "status": _env("DRIFT_STATUS", "unresolved"),
            "unresolved_seconds": _env_int("DRIFT_UNRESOLVED_SECONDS", 0),
            "unresolved_human": _env("DRIFT_UNRESOLVED_HUMAN", "0s"),
            "budget_hours": _env_int("DRIFT_BUDGET_HOURS", 48),
            "breached": _env_bool("DRIFT_BREACHED", False),
            "breach_seconds": _env_int("DRIFT_BREACH_SECONDS", 0),
        },
        "provenance": {
            "ci_mode": _env_bool("CI", False),
            "rotation": {
                "config_sha12": _env("DRIFT_ROTATION_SHA12", "000000000000"),
                "schema_sha12": _env("DRIFT_SCHEMA_SHA12", "000000000000"),
                "schema_version": _env("DRIFT_ROTATION_SCHEMA_VERSION", "oncall_rotation_schema_v1"),
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate drift_budget_signal_v1 artifact")
    parser.add_argument("--out", required=True, help="Output path for JSON artifact")
    args = parser.parse_args()

    signal = build_signal()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(signal, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
