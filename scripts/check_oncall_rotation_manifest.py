#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from datetime import date


ROTATION_PATH = Path(".github/oncall_rotation.json")
MANIFEST_PATH = Path(".github/oncall_rotation.manifest.json")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def die(msg: str) -> int:
    print(msg)
    return 1


def parse_ymd(s: str) -> date | None:
    try:
        y, m, d = s.split("-")
        return date(int(y), int(m), int(d))
    except Exception:
        return None


def main() -> int:
    if not ROTATION_PATH.exists():
        return die(f"Missing {ROTATION_PATH}")
    if not MANIFEST_PATH.exists():
        return die(f"Missing {MANIFEST_PATH} (run scripts/refresh_oncall_rotation_manifest.py)")

    try:
        rotation = json.loads(ROTATION_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        return die(f"Invalid JSON in {ROTATION_PATH}: {e}")

    rot = rotation.get("rotation")
    if not isinstance(rot, list) or not rot:
        return die("oncall_rotation.json must contain non-empty array: rotation")

    strategy = rotation.get("strategy", "daily")
    if strategy not in ("daily", "weekly"):
        return die("strategy must be 'daily' or 'weekly'")

    week_start = rotation.get("week_start")
    if strategy == "weekly":
        if not isinstance(week_start, str) or not week_start.strip():
            return die("week_start is required when strategy='weekly'")
        if week_start.lower() not in (
            "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
        ):
            return die("week_start must be one of monday..sunday")

    cleaned: list[str] = []
    for i, v in enumerate(rot):
        if not isinstance(v, str) or not v.strip():
            return die(f"rotation[{i}] must be a non-empty string")
        s = v.strip()
        if s.startswith("@"):
            return die(f"rotation[{i}] must not start with '@' (got {s})")
        cleaned.append(s)

    if len(set(cleaned)) != len(cleaned):
        return die("rotation entries must be unique (duplicates found)")

    exc = rotation.get("exceptions", [])
    if exc is not None:
        if not isinstance(exc, list):
            return die("exceptions must be an array if present")
        parsed_ranges: list[tuple[date, date]] = []
        for i, e in enumerate(exc):
            if not isinstance(e, dict):
                return die(f"exceptions[{i}] must be an object")
            start = e.get("start")
            end = e.get("end")
            assignee = e.get("assignee")
            priority = e.get("priority", 1000)
            if not isinstance(start, str) or not isinstance(end, str):
                return die(f"exceptions[{i}] must include 'start' and 'end' as YYYY-MM-DD strings")
            ds = parse_ymd(start)
            de = parse_ymd(end)
            if ds is None or de is None:
                return die(f"exceptions[{i}] start/end must be YYYY-MM-DD (got start={start}, end={end})")
            if ds > de:
                return die(f"exceptions[{i}] invalid range: start > end ({start} > {end})")
            if not isinstance(assignee, str) or not assignee.strip():
                return die(f"exceptions[{i}] must include non-empty 'assignee'")
            if assignee.strip().startswith("@"):
                return die(f"exceptions[{i}] assignee must not start with '@' (got {assignee.strip()})")
            if not isinstance(priority, int):
                return die(f"exceptions[{i}] priority must be an int if present (got {type(priority).__name__})")
            parsed_ranges.append((ds, de))

        # Overlaps allowed ("most specific wins"). Optional hygiene warning:
        # If two exceptions overlap and have identical inclusive length, the picker will tie-break
        # deterministically (start/end/assignee), but this is often unintended.
        # We warn (do not fail) to keep CI flexible.
        parsed_ranges.sort()
        warnings: list[str] = []
        for i in range(len(parsed_ranges)):
            s1, e1 = parsed_ranges[i]
            len1 = (e1 - s1).days + 1
            for j in range(i + 1, len(parsed_ranges)):
                s2, e2 = parsed_ranges[j]
                if s2 > e1:
                    break
                # overlap exists
                len2 = (e2 - s2).days + 1
                if len1 == len2:
                    warnings.append(
                        f"warning: overlapping exceptions with same length: {s1.isoformat()}..{e1.isoformat()} "
                        f"and {s2.isoformat()}..{e2.isoformat()}"
                    )
        for w in warnings:
            print(w)

    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        return die(f"Invalid JSON in {MANIFEST_PATH}: {e}")

    expected = manifest.get("sha256")
    actual = sha256_file(ROTATION_PATH)
    if expected != actual:
        return die(
            "Oncall rotation file changed without refreshing manifest.\n"
            f"Expected sha256={expected}\n"
            f"Actual   sha256={actual}\n"
            "Fix: python scripts/refresh_oncall_rotation_manifest.py"
        )

    print("oncall rotation manifest OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
