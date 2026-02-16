#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROTATION = Path(".github/oncall_rotation.json")
SCHEMA = Path(".github/oncall_rotation.schema.json")


def die(msg: str) -> int:
    print(msg)
    return 1


def main() -> int:
    if not ROTATION.exists():
        return die(f"Missing {ROTATION}")
    if not SCHEMA.exists():
        return die(f"Missing {SCHEMA}")

    try:
        instance = json.loads(ROTATION.read_text(encoding="utf-8"))
    except Exception as e:
        return die(f"Invalid JSON in {ROTATION}: {e}")

    try:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    except Exception as e:
        return die(f"Invalid JSON in {SCHEMA}: {e}")

    try:
        from jsonschema import Draft202012Validator
    except Exception:
        return die(
            "Missing dependency: jsonschema\n"
            "Install: python -m pip install jsonschema\n"
            "CI: add jsonschema to your workflow install step."
        )

    v = Draft202012Validator(schema)
    errors = sorted(v.iter_errors(instance), key=lambda e: e.json_path)
    if errors:
        print(f"Schema validation failed for {ROTATION}:")
        for e in errors[:50]:
            loc = e.json_path or "$"
            print(f"- {loc}: {e.message}")
        if len(errors) > 50:
            print(f"...and {len(errors) - 50} more")
        return 1

    print("oncall rotation schema OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
