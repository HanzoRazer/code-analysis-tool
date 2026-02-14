"""Guardrail: no direct json.dump / json.dumps in Supported command paths.

All JSON serialisation in Supported v1 surface MUST flow through
``stable_json_dump`` / ``stable_json_dumps`` (from ``code_audit.utils.json_norm``).

This test will fail if anyone reintroduces raw ``json.dump(`` or
``json.dumps(`` calls in the listed files — preventing silent format drift.
"""

from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

SUPPORTED_FILES = [
    REPO_ROOT / "src" / "code_audit" / "__main__.py",
    REPO_ROOT / "src" / "code_audit" / "core" / "runner.py",
]


def test_supported_paths_do_not_use_json_dump_directly() -> None:
    pat = re.compile(r"\bjson\.dumps?\(")
    bad: list[tuple[str, int]] = []
    for p in SUPPORTED_FILES:
        text = p.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                bad.append((str(p), lineno))
    assert not bad, f"Direct json.dump/json.dumps found in supported paths: {bad}"
