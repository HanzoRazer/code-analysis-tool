"""Tests for the canonical JSON normalization layer."""

import json
from pathlib import Path

from code_audit.utils.json_norm import stable_json_dumps, stable_json_dump


def test_stable_json_dumps_sorts_keys_and_adds_newline():
    s = stable_json_dumps({"b": 1, "a": 2})
    assert s.endswith("\n")
    # Keys should be sorted in the serialized output
    assert s.index('"a"') < s.index('"b"')


def test_stable_json_dumps_rounds_floats_in_ci_mode():
    s = stable_json_dumps({"x": 1.234567}, ci_mode=True)
    obj = json.loads(s)
    assert obj["x"] == 1.2346


def test_stable_json_dumps_normalizes_paths():
    s = stable_json_dumps({"p": Path("a") / "b"})
    obj = json.loads(s)
    assert obj["p"] == "a/b"


def test_stable_json_dump_writes_to_file_like(tmp_path):
    out = tmp_path / "x.json"
    with out.open("w", encoding="utf-8") as f:
        stable_json_dump({"b": 1, "a": 2}, f)
    txt = out.read_text(encoding="utf-8")
    assert txt.endswith("\n")
    assert '"a"' in txt and '"b"' in txt
