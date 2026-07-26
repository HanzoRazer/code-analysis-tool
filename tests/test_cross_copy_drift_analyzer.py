"""Unit tests for the cross-copy / vendored-drift detector.

Flags a file existing byte-identical (LF-normalized) at 2+ paths — an undeclared
copy that can drift. v1 records authority_declared_confirmed=False for the v2 pass.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.cross_copy_drift import CrossCopyDriftAnalyzer
from code_audit.model import AnalyzerType, Severity

# Substantial content (> the 200-byte floor).
_BODY = "{\n" + ",\n".join(f'  "field_{i}": "value_{i}"' for i in range(20)) + "\n}\n"


def _run(root: Path):
    py = [p for p in root.rglob("*.py")]
    return CrossCopyDriftAnalyzer().run(root, py)


def test_identical_files_flagged(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "schema.json").write_text(_BODY, encoding="utf-8")
    (tmp_path / "b" / "schema.json").write_text(_BODY, encoding="utf-8")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.CROSS_COPY_DRIFT
    assert f[0].severity is Severity.LOW
    assert set(f[0].metadata["copy_paths"]) == {"a/schema.json", "b/schema.json"}
    assert f[0].metadata["copy_count"] == 2
    assert f[0].metadata["authority_declared_confirmed"] is False
    assert f[0].finding_id


def test_crlf_vs_lf_copy_still_flagged(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "s.json").write_bytes(_BODY.encode("utf-8"))
    (tmp_path / "b" / "s.json").write_bytes(_BODY.replace("\n", "\r\n").encode("utf-8"))
    f = _run(tmp_path)
    assert len(f) == 1  # differ only by line ending → still the same file


def test_different_content_not_flagged(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "s.json").write_text(_BODY, encoding="utf-8")
    (tmp_path / "b" / "s.json").write_text(_BODY + '{"extra": 1}\n', encoding="utf-8")
    assert _run(tmp_path) == []


def test_trivially_small_identical_not_flagged(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "c.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "b" / "c.json").write_text("{}\n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_init_py_not_flagged(tmp_path):
    body = "import os\n" + "\n".join(f"X_{i} = {i}" for i in range(40)) + "\n"
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "__init__.py").write_text(body, encoding="utf-8")
    (tmp_path / "b" / "__init__.py").write_text(body, encoding="utf-8")
    assert _run(tmp_path) == []


def test_duplication_only_within_tests_not_flagged(tmp_path):
    t = tmp_path / "tests" / "fixtures"
    (t / "a").mkdir(parents=True)
    (t / "b").mkdir(parents=True)
    (t / "a" / "case.json").write_text(_BODY, encoding="utf-8")
    (t / "b" / "case.json").write_text(_BODY, encoding="utf-8")
    assert _run(tmp_path) == []


def test_source_and_test_copy_is_flagged(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "s.json").write_text(_BODY, encoding="utf-8")
    (tmp_path / "tests" / "s.json").write_text(_BODY, encoding="utf-8")
    # crosses into real source → authority drift risk → flagged.
    assert len(_run(tmp_path)) == 1


def test_excluded_dir_copy_not_flagged(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "src" / "s.json").write_text(_BODY, encoding="utf-8")
    (tmp_path / "node_modules" / "pkg" / "s.json").write_text(_BODY, encoding="utf-8")
    # node_modules is pruned → the src copy stands alone → no duplication.
    assert _run(tmp_path) == []


def test_single_file_no_finding(tmp_path):
    (tmp_path / "s.json").write_text(_BODY, encoding="utf-8")
    assert _run(tmp_path) == []


def test_three_way_copy_lists_all(tmp_path):
    for d in ("a", "b", "c"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "m.json").write_text(_BODY, encoding="utf-8")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["copy_count"] == 3
