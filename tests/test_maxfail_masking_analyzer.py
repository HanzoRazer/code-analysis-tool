"""Unit tests for the maxfail-masking detector.

Flags test/CI config that runs fail-fast (--maxfail/-x/--exitfirst), which hides
the true failure set. v1 scans config surfaces and records
``collect_all_escape_confirmed=False`` for the v2 enrichment pass.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.maxfail_masking import MaxfailMaskingAnalyzer
from code_audit.model import AnalyzerType, Severity


def _run(root: Path):
    return MaxfailMaskingAnalyzer().run(root, [])


def test_pyproject_addopts_maxfail_flagged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        'addopts = """\n'
        "-q\n"
        "--maxfail=1\n"
        '"""\n',
        encoding="utf-8",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.MAXFAIL_MASKING
    assert "--maxfail" in f[0].metadata["fail_fast_flags"]
    assert f[0].metadata["collect_all_escape_confirmed"] is False
    assert f[0].severity is Severity.LOW
    assert f[0].finding_id  # non-empty (schema minLength)
    assert f[0].location.path == "pyproject.toml"


def test_maxfail_zero_not_flagged(tmp_path):
    # --maxfail=0 means "no limit" — not fail-fast.
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "--maxfail=0"\n', encoding="utf-8"
    )
    assert _run(tmp_path) == []


def test_exitfirst_flagged(tmp_path):
    (tmp_path / "setup.cfg").write_text(
        "[tool:pytest]\naddopts = --exitfirst -q\n", encoding="utf-8"
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert "--exitfirst" in f[0].metadata["fail_fast_flags"]


def test_ini_maxfail_option_flagged(tmp_path):
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\nmaxfail = 2\n", encoding="utf-8"
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert "maxfail" in f[0].metadata["fail_fast_flags"]


def test_ci_workflow_pytest_dash_x_flagged(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: python -m pytest -x -q\n",
        encoding="utf-8",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert "-x" in f[0].metadata["fail_fast_flags"]
    assert f[0].location.path == ".github/workflows/ci.yml"


def test_clean_config_no_finding(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "-q --strict-markers"\n',
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_maxfail_in_comment_not_flagged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        "# we deliberately avoid --maxfail here\n"
        'addopts = "-q"\n',
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_bare_dash_x_not_pytest_not_flagged(tmp_path):
    # -x unrelated to pytest (e.g. a curl flag) must not trip the detector.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n      - run: curl -x proxy https://x\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_no_config_files_no_finding(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert _run(tmp_path) == []
