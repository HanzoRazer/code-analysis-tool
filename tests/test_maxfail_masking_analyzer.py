"""Unit tests for the maxfail-masking detector.

Flags test/CI config that runs fail-fast (--maxfail/-x/--exitfirst), which hides
the true failure set. v2 looks for a companion collect-all escape and downgrades
when one is confirmed.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.maxfail_masking import MaxfailMaskingAnalyzer
from code_audit.model import AnalyzerType, Severity


def _run(root: Path):
    return MaxfailMaskingAnalyzer().run(root, [])


def _wf(root: Path, name: str, body: str) -> None:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(body, encoding="utf-8")


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


# ── hardening: combined short flags, chained commands, value capture ──


def test_combined_short_flag_xvs_flagged(tmp_path):
    # `-xvs` == `-x -v -s`; the common way pytest -x is written. Must be caught.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - run: python -m pytest -xvs\n",
        encoding="utf-8",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert "-x" in f[0].metadata["fail_fast_flags"]


def test_chained_ssh_dash_x_after_pytest_not_flagged(tmp_path):
    # -x belongs to ssh (a later chained command), not pytest — false positive.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - run: pytest tests && ssh -x host\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_yaml_list_item_dash_not_treated_as_flag(tmp_path):
    # The `- run:` YAML dash must not make an unrelated `-x` look like a flag line.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - run: curl -x proxy https://example\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_multiline_addopts_bare_dash_x_flagged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        'addopts = """\n'
        "-x\n"
        "-q\n"
        '"""\n',
        encoding="utf-8",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert "-x" in f[0].metadata["fail_fast_flags"]


def test_maxfail_value_recorded_and_field_cleaned(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "--maxfail=3"\n', encoding="utf-8"
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["maxfail_value"] == 3
    # the misapplied context_confirmed placeholder was removed; the meaningful
    # v2 flag for this detector is collect_all_escape_confirmed.
    assert "context_confirmed" not in f[0].metadata
    assert f[0].metadata["collect_all_escape_confirmed"] is False


def test_uppercase_workflow_extension_scanned(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.YML").write_text(
        "steps:\n  - run: pytest --maxfail=1\n", encoding="utf-8"
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert "--maxfail" in f[0].metadata["fail_fast_flags"]


# ── v2: collect-all escape enrichment ───────────────────────────────


def test_collect_all_escape_via_addopts_override_downgrades(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "--maxfail=1"\n',
        encoding="utf-8",
    )
    _wf(
        tmp_path,
        "ci.yml",
        "jobs:\n  full:\n    steps:\n"
        '      - run: python -m pytest -o addopts="" -q\n',
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["collect_all_escape_confirmed"] is True
    assert "ci.yml" in f[0].metadata["collect_all_escape_evidence"]
    assert f[0].severity is Severity.INFO
    assert f[0].confidence == 0.45


def test_bare_pytest_workflow_inherits_root_fail_fast_no_escape(tmp_path):
    """CI `pytest -q` still inherits pyproject --maxfail=1 — not an escape."""
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "--maxfail=1"\n',
        encoding="utf-8",
    )
    _wf(
        tmp_path,
        "ci.yml",
        "jobs:\n  test:\n    steps:\n      - run: python -m pytest -q\n",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["collect_all_escape_confirmed"] is False
    assert f[0].severity is Severity.LOW


def test_collect_all_escape_via_maxfail_zero(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "--maxfail=1"\n',
        encoding="utf-8",
    )
    _wf(
        tmp_path,
        "full.yml",
        "jobs:\n  all:\n    steps:\n      - run: pytest --maxfail=0 -q\n",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["collect_all_escape_confirmed"] is True
    assert f[0].severity is Severity.INFO


def test_bare_pytest_is_escape_when_root_has_no_fail_fast(tmp_path):
    # No root fail-fast; a clean pytest workflow line is itself collect-all.
    # Fail-fast only appears in a *different* workflow job.
    _wf(
        tmp_path,
        "fast.yml",
        "jobs:\n  fast:\n    steps:\n      - run: pytest -x -q\n",
    )
    _wf(
        tmp_path,
        "full.yml",
        "jobs:\n  full:\n    steps:\n      - run: pytest -q\n",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].location.path.endswith("fast.yml")
    assert f[0].metadata["collect_all_escape_confirmed"] is True
    assert "full.yml" in f[0].metadata["collect_all_escape_evidence"]


def test_dogfood_this_repo_maxfail_without_collect_all_escape():
    """This repo's pyproject has --maxfail=1; CI runs bare pytest (inherits it)."""
    root = Path(__file__).resolve().parents[1]
    f = _run(root)
    py_hits = [x for x in f if x.location.path == "pyproject.toml"]
    assert py_hits, "expected pyproject.toml fail-fast finding"
    assert py_hits[0].metadata["collect_all_escape_confirmed"] is False
    assert py_hits[0].severity is Severity.LOW
    assert "--maxfail" in py_hits[0].metadata["fail_fast_flags"]
