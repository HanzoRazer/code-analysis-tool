"""Unit tests for the unpinned-toolchain detector (v2 — section-based).

Gate is structural position (dev/lint/test/ci section), not a tool-name
whitelist. Known-tool list only boosts severity/confidence.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from code_audit.analyzers.unpinned_toolchain import UnpinnedToolchainAnalyzer
from code_audit.model import AnalyzerType, Severity


def _run(root: Path, files: list[Path] | None = None):
    if files is None:
        files = [root / "pyproject.toml"] if (root / "pyproject.toml").is_file() else []
    return UnpinnedToolchainAnalyzer().run(root, files)


def test_dev_section_floor_only_known_tool_medium(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        "dev = [\n"
        '  "ruff>=0.4.0",\n'
        "]\n",
        encoding="utf-8",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.UNPINNED_TOOLCHAIN
    assert f[0].severity is Severity.MEDIUM
    assert f[0].confidence == 0.9
    assert f[0].metadata["section"] == "dev"
    assert f[0].metadata["tool"] == "ruff"
    assert f[0].metadata["known_ci_tool"] is True
    assert f[0].metadata["remedy"] == "pin_or_advisory"
    assert f[0].finding_id
    assert f[0].location.path == "pyproject.toml"
    assert f[0].location.line_start == 3


def test_dev_section_unlisted_tool_low_confidence(tmp_path):
    """Blind-spot proof: unlisted tool in a dev section IS flagged."""
    (tmp_path / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        "dev = [\n"
        '  "some-obscure-linter-9000>=1.0",\n'
        "]\n",
        encoding="utf-8",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].severity is Severity.LOW
    assert f[0].confidence == 0.6
    assert f[0].metadata["known_ci_tool"] is False
    assert f[0].metadata["tool"] == "some-obscure-linter-9000"


def test_runtime_section_not_flagged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        "api = [\n"
        '  "requests>=2.0",\n'
        "]\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_ceilinged_spec_not_flagged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        "dev = [\n"
        '  "ruff>=0.4.0,<0.5",\n'
        "]\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_pinned_spec_not_flagged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        "dev = [\n"
        '  "ruff==0.4.0",\n'
        "]\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_compatible_release_not_flagged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        "dev = [\n"
        '  "ruff~=0.4.0",\n'
        "]\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_commented_line_not_flagged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        "dev = [\n"
        '  # "ruff>=0.4.0",\n'
        '  "pytest==7.0.0",\n'
        "]\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_inline_array_parsed(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        'dev = ["pytest>=7.0", "ruff>=0.4.0"]\n',
        encoding="utf-8",
    )
    f = _run(tmp_path)
    tools = sorted(x.metadata["tool"] for x in f)
    assert tools == ["pytest", "ruff"]


def test_lint_section_is_dev_surface(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        "lint = [\n"
        '  "flake8>=6.0",\n'
        "]\n",
        encoding="utf-8",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["section"] == "lint"
    assert f[0].severity is Severity.MEDIUM


def test_requirements_dev_txt(tmp_path):
    (tmp_path / "requirements-dev.txt").write_text(
        "ruff>=0.4.0\n"
        "requests>=2.0\n",
        encoding="utf-8",
    )
    f = _run(tmp_path, files=[tmp_path / "requirements-dev.txt"])
    tools = sorted(x.metadata["tool"] for x in f)
    assert tools == ["requests", "ruff"]
    assert all(x.metadata["section"] == "<dev-requirements-file>" for x in f)


def test_dogfood_this_repo_pyproject():
    """Acceptance: catch the motivating `ruff>=0.4.0` in THIS repo."""
    root = Path(__file__).resolve().parents[1]
    findings = UnpinnedToolchainAnalyzer().run(root, [root / "pyproject.toml"])
    tools = {f.metadata["tool"] for f in findings}

    assert "ruff" in tools, "MUST flag the motivating ruff>=0.4.0"
    assert "fastapi" not in tools and "uvicorn" not in tools and "pydantic" not in tools

    ruff_f = [f for f in findings if f.metadata["tool"] == "ruff"][0]
    assert ruff_f.metadata["known_ci_tool"] is True
    assert ruff_f.severity is Severity.MEDIUM
    assert ruff_f.metadata["section"] == "dev"
    assert ruff_f.location.line_start == 24

    for name in ("pytest", "jsonschema", "openapi-spec-validator"):
        assert name in tools, f"expected {name} flagged"
        hit = [f for f in findings if f.metadata["tool"] == name][0]
        assert hit.severity is Severity.LOW


def test_blind_spot_unlisted_dev_tool_flagged_runtime_ignored():
    d = Path(tempfile.mkdtemp())
    (d / "pyproject.toml").write_text(
        "[project.optional-dependencies]\n"
        "dev = [\n"
        '  "some-obscure-linter-9000>=1.0",\n'
        "]\n"
        "api = [\n"
        '  "requests>=2.0",\n'
        "]\n",
        encoding="utf-8",
    )
    f2 = UnpinnedToolchainAnalyzer().run(d, [d / "pyproject.toml"])
    t2 = {x.metadata["tool"] for x in f2}
    assert "some-obscure-linter-9000" in t2
    assert "requests" not in t2
