"""Unit tests for the unpinned-toolchain detector (v2 — section-based).

Gate is structural position (dev/lint/test/ci section), not a tool-name
whitelist. Known-tool list only boosts severity/confidence.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.unpinned_toolchain import UnpinnedToolchainAnalyzer
from code_audit.model import AnalyzerType, Severity


def _run(root: Path):
    return UnpinnedToolchainAnalyzer().run(root, [])


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
    assert f[0].metadata["known_ci_tool"] is True
    assert f[0].metadata["detection_strategy"] == "section"
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
    assert f[0].metadata["package"] == "some-obscure-linter-9000"


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
    pkgs = sorted(x.metadata["package"] for x in f)
    assert pkgs == ["pytest", "ruff"]


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
        "requests>=2.0\n",  # still flagged — file itself is the dev surface
        encoding="utf-8",
    )
    f = _run(tmp_path)
    pkgs = sorted(x.metadata["package"] for x in f)
    assert pkgs == ["requests", "ruff"]
    assert all(x.metadata["section"] == "requirements-dev" for x in f)


def test_dogfood_this_repo_pyproject():
    """Acceptance: catch the motivating `ruff>=0.4.0` in THIS repo."""
    root = Path(__file__).resolve().parents[1]
    f = _run(root)
    by_pkg = {x.metadata["package"]: x for x in f}

    assert "ruff" in by_pkg
    assert by_pkg["ruff"].severity is Severity.MEDIUM
    assert by_pkg["ruff"].metadata["section"] == "dev"
    assert by_pkg["ruff"].metadata["known_ci_tool"] is True
    assert by_pkg["ruff"].location.line_start == 24

    # Other floor-only dev deps flagged at LOW (not on known-tool booster).
    for name in ("pytest", "jsonschema", "openapi-spec-validator"):
        assert name in by_pkg, f"expected {name} flagged"
        assert by_pkg[name].severity is Severity.LOW

    # Runtime api section must not contribute findings (ceilinged + non-dev).
    assert "fastapi" not in by_pkg
    assert "httpx" not in by_pkg
    assert "uvicorn" not in by_pkg
    assert "pydantic" not in by_pkg
    assert "tree-sitter" not in by_pkg
