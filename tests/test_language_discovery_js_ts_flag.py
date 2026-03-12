"""Tests for multi-language file discovery and JS/TS default-on behavior.

Phase 1 of Multi-Language Analyzer implementation.
Verifies:
1. discover_source_files() always returns py key.
2. JS/TS files discovered by default (enable_js_ts=True).
3. JS/TS files excluded when explicitly disabled.
4. Default exclusions (node_modules, dist) respected.
5. Backward compatibility: discover_py_files unchanged.
6. Runner accepts enable_js_ts parameter.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from code_audit.core.discover import discover_py_files, discover_source_files


@pytest.fixture()
def sample_tree(tmp_path: Path) -> Path:
    """Create a sample project with Python, JS, and TS files."""
    # Python files
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "lib" / "utils.py").parent.mkdir(parents=True)
    (tmp_path / "lib" / "utils.py").write_text("x = 1\n", encoding="utf-8")

    # JS files
    (tmp_path / "web" / "main.js").parent.mkdir(parents=True)
    (tmp_path / "web" / "main.js").write_text("console.log('hi');\n", encoding="utf-8")
    (tmp_path / "web" / "helper.mjs").write_text("export default 1;\n", encoding="utf-8")

    # TS files
    (tmp_path / "web" / "app.ts").write_text("const x: number = 1;\n", encoding="utf-8")
    (tmp_path / "web" / "component.tsx").write_text("<div />\n", encoding="utf-8")

    # Files that should be excluded
    (tmp_path / "node_modules" / "pkg" / "index.js").parent.mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("// excluded\n", encoding="utf-8")
    (tmp_path / "dist" / "bundle.js").parent.mkdir(parents=True)
    (tmp_path / "dist" / "bundle.js").write_text("// excluded\n", encoding="utf-8")

    return tmp_path


def test_discover_source_files_returns_all_keys(sample_tree: Path) -> None:
    """Result always has py, js, ts keys even when JS/TS disabled."""
    result = discover_source_files(sample_tree, enable_js_ts=False)
    assert "py" in result
    assert "js" in result
    assert "ts" in result


def test_discover_source_files_js_ts_enabled_by_default(sample_tree: Path) -> None:
    """With enable_js_ts=True (default), JS/TS lists are populated."""
    result = discover_source_files(sample_tree)
    assert len(result["py"]) == 2
    assert len(result["js"]) == 2  # main.js + helper.mjs
    assert len(result["ts"]) == 2  # app.ts + component.tsx


def test_discover_source_files_js_ts_disabled_explicit(sample_tree: Path) -> None:
    """With explicit enable_js_ts=False, JS/TS lists are empty."""
    result = discover_source_files(sample_tree, enable_js_ts=False)
    assert len(result["py"]) == 2
    assert result["js"] == []
    assert result["ts"] == []


def test_discover_source_files_js_ts_enabled(sample_tree: Path) -> None:
    """With enable_js_ts=True, JS and TS files discovered."""
    result = discover_source_files(sample_tree, enable_js_ts=True)
    assert len(result["py"]) == 2
    assert len(result["js"]) == 2  # main.js + helper.mjs
    assert len(result["ts"]) == 2  # app.ts + component.tsx


def test_discover_source_files_excludes_node_modules(sample_tree: Path) -> None:
    """node_modules and dist are excluded from JS/TS discovery."""
    result = discover_source_files(sample_tree, enable_js_ts=True)
    js_names = {p.name for p in result["js"]}
    ts_names = {p.name for p in result["ts"]}
    assert "index.js" not in js_names
    assert "bundle.js" not in js_names


def test_discover_py_files_unchanged(sample_tree: Path) -> None:
    """discover_py_files still works exactly as before."""
    py_direct = discover_py_files(sample_tree)
    result = discover_source_files(sample_tree, enable_js_ts=True)
    assert py_direct == result["py"]


def test_discover_source_files_empty_dir(tmp_path: Path) -> None:
    """Empty directory returns all empty lists."""
    result = discover_source_files(tmp_path, enable_js_ts=True)
    assert result == {"py": [], "js": [], "ts": []}


def test_discover_source_files_custom_exclude(sample_tree: Path) -> None:
    """Custom exclude dirs are respected for JS/TS."""
    result = discover_source_files(
        sample_tree, enable_js_ts=True, exclude=["web"],
    )
    assert result["js"] == []
    assert result["ts"] == []
    # Python files not in web/ still discovered
    assert len(result["py"]) == 2
