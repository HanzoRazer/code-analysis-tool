"""Smoke test: tree-sitter loads and parses JS/TS.

Phase 2 of Multi-Language Analyzer implementation.
Verifies:
1. tree-sitter is available.
2. JS parser produces an AST from trivial source.
3. TS parser produces an AST from trivial source.
4. TSX parser produces an AST from trivial source.
5. is_available() returns True.
6. Unsupported extension raises ValueError.
7. parse_file() reads and parses a real .js file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from code_audit.parsers.tree_sitter_loader import (
    get_js_parser,
    get_parser_for_extension,
    get_ts_parser,
    get_tsx_parser,
    is_available,
)


pytestmark = pytest.mark.skipif(
    not is_available(),
    reason="tree-sitter not installed",
)


def test_is_available():
    assert is_available() is True


def test_js_parser_parses_trivial_source():
    parser = get_js_parser()
    tree = parser.parse(b"var x = 1;")
    assert tree.root_node.type == "program"
    assert tree.root_node.child_count >= 1


def test_ts_parser_parses_trivial_source():
    parser = get_ts_parser()
    tree = parser.parse(b"const x: number = 1;")
    assert tree.root_node.type == "program"
    assert tree.root_node.child_count >= 1


def test_tsx_parser_parses_trivial_source():
    parser = get_tsx_parser()
    tree = parser.parse(b"const el = <div />;")
    assert tree.root_node.type == "program"
    assert tree.root_node.child_count >= 1


def test_get_parser_for_extension_js():
    p = get_parser_for_extension(".js")
    assert p is get_js_parser()


def test_get_parser_for_extension_mjs():
    p = get_parser_for_extension(".mjs")
    assert p is get_js_parser()


def test_get_parser_for_extension_ts():
    p = get_parser_for_extension(".ts")
    assert p is get_ts_parser()


def test_get_parser_for_extension_tsx():
    p = get_parser_for_extension(".tsx")
    assert p is get_tsx_parser()


def test_get_parser_for_unsupported_extension():
    with pytest.raises(ValueError, match="Unsupported"):
        get_parser_for_extension(".py")


def test_parse_file_reads_and_parses(tmp_path: Path):
    """parse_file() produces a ParseResult for a JS file."""
    from code_audit.parsers.tree_sitter_js import parse_file

    js_file = tmp_path / "test.js"
    js_file.write_text("console.log('hello');\n", encoding="utf-8")

    result = parse_file(js_file)
    assert result.path == js_file
    assert result.language == "js"
    assert result.tree.root_node.type == "program"
    assert result.source.replace(b"\r\n", b"\n") == b"console.log('hello');\n"
