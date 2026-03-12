"""JS/TS specific tree-sitter helpers.

Provides ``parse_js_file`` / ``parse_ts_file`` convenience functions
that read a file, choose the right parser, and return the AST.
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

from code_audit.parsers.tree_sitter_loader import get_parser_for_extension


class ParseResult(NamedTuple):
    """Result of parsing a single file."""

    path: Path
    source: bytes
    tree: object  # tree_sitter.Tree (untyped to avoid import-time dependency)
    language: str  # "js" | "ts" | "tsx"


def _ext_to_language(ext: str) -> str:
    """Map file extension to language label."""
    ext = ext.lower()
    if ext in {".js", ".mjs", ".cjs"}:
        return "js"
    if ext == ".ts":
        return "ts"
    if ext == ".tsx":
        return "tsx"
    raise ValueError(f"Unsupported extension: {ext!r}")


def parse_file(path: Path) -> ParseResult:
    """Parse a JS/TS file and return its AST.

    Parameters
    ----------
    path:
        Absolute path to the source file.

    Returns
    -------
    ParseResult with the file's source bytes, AST tree, and language.

    Raises
    ------
    TreeSitterNotAvailable
        If tree-sitter is not installed.
    FileNotFoundError
        If the file does not exist.
    """
    source = path.read_bytes()
    parser = get_parser_for_extension(path.suffix)
    tree = parser.parse(source)
    language = _ext_to_language(path.suffix)
    return ParseResult(path=path, source=source, tree=tree, language=language)
