"""Lazy tree-sitter parser factory.

Loads parsers for JavaScript, TypeScript, and TSX using the modern
``tree-sitter-languages`` pip packages (``tree-sitter-javascript``,
``tree-sitter-typescript``).

All tree-sitter imports are deferred — if the optional dependency
is not installed, a clear error is raised at call time.

Usage::

    from code_audit.parsers.tree_sitter_loader import get_js_parser, is_available
    if is_available():
        parser = get_js_parser()
        tree = parser.parse(b"var x = 1;")
"""

from __future__ import annotations

import logging
from functools import lru_cache

_logger = logging.getLogger(__name__)


class TreeSitterNotAvailable(ImportError):
    """Raised when tree-sitter optional dependencies are missing."""

    def __init__(self) -> None:
        super().__init__(
            "tree-sitter is not installed. "
            "Install with: pip install 'code-analysis-tool[treesitter]'"
        )


def is_available() -> bool:
    """Return True if tree-sitter and language grammars are importable."""
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_javascript  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
        return True
    except ImportError:
        return False


def _require_tree_sitter():
    """Import tree_sitter or raise TreeSitterNotAvailable."""
    try:
        import tree_sitter
        return tree_sitter
    except ImportError:
        raise TreeSitterNotAvailable()


@lru_cache(maxsize=1)
def get_js_parser():
    """Return a tree-sitter Parser configured for JavaScript."""
    ts = _require_tree_sitter()
    try:
        import tree_sitter_javascript as ts_js
    except ImportError:
        raise TreeSitterNotAvailable()

    lang = ts.Language(ts_js.language())
    parser = ts.Parser(lang)
    _logger.debug("Loaded JavaScript tree-sitter parser")
    return parser


@lru_cache(maxsize=1)
def get_ts_parser():
    """Return a tree-sitter Parser configured for TypeScript."""
    ts = _require_tree_sitter()
    try:
        import tree_sitter_typescript as ts_ts
    except ImportError:
        raise TreeSitterNotAvailable()

    lang = ts.Language(ts_ts.language_typescript())
    parser = ts.Parser(lang)
    _logger.debug("Loaded TypeScript tree-sitter parser")
    return parser


@lru_cache(maxsize=1)
def get_tsx_parser():
    """Return a tree-sitter Parser configured for TSX."""
    ts = _require_tree_sitter()
    try:
        import tree_sitter_typescript as ts_ts
    except ImportError:
        raise TreeSitterNotAvailable()

    lang = ts.Language(ts_ts.language_tsx())
    parser = ts.Parser(lang)
    _logger.debug("Loaded TSX tree-sitter parser")
    return parser


def get_parser_for_extension(ext: str):
    """Return the appropriate parser for a file extension.

    Parameters
    ----------
    ext:
        File extension including dot: ".js", ".mjs", ".cjs", ".ts", ".tsx"

    Returns
    -------
    tree_sitter.Parser

    Raises
    ------
    TreeSitterNotAvailable
        If tree-sitter is not installed.
    ValueError
        If the extension is not supported.
    """
    ext = ext.lower()
    if ext in {".js", ".mjs", ".cjs"}:
        return get_js_parser()
    if ext == ".ts":
        return get_ts_parser()
    if ext == ".tsx":
        return get_tsx_parser()
    raise ValueError(f"Unsupported extension for tree-sitter: {ext!r}")
