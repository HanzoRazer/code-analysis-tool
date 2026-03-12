"""Tree-sitter parser integration for multi-language analysis.

This package provides lazy-loaded tree-sitter parsers for JavaScript
and TypeScript.  All tree-sitter dependencies are optional — if not
installed, importers get a clear ``TreeSitterNotAvailable`` error.

Usage::

    from code_audit.parsers.tree_sitter_loader import get_js_parser
    parser = get_js_parser()
    tree = parser.parse(b"console.log('hello');")
"""
