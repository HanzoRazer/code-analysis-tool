"""Base class for tree-sitter-powered multi-language analyzers.

Provides common infrastructure for analyzers that use tree-sitter
to parse JS/TS files: file filtering, parsing, finding production.

Subclasses implement ``analyze_file()`` and call helpers to emit
findings via the ``FindingSink`` protocol.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from code_audit.model.finding import Finding
from code_audit.parsers.tree_sitter_loader import is_available

_logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SourceFile:
    """A parsed source file ready for analysis."""

    path: Path
    language: str  # "js" | "ts" | "tsx"
    text: str
    source: bytes
    tree: object  # tree_sitter.Tree


class FindingSink(Protocol):
    """Protocol for collecting findings during analysis."""

    def emit(self, finding: Finding) -> None: ...


class TreeSitterAnalyzerBase:
    """Base class for multi-language analyzers using tree-sitter.

    Subclasses must set ``id`` and ``version`` and implement
    ``analyze_file(source_file, root) -> list[Finding]``.
    """

    id: str = ""
    version: str = ""
    # Languages this analyzer processes
    languages: tuple[str, ...] = ("js", "ts", "tsx")

    def filter_files(
        self,
        files_by_lang: dict[str, list[Path]],
    ) -> list[tuple[Path, str]]:
        """Return (path, language) pairs for all files this analyzer handles."""
        result: list[tuple[Path, str]] = []
        lang_map = {
            "js": "js",
            "ts": "ts",
        }
        for lang_key in ("js", "ts"):
            if lang_key not in files_by_lang:
                continue
            for p in files_by_lang[lang_key]:
                # ts list may contain .tsx files
                if p.suffix.lower() == ".tsx":
                    result.append((p, "tsx"))
                else:
                    result.append((p, lang_map.get(lang_key, lang_key)))
        return result

    def _parse_file(self, path: Path, language: str) -> SourceFile | None:
        """Parse a file into a SourceFile, or None on failure."""
        try:
            from code_audit.parsers.tree_sitter_loader import get_parser_for_extension

            source = path.read_bytes()
            text = source.decode("utf-8", errors="replace")
            parser = get_parser_for_extension(path.suffix)
            tree = parser.parse(source)
            return SourceFile(
                path=path, language=language,
                text=text, source=source, tree=tree,
            )
        except Exception:
            _logger.warning("Failed to parse %s", path, exc_info=True)
            return None

    def analyze_file(self, source_file: SourceFile, root: Path) -> list[Finding]:
        """Analyze a single parsed file. Override in subclasses."""
        return []

    def run_multilang(
        self,
        root: Path,
        files_by_lang: dict[str, list[Path]],
    ) -> list[Finding]:
        """Entry point called by the runner for multi-language analysis."""
        if not is_available():
            _logger.info(
                "tree-sitter not available — skipping %s", self.id,
            )
            return []

        all_findings: list[Finding] = []
        for path, language in self.filter_files(files_by_lang):
            sf = self._parse_file(path, language)
            if sf is not None:
                findings = self.analyze_file(sf, root)
                all_findings.extend(findings)
        return all_findings

    # Required by the Analyzer protocol for Python files (no-op)
    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        """Python file analysis — not applicable for tree-sitter analyzers."""
        return []
