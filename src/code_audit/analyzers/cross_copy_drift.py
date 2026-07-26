"""Cross-copy / vendored-drift detector.

Flags the same file (a module, schema, or config) that exists **byte-identical at
two or more paths** — an *undeclared copy*. Copies silently drift: a fix in one
place doesn't reach the other, and a consumer reading the stale copy sees the old
behavior (or, when a key/field diverges, zero records). **Family I + VI** — the
divergence family and the missing-authority family.

Universal: a schema kept in two directories, a util module copied into a second
package, a config vendored from another repo. No mainstream linter organizes
around "these two files are the same file in two places, and nothing says which
is authoritative."

**v1** detects *exact* copies (content compared LF-normalized, so a copy that
differs only by line ending still counts as a copy — the same context lesson the
hash detector encodes). It flags substantial source/schema/config files that
appear at 2+ distinct paths, skipping trivial files and dependency/build dirs.

``Finding.metadata.authority_declared_confirmed`` is ``False`` in v1: the detector
cannot yet tell a *governed* duplication (a declared authority + sync gate, e.g.
a README stating the relationship) from an accidental one. A v2 pass looks for
that declaration and clears/downgrades governed copies — enrichment, not rework.
A further v2 extension adds *drifted* copies (near-identical, not byte-identical).

Emits: designate one authority; make the others a pinned dependency or a
declared, pinned vendor — never an undeclared copy.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "CROSS_COPY_DRIFT_001"

# Non-.py artifacts that carry authority and are worth copy-checking.
_NONPY_EXTS = frozenset({".json", ".yaml", ".yml", ".toml", ".sql", ".proto"})
# Directories that are dependency / build / cache output, never authority.
_EXCLUDE_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "site-packages", ".eggs", ".idea", ".vscode",
})
# Basenames that are conventionally duplicated and carry no authority.
_TRIVIAL_NAMES = frozenset({"__init__.py", "py.typed", "__main__.py"})
_MIN_BYTES = 200   # skip trivially-small files (empty __init__, stub configs)
# Path segments marking non-authority test data. Cross-copy is an authority-drift
# concern: a duplication living entirely under test fixtures is intentional test
# data, not a drift risk. Flag a group only if at least one copy is real source.
_TEST_SEGMENTS = frozenset({
    "tests", "test", "fixtures", "testdata", "__fixtures__", "__snapshots__",
})


class CrossCopyDriftAnalyzer:
    """Detect the same file existing byte-identical at 2+ paths (undeclared copy)."""

    id: str = "cross_copy_drift"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        by_hash: dict[str, list[str]] = {}
        for path, rel in self._candidates(root, files):
            try:
                content = path.read_bytes()
            except OSError:
                continue
            if not _is_substantial(content):
                continue
            h = _norm_hash(content)
            by_hash.setdefault(h, []).append(rel)

        findings: list[Finding] = []
        for rels in by_hash.values():
            uniq = sorted(set(rels))
            if len(uniq) < 2:
                continue
            # A duplication entirely within test data is intentional, not drift.
            if all(_is_test_path(r) for r in uniq):
                continue
            findings.append(self._emit(uniq))
        # Deterministic order.
        findings.sort(key=lambda f: f.location.path)
        return findings

    # ── candidate collection ────────────────────────────────────────

    def _candidates(self, root: Path, files: list[Path]):
        seen: set[Path] = set()

        def add(p: Path):
            if p.name in _TRIVIAL_NAMES:
                return
            try:
                rp = p.resolve()
            except OSError:
                return
            if rp in seen:
                return
            seen.add(rp)
            try:
                rel = p.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                rel = p.name
            yield_list.append((p, rel))

        yield_list: list[tuple[Path, str]] = []
        # .py from the runner's discovery (respects scan config).
        for p in files:
            add(p)
        # non-.py authority artifacts via a pruned walk.
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _EXCLUDE_DIRS]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in _NONPY_EXTS:
                    add(Path(dirpath) / fn)
        return yield_list

    # ── finding ─────────────────────────────────────────────────────

    def _emit(self, rels: list[str]) -> Finding:
        anchor = rels[0]
        others = rels[1:]
        message = (
            f"'{anchor}' is byte-identical to {len(others)} other "
            f"location(s): {', '.join(others)}. An undeclared copy silently "
            f"drifts — a fix in one place doesn't reach the other, and a consumer "
            f"reading the stale copy sees the old behavior. Fix: designate one "
            f"authority; make the others a pinned dependency or a declared, pinned "
            f"vendor — not an undeclared copy."
        )
        fingerprint = make_fingerprint(_RULE_ID, anchor, "cross_copy", "|".join(rels))
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.CROSS_COPY_DRIFT,
            severity=Severity.LOW,
            confidence=0.7,
            message=message,
            location=Location(path=anchor, line_start=1, line_end=1),
            fingerprint=fingerprint,
            snippet="",
            metadata={
                "rule_id": _RULE_ID,
                "copy_paths": rels,
                "copy_count": len(rels),
                # v1 cannot tell a governed duplication (declared authority + sync
                # gate) from an accidental one; the v2 pass confirms and clears.
                "authority_declared_confirmed": False,
            },
        )


# ── helpers ─────────────────────────────────────────────────────────


def _norm_hash(content: bytes) -> str:
    """LF-normalized content hash — a copy differing only by line ending still
    counts as the same file."""
    return hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()


def _is_substantial(content: bytes) -> bool:
    if len(content) < _MIN_BYTES:
        return False
    return bool(content.strip())


def _is_test_path(rel: str) -> bool:
    return any(seg in _TEST_SEGMENTS for seg in rel.split("/"))
