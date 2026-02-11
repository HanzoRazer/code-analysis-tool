"""Duplication analyzer — AST-based code clone detector.

Finds structurally duplicate code blocks by normalizing function/method
ASTs and comparing their hashes.  Two functions that differ only in
variable names, string literals, or numeric constants are considered
clones.

Ported from the luthiers-toolbox ``check_duplication.py`` CI tool.

Key algorithms:
  - ``_normalize_ast()``  — strips names/literals to canonical form
  - ``_extract_blocks()`` — pulls function/method bodies ≥ min_lines
  - ``_hash_block()``     — sha256 of the normalized AST dump
  - clone grouping        — group blocks by hash, flag groups with ≥2 members
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# ── defaults ─────────────────────────────────────────────────────────
_DEFAULT_MIN_LINES = 6       # ignore functions shorter than this
_DEFAULT_THRESHOLD = 0       # 0 = report all clones; >0 = fail only above N


@dataclass(frozen=True, slots=True)
class _Block:
    """An extractable code block with its source location."""

    name: str          # function/method name
    rel_path: str      # path relative to scan root
    line_start: int
    line_end: int
    line_count: int
    ast_hash: str      # sha256 of normalized AST


# ── AST normalisation ────────────────────────────────────────────────

class _Normalizer(ast.NodeTransformer):
    """Strip identifiers, literals, and docstrings so only structure remains.

    After normalisation two functions that differ only in names/values
    will produce identical AST dumps.
    """

    def visit_Name(self, node: ast.Name) -> ast.Name:  # noqa: N802
        node.id = "_"
        return self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.arg = "_"
        if node.annotation:
            node.annotation = None
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:  # noqa: N802
        node.name = "_"
        node.decorator_list = []
        node.returns = None
        # Strip docstrings
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            node.body = node.body[1:]
        return self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # same treatment

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:  # noqa: N802
        # Normalise all constants to a canonical value
        if isinstance(node.value, (int, float, complex)):
            node.value = 0
        elif isinstance(node.value, str):
            node.value = ""
        elif isinstance(node.value, bytes):
            node.value = b""
        return node

    def visit_alias(self, node: ast.alias) -> ast.alias:
        # Normalise import aliases
        node.asname = None
        return self.generic_visit(node)


def _normalize_ast(tree: ast.AST) -> ast.AST:
    """Return a normalised copy of *tree* for structural comparison."""
    return _Normalizer().visit(tree)


def _hash_block(node: ast.AST) -> str:
    """SHA-256 of the normalised AST dump."""
    normalised = _normalize_ast(node)
    dump = ast.dump(normalised, annotate_fields=False)
    return hashlib.sha256(dump.encode()).hexdigest()


# ── block extraction ─────────────────────────────────────────────────

def _extract_blocks(
    tree: ast.Module,
    rel_path: str,
    min_lines: int,
) -> list[_Block]:
    """Pull function/method definitions that meet the min_lines threshold."""
    blocks: list[_Block] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        start = node.lineno
        end = getattr(node, "end_lineno", start) or start
        line_count = end - start + 1

        if line_count < min_lines:
            continue

        blocks.append(
            _Block(
                name=node.name,
                rel_path=rel_path,
                line_start=start,
                line_end=end,
                line_count=line_count,
                ast_hash=_hash_block(node),
            )
        )

    return blocks


# ── analyzer ─────────────────────────────────────────────────────────

class DuplicationAnalyzer:
    """Finds structurally duplicate code blocks via AST hashing.

    Conforms to the ``Analyzer`` protocol (``id``, ``version``, ``run()``).
    """

    id: str = "duplication"
    version: str = "1.0.0"

    def __init__(
        self,
        *,
        min_lines: int = _DEFAULT_MIN_LINES,
        threshold: int = _DEFAULT_THRESHOLD,
    ) -> None:
        self.min_lines = min_lines
        self.threshold = threshold

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        """Scan *files*, group by AST hash, and report clone groups."""
        # 1. Extract blocks from all files
        all_blocks: list[_Block] = []
        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                continue

            rel = str(path.relative_to(root))
            all_blocks.extend(_extract_blocks(tree, rel, self.min_lines))

        # 2. Group by hash → clone groups
        groups: dict[str, list[_Block]] = {}
        for block in all_blocks:
            groups.setdefault(block.ast_hash, []).append(block)

        # Only keep groups with ≥2 members (actual clones)
        clone_groups = {h: blks for h, blks in groups.items() if len(blks) >= 2}

        # 3. Emit findings
        findings: list[Finding] = []

        for ast_hash, clones in sorted(clone_groups.items()):
            # All members of a clone group share the same structural hash
            clone_count = len(clones)
            total_dup_lines = sum(b.line_count for b in clones)

            # Severity: 2 clones = LOW, 3+ = MEDIUM, >200 total dup lines = HIGH
            if total_dup_lines > 200:
                severity = Severity.HIGH
                rule_id = "DUP-HEAVY-001"
            elif clone_count >= 3:
                severity = Severity.MEDIUM
                rule_id = "DUP-GROUP-001"
            else:
                severity = Severity.LOW
                rule_id = "DUP-PAIR-001"

            # Emit a finding for each member of the group
            other_locations = [
                f"{b.rel_path}:{b.line_start}" for b in clones
            ]
            for block in clones:
                peers = [loc for loc in other_locations if loc != f"{block.rel_path}:{block.line_start}"]
                snippet = (
                    f"def {block.name}(…)  "
                    f"# {block.line_count} lines, "
                    f"{clone_count} clones"
                )

                findings.append(
                    Finding(
                        finding_id="",  # assigned below
                        type=AnalyzerType.COMPLEXITY,
                        severity=severity,
                        confidence=0.85,
                        message=(
                            f"Function '{block.name}' is a structural clone "
                            f"({clone_count} copies, {total_dup_lines} total "
                            f"duplicate lines)"
                        ),
                        location=Location(
                            path=block.rel_path,
                            line_start=block.line_start,
                            line_end=block.line_end,
                        ),
                        fingerprint=make_fingerprint(
                            rule_id,
                            block.rel_path,
                            block.name,
                            snippet,
                        ),
                        snippet=snippet,
                        metadata={
                            "rule_id": rule_id,
                            "ast_hash": ast_hash[:16],
                            "clone_count": clone_count,
                            "total_dup_lines": total_dup_lines,
                            "peer_locations": peers,
                        },
                    )
                )

        # Assign stable finding IDs
        for i, f in enumerate(findings):
            object.__setattr__(
                f, "finding_id", f"dup_{f.fingerprint[7:15]}_{i:04d}"
            )

        return findings
