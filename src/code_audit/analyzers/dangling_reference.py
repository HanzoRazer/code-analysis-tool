"""Dangling-reference analyzer — references to first-party modules that no longer exist.

This is the **inverse** of ``dead_code``. Dead-code asks *"does X still have
consumers?"* (run it **before** deleting X). This asks *"do X's consumers still
have X?"* — a reference to a first-party module that exists at no reachable commit
(run it **after** deleting X). Together they are the two halves of **deletion
safety**; a deletion that runs neither is how a "remove unused ``app/retopo/``"
commit leaves ``examples/retopo/run.sh`` calling ``python -m app.retopo.run`` and a
CI job invoking that script — **callee deleted, callers left in place**, structurally
unfixable because the called code exists nowhere in the tree.

``dead_code``'s own docstring defers cross-file analysis; this is that cross-file
sibling, built as its own analyzer rather than inside dead_code.

**The first-party discriminator (portable, not hard-coded to any package name):**
a reference ``a.b.c`` is flagged only when its *top-level* package ``a`` still
resolves somewhere in the scanned tree **but the full dotted path does not**. That
is exactly the ``app.retopo.run`` shape (``app/`` survives, ``app/retopo/`` was
deleted) and it naturally excludes a missing *third-party* import: ``import scipy``
has no ``scipy`` package anywhere in the tree, so its top-level does not resolve and
it is left to the requirements/deployment analyzers, not flagged here.

**Scope (v1): module-level resolution only.** References are collected only in
*unambiguous module contexts* — ``import a.b.c`` / ``from a.b.c import …`` in Python,
and ``python -m a.b.c`` / ``import``/``from`` / ``"a.b.c:sym"`` entry-points in
shell, YAML, Makefile, and TOML — where the captured dotted path is a module by
construction. Symbol-level resolution (module survives, a *name* inside it was
deleted) requires reading the target module's exports and is **deferred**, matching
dead_code's own single-granularity v1 posture.

Every failure mode is a Finding, never a raised exception — a crash here would abort
the whole scan, the same silent pass this analyzer exists to prevent.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "DANGLING_REF_001"
_ERROR_RULE_ID = "DANGLING_REF_ERROR"

# Directories never worth walking. Mirrors code_audit.core.discover._DEFAULT_EXCLUDES
# but KEEPS ``.github`` — CI workflow YAML is exactly where deleted-module calls hide
# (the mesh-pipeline-ci.yml half of the motivating instance).
_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
})

# Source roots under which top-level first-party packages live. Covers the flat
# layout (``root/app/``) and the src layout (``root/src/code_audit/``).
_SRC_SUBDIRS = ("", "src")

_CONFIG_SUFFIXES = frozenset({".sh", ".yml", ".yaml", ".toml", ".cfg", ".ini"})
_MAKEFILE_NAMES = frozenset({"Makefile", "makefile", "GNUmakefile"})
_MAX_FILE_BYTES = 2_000_000

# ── reference patterns (module always captured in group 1) ──────────
# ``python -m a.b.c`` / ``py -m a.b.c``
_RE_DASH_M = re.compile(r"\b(?:python[0-9.]*|py)\s+-m\s+([A-Za-z_][\w.]*)")
# ``import a.b.c`` — ``\b`` before ``import`` won't match mid-word (``reimport``),
# and matches through a preceding quote in inline ``python -c '…'`` blocks.
_RE_IMPORT = re.compile(r"\bimport\s+([A-Za-z_][\w.]*)")
# ``from a.b.c import …``
_RE_FROM = re.compile(r"\bfrom\s+([A-Za-z_][\w.]*)\s+import\b")
# console-script / entry-point ``a.b.c:symbol`` (TOML/cfg only — ``:`` is too
# common in YAML to treat as an entry-point everywhere)
_RE_ENTRYPOINT = re.compile(r"([A-Za-z_][\w.]*)\s*:\s*[A-Za-z_]\w*")


def _dotted_valid(name: str) -> bool:
    """A dotted module path whose every component is a Python identifier."""
    if not name or name.startswith(".") or name.endswith("."):
        return False
    parts = name.split(".")
    return all(p.isidentifier() for p in parts)


def _module_prefixes(dotted: str) -> list[str]:
    """``a.b.c`` -> ``["a", "a.b", "a.b.c"]`` — every package/module along the path."""
    parts = dotted.split(".")
    return [".".join(parts[: i + 1]) for i in range(len(parts))]


class _Reference:
    __slots__ = ("module", "path", "line", "kind", "source")

    def __init__(self, module: str, path: str, line: int, kind: str, source: str) -> None:
        self.module = module
        self.path = path
        self.line = line
        self.kind = kind      # import | from-import | python-m | entry-point
        self.source = source  # python | config


class DanglingReferenceAnalyzer:
    """Detect references to first-party modules that no longer exist in the tree."""

    id: str = "dangling_reference"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        # Belt-and-suspenders: any unexpected failure becomes a Finding, never an
        # exception escaping run() (which would abort the scan — the silent pass this
        # analyzer exists to prevent). ``files`` is ignored: we walk ``root`` directly
        # so the analyzer is self-contained (tests invoke it with ``files=[]``, and we
        # need config files the Python-only ``files`` list never carries).
        try:
            return self._run_inner(root)
        except Exception as exc:  # noqa: BLE001 — fail loud as a finding, never raise
            return [self._error_finding(
                f"dangling_reference analysis raised {type(exc).__name__}: {exc}."
            )]

    def _run_inner(self, root: Path) -> list[Finding]:
        resolvable, first_party = self._index_modules(root)
        if not first_party:
            return []  # no first-party Python in the tree — nothing to dangle

        references = self._collect_references(root, first_party)

        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for ref in references:
            if ref.module in resolvable:
                continue  # target exists — fine
            key = (ref.path, ref.line, ref.module)
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._finding(ref))
        # Stable ordering, independent of filesystem walk order.
        findings.sort(key=lambda f: (f.location.path, f.location.line_start,
                                     f.metadata["missing_module"]))
        return findings

    # ── module index ────────────────────────────────────────────────

    def _index_modules(self, root: Path) -> tuple[set[str], set[str]]:
        """Return (resolvable_modules, first_party_toplevels).

        ``resolvable_modules`` holds every package and module dotted-path that
        exists in the tree; ``first_party_toplevels`` holds their first components
        — the set a reference's top-level must be in to be considered first-party.
        """
        resolvable: set[str] = set()
        for sub in _SRC_SUBDIRS:
            src_root = root / sub if sub else root
            if not src_root.is_dir():
                continue
            for py in src_root.rglob("*.py"):
                try:
                    rel_parts = py.relative_to(src_root).parts
                except ValueError:
                    continue
                if any(part in _SKIP_DIRS for part in rel_parts):
                    continue
                # src layout wins: a file under root/src is indexed relative to src,
                # not doubly under root. (root/src is handled by its own iteration;
                # skip it here so root-iteration doesn't shadow it with a "src." path.)
                if sub == "" and rel_parts and rel_parts[0] == "src":
                    continue
                dotted_parts = list(rel_parts[:-1])
                stem = py.stem
                if stem != "__init__":
                    dotted_parts.append(stem)
                if not dotted_parts:
                    continue
                dotted = ".".join(dotted_parts)
                if not _dotted_valid(dotted):
                    continue
                resolvable.update(_module_prefixes(dotted))

        first_party = {m.split(".", 1)[0] for m in resolvable}
        return resolvable, first_party

    # ── reference collection ────────────────────────────────────────

    def _collect_references(self, root: Path, first_party: set[str]) -> list[_Reference]:
        refs: list[_Reference] = []
        for path in root.rglob("*"):
            try:
                if not path.is_file():
                    continue
                rel_parts = path.relative_to(root).parts
                if any(part in _SKIP_DIRS for part in rel_parts):
                    continue
                try:
                    if path.stat().st_size > _MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                rel = path.relative_to(root).as_posix()
                suffix = path.suffix.lower()
                if suffix == ".py":
                    refs.extend(self._py_references(path, rel, first_party))
                elif suffix in _CONFIG_SUFFIXES or path.name in _MAKEFILE_NAMES:
                    refs.extend(self._config_references(path, rel, suffix, first_party))
            except OSError:
                continue
        return refs

    def _py_references(self, path: Path, rel: str, first_party: set[str]) -> list[_Reference]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, ValueError):
            return []  # unparseable file carries no extractable reference
        out: list[_Reference] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name
                    if _dotted_valid(mod) and mod.split(".", 1)[0] in first_party:
                        out.append(_Reference(mod, rel, node.lineno, "import", "python"))
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # relative import — resolving it is a different concern
                mod = node.module
                if mod and _dotted_valid(mod) and mod.split(".", 1)[0] in first_party:
                    out.append(_Reference(mod, rel, node.lineno, "from-import", "python"))
        return out

    def _config_references(
        self, path: Path, rel: str, suffix: str, first_party: set[str]
    ) -> list[_Reference]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        # (pattern, kind) — each pattern captures a module in group 1 from an
        # unambiguous module context. Entry-points (``a.b.c:sym``) only in TOML/cfg,
        # where ``:`` denotes a console-script rather than arbitrary YAML mapping.
        patterns = [(_RE_DASH_M, "python-m"), (_RE_IMPORT, "import"),
                    (_RE_FROM, "from-import")]
        if suffix in (".toml", ".cfg", ".ini"):
            patterns.append((_RE_ENTRYPOINT, "entry-point"))
        out: list[_Reference] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, kind in patterns:
                for mod in pattern.findall(line):
                    if _dotted_valid(mod) and "." in mod and mod.split(".", 1)[0] in first_party:
                        out.append(_Reference(mod, rel, lineno, kind, "config"))
        return out

    # ── findings ────────────────────────────────────────────────────

    def _finding(self, ref: _Reference) -> Finding:
        top = ref.module.split(".", 1)[0]
        fingerprint = make_fingerprint(_RULE_ID, ref.path, ref.module, "")
        confidence = 0.9 if ref.source == "python" else 0.85
        message = (
            f"'{ref.path}' references first-party module '{ref.module}' "
            f"({ref.kind}), which no longer exists in the tree — its top-level "
            f"package '{top}' resolves but the full path does not. Callee deleted, "
            f"caller left in place: this call reaches code that exists at no "
            f"reachable commit. Restore the module, or remove/redirect the "
            f"reference. (Run dead_code BEFORE deleting to check for consumers; "
            f"this is the after-deletion half.)"
        )
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.DANGLING_REFERENCE,
            severity=Severity.HIGH,
            confidence=confidence,
            message=message,
            location=Location(path=ref.path, line_start=ref.line, line_end=ref.line),
            fingerprint=fingerprint,
            metadata={
                "rule_id": _RULE_ID,
                "missing_module": ref.module,
                "top_level": top,
                "reference_kind": ref.kind,
                "source": ref.source,
            },
        )

    def _error_finding(self, message: str) -> Finding:
        fingerprint = make_fingerprint(_ERROR_RULE_ID, ".", "dangling_reference", "")
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.DANGLING_REFERENCE,
            severity=Severity.LOW,
            confidence=0.99,
            message=(
                f"{message} dangling_reference failing loud as a finding rather than "
                f"aborting the scan."
            ),
            location=Location(path=".", line_start=1, line_end=1),
            fingerprint=fingerprint,
            metadata={"rule_id": _ERROR_RULE_ID},
        )
