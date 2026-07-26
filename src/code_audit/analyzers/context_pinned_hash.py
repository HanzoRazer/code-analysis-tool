"""Context-pinned hash detector.

Flags a hash (sha256/sha1/md5/…) computed over an input whose bytes depend on a
**context the hash does not record** — line endings (CRLF vs LF), interpreter
version (``ast.dump`` differs across Python minor versions), or OS — and then
asserted byte-equal against a stored value. Such a hash passes in the context it
was baked in and fails everywhere else: the classic "green on my machine, red on
CI" manifest/golden-file bug that no mainstream linter checks for.

**Family II (implicit context).** Every team that bakes a hash on one platform
and checks it on another has this latent defect — a lockfile digest, a golden-
file test, an AST-fingerprint gate.

**v1 is a source-pattern heuristic.** It finds the *candidate* — a function that
both computes a hash and feeds it a context-sensitive input — and records, in the
finding's ``metadata``, which context axis is at risk and whether an *in-file*
mitigation is visible (LF-normalization for byte hashes; a Python-version guard
for ``ast.dump`` hashes). It sets ``context_confirmed = False`` because the real
mitigation may live outside the source (``.gitattributes eol=lf``, a CI matrix
pin, a context field recorded in the manifest). A follow-up pass (v2) reads those
artifacts and confirms/clears each finding — it enriches this metadata rather than
restructuring it, so nothing here has to change.

Fix it emits: *record the context* — normalize the input (LF), pin the generator
(one interpreter), or declare the context in the manifest — not a one-off
regenerate, which only relocates the defect to the next context.
"""
from __future__ import annotations

import ast
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# Hash constructors whose output is byte-exact and therefore context-sensitive.
_HASH_FUNCS = frozenset(
    {"sha256", "sha1", "sha224", "sha384", "sha512", "md5", "blake2b", "blake2s"}
)

_RULE_BYTE = "CTX_PINNED_HASH_BYTES_001"   # line-ending / OS axis
_RULE_AST = "CTX_PINNED_HASH_AST_001"      # interpreter-version axis

# Names that, present anywhere in the module, indicate the generator is pinned to
# one interpreter (mitigation for the ast.dump / interpreter-version axis).
_VERSION_GUARD_NAMES = frozenset(
    {"version_info", "require_ci_python", "_require_ci_python",
     "_REQUIRED_PYTHON", "_CI_PYTHON", "CI_PYTHON"}
)


class ContextPinnedHashAnalyzer:
    """Detect hashes asserted byte-equal across a context they weren't computed in."""

    id: str = "context_pinned_hash"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(src, filename=str(path))
            except (OSError, SyntaxError, ValueError):
                continue
            findings.extend(self._scan_module(tree, src, path, root))
        return findings

    # ── module ──────────────────────────────────────────────────────

    def _scan_module(
        self, tree: ast.Module, src: str, path: Path, root: Path
    ) -> list[Finding]:
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = path.name

        module_has_version_guard = _module_has_version_guard(tree)
        # Local helper functions that wrap a hash constructor (e.g.
        # ``_sha256_bytes(b): return hashlib.sha256(b).hexdigest()``). A call to
        # one is a hash producer, so a *caller* that reads bytes and passes them
        # in is context-pinned even though the hash constructor is elsewhere.
        hash_wrappers = _hash_wrapper_names(tree)
        src_lines = src.splitlines()
        findings: list[Finding] = []

        # A "scope" is a function body — where manifest/golden hashing lives.
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            feats = _scope_features(node, hash_wrappers)
            if not feats.has_hash:
                continue

            if feats.hashes_ast_dump:
                findings.append(
                    self._emit(
                        rule_id=_RULE_AST,
                        axis="python_version",
                        mitigated=module_has_version_guard,
                        mitigation_kind="generator_python_pinned"
                        if module_has_version_guard else None,
                        fn_name=node.name,
                        line=feats.hash_line,
                        rel=rel,
                        src_lines=src_lines,
                    )
                )
            if feats.hashes_file_bytes:
                findings.append(
                    self._emit(
                        rule_id=_RULE_BYTE,
                        axis="line_ending",
                        mitigated=feats.has_lf_normalize,
                        mitigation_kind="input_lf_normalized"
                        if feats.has_lf_normalize else None,
                        fn_name=node.name,
                        line=feats.hash_line,
                        rel=rel,
                        src_lines=src_lines,
                    )
                )
        return findings

    # ── finding construction ────────────────────────────────────────

    def _emit(
        self,
        *,
        rule_id: str,
        axis: str,
        mitigated: bool,
        mitigation_kind: str | None,
        fn_name: str,
        line: int,
        rel: str,
        src_lines: list[str],
    ) -> Finding:
        snippet = src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""

        if axis == "python_version":
            axis_phrase = "the Python interpreter version (ast.dump differs across minor versions)"
            fix = (
                "pin the generator to one interpreter (fail loudly on any other), "
                "and skip the gate off that version"
            )
        else:
            axis_phrase = "line endings (CRLF vs LF) and OS"
            fix = (
                "normalize the input to LF before hashing (and pin the file to "
                "eol=lf via .gitattributes)"
            )

        mit_note = (
            f" An in-file mitigation is visible ({mitigation_kind}); a follow-up "
            "context-confirmation pass will verify it."
            if mitigated
            else " No in-file mitigation is visible."
        )
        severity = Severity.LOW if mitigated else Severity.MEDIUM
        confidence = 0.5 if mitigated else 0.7

        message = (
            f"'{fn_name}' hashes an input that varies by {axis_phrase}, then this "
            f"hash is typically asserted byte-equal against a stored value — it will "
            f"pass in the context it was baked in and fail in any other. "
            f"Fix: {fix} — record the context, don't just regenerate.{mit_note}"
        )
        fingerprint = make_fingerprint(rule_id, rel, fn_name, snippet)
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.CONTEXT_PINNED_HASH,
            severity=severity,
            confidence=confidence,
            message=message,
            location=Location(path=rel, line_start=line, line_end=line),
            fingerprint=fingerprint,
            snippet=snippet,
            metadata={
                "rule_id": rule_id,
                "context_axis": axis,
                "mitigation_detected": mitigated,
                "mitigation_kind": mitigation_kind,
                # v1 is a source-pattern heuristic; the v2 pass reads
                # .gitattributes / CI matrix / manifest context fields and sets
                # this True or clears the finding. Enrichment, not rework.
                "context_confirmed": False,
            },
        )


# ── AST feature detection (module-scoped) ───────────────────────────


def _module_has_version_guard(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _VERSION_GUARD_NAMES:
            return True
        if isinstance(node, ast.Name) and node.id in _VERSION_GUARD_NAMES:
            return True
    return False


class _ScopeFeatures:
    __slots__ = (
        "has_hash", "hashes_ast_dump", "hashes_file_bytes",
        "has_lf_normalize", "hash_line",
    )

    def __init__(self) -> None:
        self.has_hash = False
        self.hashes_ast_dump = False
        self.hashes_file_bytes = False
        self.has_lf_normalize = False
        self.hash_line = 0


def _hash_wrapper_names(tree: ast.Module) -> frozenset[str]:
    """Names of module-local functions whose body computes a hash."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and _is_hash_constructor(sub):
                    names.add(node.name)
                    break
    return frozenset(names)


def _scope_features(fn: ast.AST, hash_wrappers: frozenset[str] = frozenset()) -> _ScopeFeatures:
    """Detect, within a single function body, whether it computes a hash and
    feeds it a context-sensitive input, plus any in-scope mitigation."""
    f = _ScopeFeatures()
    fn_name = getattr(fn, "name", None)
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            is_hash = _is_hash_constructor(node) or _calls_hash_wrapper(node, hash_wrappers, fn_name)
            if is_hash:
                f.has_hash = True
                if not f.hash_line:
                    f.hash_line = getattr(node, "lineno", 0)
            if _is_ast_dump(node):
                f.hashes_ast_dump = True
            if _is_binary_file_read(node):
                f.hashes_file_bytes = True
            if _is_lf_normalize(node):
                f.has_lf_normalize = True
    return f


def _is_hash_constructor(call: ast.Call) -> bool:
    fn = call.func
    # hashlib.sha256(...) / hashlib.md5(...) / x.sha256(...)
    if isinstance(fn, ast.Attribute):
        if fn.attr in _HASH_FUNCS:
            return True
        # hashlib.new("sha256", ...)
        if fn.attr == "new" and isinstance(fn.value, ast.Name) and fn.value.id == "hashlib":
            return True
    # bare sha256(...) after `from hashlib import sha256`
    if isinstance(fn, ast.Name) and fn.id in _HASH_FUNCS:
        return True
    return False


def _calls_hash_wrapper(
    call: ast.Call, hash_wrappers: frozenset[str], current_fn: str | None
) -> bool:
    if not hash_wrappers:
        return False
    fn = call.func
    name = None
    if isinstance(fn, ast.Name):
        name = fn.id
    elif isinstance(fn, ast.Attribute):
        name = fn.attr
    # A call to a module-local hash-wrapper (not the function itself).
    return name in hash_wrappers and name != current_fn


def _is_ast_dump(call: ast.Call) -> bool:
    fn = call.func
    if isinstance(fn, ast.Attribute) and fn.attr == "dump":
        # ast.dump(...) — receiver named 'ast'
        if isinstance(fn.value, ast.Name) and fn.value.id == "ast":
            return True
    # bare dump(...) after `from ast import dump`
    if isinstance(fn, ast.Name) and fn.id == "dump":
        return True
    return False


def _is_binary_file_read(call: ast.Call) -> bool:
    fn = call.func
    if isinstance(fn, ast.Attribute):
        if fn.attr == "read_bytes":            # path.read_bytes()
            return True
        if fn.attr == "open":                  # path.open("rb")
            return _has_binary_mode_arg(call)
    if isinstance(fn, ast.Name) and fn.id == "open":  # open(path, "rb")
        return _has_binary_mode_arg(call)
    return False


def _has_binary_mode_arg(call: ast.Call) -> bool:
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and "b" in arg.value:
            return True
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant) \
                and isinstance(kw.value.value, str) and "b" in kw.value.value:
            return True
    return False


def _is_lf_normalize(call: ast.Call) -> bool:
    """Detect ``x.replace(b'\\r\\n', b'\\n')`` / ``x.replace('\\r\\n', '\\n')``."""
    fn = call.func
    if not (isinstance(fn, ast.Attribute) and fn.attr == "replace"):
        return False
    if not call.args:
        return False
    first = call.args[0]
    if isinstance(first, ast.Constant):
        v = first.value
        if isinstance(v, (bytes, str)):
            return b"\r\n" == v if isinstance(v, bytes) else "\r\n" == v
    return False
