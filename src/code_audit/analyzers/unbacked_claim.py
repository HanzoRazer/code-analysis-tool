"""Unbacked-capability-claim analyzer — a comment/docstring claims a dependency the module never imports.

A comment or docstring says the code *uses* or *falls back to* a library, but that
library is imported nowhere in the module — so the claimed code path cannot exist.
The purest failure-mimics-success shape: a claim of a capability that isn't there,
in front of a substitute that returns a right-shaped answer to a different
calculation. Motivating instance (MAINT-DEFER-010): ``rayleigh_ritz.py`` carried
``# Fallback to scipy if available`` with **no scipy imported anywhere**; what ran
was ``np.diag(K)/np.diag(M)`` with ``np.eye()`` mode shapes — every off-diagonal
coupling discarded, every mode shape a unit vector. Not a degraded solve of the
stated problem, a *different* calculation returning the same shape, and silent, so a
caller cannot tell which one they got.

Conceptually adjacent to name != behavior, but the mechanical signature is specific
and cheap: a capability-shaped claim naming a known library whose import is absent
from the module. Distinct from ``exceptions`` (broad-except) and from the
requirements/deployment analyzers (missing *third-party install*): this fires only
on a first-person capability claim contradicted by the module's own imports.

Severity: HIGH when the claim is a *fallback / if-available* shape (the silent
substitution case), MEDIUM for a plain "uses X" / "X-based" claim. A mere mention
in prose ("faster than scipy") is not a capability claim and stays silent — the
claim shape is the discriminator, not the bare name.

Every failure mode is a Finding, never a raised exception — a crash here would
abort the whole scan, the same silent pass this analyzer exists to prevent.
"""
from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "UNBACKED_CLAIM_001"
_ERROR_RULE_ID = "UNBACKED_CLAIM_ERROR"

_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
})
_MAX_FILE_BYTES = 2_000_000

# Prose name (as written in a comment) -> import name to check against. Heavy /
# optional compute libs only — never numpy/pandas/requests, which are near-ubiquitous
# and would drown the signal. A claim naming one of these that the module does not
# import is the signal.
_LIB_ALIASES: dict[str, str] = {
    "scipy": "scipy", "numba": "numba", "torch": "torch", "pytorch": "torch",
    "tensorflow": "tensorflow", "jax": "jax", "sklearn": "sklearn",
    "scikit-learn": "sklearn", "cython": "cython", "cupy": "cupy", "dask": "dask",
    "joblib": "joblib", "sympy": "sympy", "numexpr": "numexpr",
    "statsmodels": "statsmodels", "xgboost": "xgboost", "lightgbm": "lightgbm",
    "opencv": "cv2", "cv2": "cv2", "onnxruntime": "onnxruntime", "onnx": "onnx",
    "polars": "polars", "pyarrow": "pyarrow", "networkx": "networkx",
}
# Longest-first so "scikit-learn" wins over a bare "sklearn" substring, etc.
_LIB_ALT = "(" + "|".join(
    re.escape(k) for k in sorted(_LIB_ALIASES, key=len, reverse=True)
) + ")"


def _compile(templates: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(t.format(LIB=_LIB_ALT), re.IGNORECASE) for t in templates]


# Fallback / availability shapes → the silent-substitution case (HIGH).
_HIGH_PATTERNS = _compile([
    r"\bfall(?:s|ing)?\s+back\s+(?:to|on)\s+{LIB}\b",
    r"\bfallback\s*(?:to|on|:)?\s*{LIB}\b",
    r"\bif\s+{LIB}\s+(?:is\s+)?(?:available|installed|present)\b",
    r"\b{LIB}\s+if\s+(?:available|installed|present)\b",
    r"\bwhen\s+{LIB}\s+is\s+(?:available|installed|present)\b",
    r"\buse\s+{LIB}\s+if\s+(?:available|installed|present)\b",
    r"\b(?:tries?|try)\s+(?:to\s+use\s+)?{LIB}\b.*\bavailable\b",
])
# Plain capability claims (MEDIUM).
_MED_PATTERNS = _compile([
    r"\buses?\s+{LIB}\b",
    r"\busing\s+{LIB}\b",
    r"\b{LIB}-based\b",
    r"\b{LIB}\s+backend\b",
    r"\bpowered\s+by\s+{LIB}\b",
    r"\bbacked\s+by\s+{LIB}\b",
    r"\bbuilt\s+on\s+{LIB}\b",
    r"\bvia\s+{LIB}\b",
])

# `importlib.import_module("scipy")` — a dynamic import that the AST import walk
# would miss; count it as imported to avoid a false claim.
_DYNAMIC_IMPORT_RE = re.compile(r"import_module\(\s*['\"]([\w.]+)['\"]")


class _Claim:
    __slots__ = ("lib", "token", "kind", "line", "source")

    def __init__(self, lib: str, token: str, kind: str, line: int, source: str) -> None:
        self.lib = lib        # normalized import name
        self.token = token    # prose token as written
        self.kind = kind      # fallback | plain
        self.line = line
        self.source = source  # comment | docstring


# Pure helpers are module-level functions (not methods) so the analyzer class stays
# small — the tool's own god-class metric applies to it too.

def _imported_names(tree: ast.AST, source: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".", 1)[0])
    for m in _DYNAMIC_IMPORT_RE.finditer(source):
        names.add(m.group(1).split(".", 1)[0])
    return names


def _comment_lines(source: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                out.append((tok.start[0], tok.string))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        pass
    return out


def _docstrings(tree: ast.AST) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        doc = ast.get_docstring(node, clean=False)
        if not doc:
            continue
        body = getattr(node, "body", None)
        first = body[0] if body else None
        base = getattr(getattr(first, "value", None), "lineno",
                       getattr(node, "lineno", 1))
        out.append((base, doc))
    return out


def _match_line(text: str, lineno: int, src: str, claims: list[_Claim]) -> None:
    # HIGH first; a (line, lib) already claimed HIGH is not downgraded to MED.
    hit: dict[str, tuple[str, str]] = {}  # import-name -> (kind, prose token)
    for pattern in _HIGH_PATTERNS:
        for m in pattern.finditer(text):
            token = m.group(1)
            hit.setdefault(_LIB_ALIASES[token.lower()], ("fallback", token))
    for pattern in _MED_PATTERNS:
        for m in pattern.finditer(text):
            token = m.group(1)
            hit.setdefault(_LIB_ALIASES[token.lower()], ("plain", token))
    for lib, (kind, token) in hit.items():
        claims.append(_Claim(lib, token, kind, lineno, src))


def _collect_claims(source: str, tree: ast.AST) -> list[_Claim]:
    lines: list[tuple[int, str, str]] = []  # (lineno, text, source_kind)
    for lineno, text in _comment_lines(source):
        lines.append((lineno, text, "comment"))
    for base, doc in _docstrings(tree):
        for offset, dl in enumerate(doc.splitlines()):
            lines.append((base + offset, dl, "docstring"))
    claims: list[_Claim] = []
    for lineno, text, src in lines:
        _match_line(text, lineno, src, claims)
    return claims


class UnbackedClaimAnalyzer:
    """Detect capability claims naming a library the module never imports."""

    id: str = "unbacked_claim"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        try:
            return self._run_inner(root)
        except Exception as exc:  # noqa: BLE001 — fail loud as a finding, never raise
            return [self._error_finding(
                f"unbacked_claim analysis raised {type(exc).__name__}: {exc}."
            )]

    def _run_inner(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in sorted(root.rglob("*.py")):
            try:
                if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
                    continue
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                rel = path.relative_to(root).as_posix()
            except (OSError, ValueError):
                continue
            findings.extend(self._scan_file(path, rel))
        findings.sort(key=lambda f: (f.location.path, f.location.line_start,
                                     f.metadata["claimed_library"]))
        return findings

    def _scan_file(self, path: Path, rel: str) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, ValueError):
            return []  # unparseable file: no reliable import set to compare against

        imported = _imported_names(tree, source)
        out: list[Finding] = []
        seen: set[tuple[int, str]] = set()
        for claim in _collect_claims(source, tree):
            if claim.lib in imported:
                continue  # the module does import it — claim is backed
            key = (claim.line, claim.lib)
            if key in seen:
                continue
            seen.add(key)
            out.append(self._finding(rel, claim))
        return out

    def _finding(self, rel: str, claim: _Claim) -> Finding:
        severity = Severity.HIGH if claim.kind == "fallback" else Severity.MEDIUM
        confidence = 0.85 if claim.kind == "fallback" else 0.8
        detail = (
            "This reads as a silent fallback: the claimed path cannot run, so a "
            "different calculation runs in its place and returns a same-shaped "
            "result a caller cannot distinguish."
            if claim.kind == "fallback" else
            "The claimed capability cannot run because the library is absent."
        )
        message = (
            f"'{rel}' {claim.source} claims '{claim.lib}' ({claim.kind} claim) but "
            f"'{claim.lib}' is imported nowhere in the module. {detail} Fix: import "
            f"'{claim.lib}' and back the claim, or correct the comment/docstring to "
            f"describe what actually runs."
        )
        fingerprint = make_fingerprint(_RULE_ID, rel, claim.lib, str(claim.line))
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.UNBACKED_CLAIM,
            severity=severity,
            confidence=confidence,
            message=message,
            location=Location(path=rel, line_start=claim.line, line_end=claim.line),
            fingerprint=fingerprint,
            metadata={
                "rule_id": _RULE_ID,
                "claimed_library": claim.lib,
                "claim_kind": claim.kind,
                "source": claim.source,
            },
        )

    def _error_finding(self, message: str) -> Finding:
        fingerprint = make_fingerprint(_ERROR_RULE_ID, ".", "unbacked_claim", "")
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.UNBACKED_CLAIM,
            severity=Severity.LOW,
            confidence=0.99,
            message=(
                f"{message} unbacked_claim failing loud as a finding rather than "
                f"aborting the scan."
            ),
            location=Location(path=".", line_start=1, line_end=1),
            fingerprint=fingerprint,
            metadata={"rule_id": _ERROR_RULE_ID},
        )
