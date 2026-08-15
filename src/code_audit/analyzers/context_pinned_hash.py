"""Context-pinned hash detector.

Flags a hash (sha256/sha1/md5/…) computed over an input whose bytes depend on a
**context the hash does not record** — line endings (CRLF vs LF), interpreter
version (``ast.dump`` differs across Python minor versions), float shortest-repr
(platform ULP / formatting drift), or OS — and then asserted byte-equal against a
stored value. Such a hash passes in the context it was baked in and fails
everywhere else: the classic "green on my machine, red on CI" manifest/golden-
file bug that no mainstream linter checks for.

**Family II (implicit context).** Every team that bakes a hash on one platform
and checks it on another has this latent defect — a lockfile digest, a golden-
file test, an AST-fingerprint gate, a geometry ``report_id``.

**v1 is a source-pattern heuristic.** It finds the *candidate* — a function that
both computes a hash and feeds it a context-sensitive input — and records, in the
finding's ``metadata``, which context axis is at risk and whether an *in-file*
mitigation is visible (LF-normalization for byte hashes; a Python-version guard
for ``ast.dump`` hashes; float quantization before serialise+hash). It sets
``context_confirmed = False`` because the real mitigation may live outside the
source (``.gitattributes eol=lf``, a CI matrix pin, a context field recorded in
the manifest). A follow-up pass (v2) reads those artifacts and confirms/clears
each finding — it enriches this metadata rather than restructuring it, so
nothing here has to change.

**The float axis is payload-scoped, not function-scoped.** A serialiser call
(``json.dumps(...)``) only opens the ``float_repr`` axis when *its own argument*
carries float evidence — a true division, a float literal, a ``float``/``round``/
``Decimal``/``math.*`` call, or a ``float``-annotated name — resolved one hop
through local assignments. The same resolution decides mitigation, so a
``round()`` elsewhere in the function does not silently downgrade an unrelated
unquantized hash, and hashing ``json.dumps({"name": "x"})`` stays silent.
Binary serialisers (``pickle``/``marshal``/``msgpack``) write IEEE-754 bytes,
not shortest-repr text, so they are excluded from the axis entirely.

That resolution is one hop and deliberately buys precision with recall: a
payload built behind a call (``json.dumps(build_payload())``) or accumulated in
a loop variable carries no visible evidence, so it is *not* flagged. On a
detector whose whole value is being believed, a miss costs less than a false
alarm; the v2 pass, which reads the serialised artifact itself, is where that
recall comes back.

Fix it emits: *record the context* — normalize the input (LF), pin the generator
(one interpreter), quantize floats before serialising, or declare the context in
the manifest — not a one-off regenerate, which only relocates the defect to the
next context.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# Hash constructors whose output is byte-exact and therefore context-sensitive.
_HASH_FUNCS = frozenset(
    {"sha256", "sha1", "sha224", "sha384", "sha512", "md5", "blake2b", "blake2s"}
)

_RULE_BYTE = "CTX_PINNED_HASH_BYTES_001"   # line-ending / OS axis
_RULE_AST = "CTX_PINNED_HASH_AST_001"      # interpreter-version axis
_RULE_FLOAT = "CTX_PINNED_HASH_FLOAT_001"  # float shortest-repr axis

# Names that, present anywhere in the module, indicate the generator is pinned to
# one interpreter (mitigation for the ast.dump / interpreter-version axis).
_VERSION_GUARD_NAMES = frozenset(
    {"version_info", "require_ci_python", "_require_ci_python",
     "_REQUIRED_PYTHON", "_CI_PYTHON", "CI_PYTHON"}
)

# f-string / format specs that look like float formatting with an explicit
# precision — e.g. ``.9g``, ``.6f``, ``#.12e`` — count as in-file quantization.
_FLOAT_QUANTIZE_SPEC = re.compile(r"\.\d+[fgFeE]")

# ``*.dumps`` receivers that emit IEEE-754 bytes rather than shortest-repr text.
# A float round-trips through these byte-exactly, so they are not on this axis.
_BINARY_SERIALISER_MODULES = frozenset(
    {"pickle", "cPickle", "dill", "marshal", "msgpack", "cbor2", "bson", "struct"}
)

# Modules whose calls return floats — evidence that a serialised payload is
# float-bearing even when no literal or division is visible at the call site.
_FLOAT_MODULES = frozenset({"math", "cmath", "statistics", "numpy", "np"})

# Builtins/constructors that produce a float (or a Decimal, which is serialised
# through ``float()`` by every mainstream JSON encoder).
_FLOAT_CALL_NAMES = frozenset({"float", "round", "Decimal", "fsum", "mean"})


class ContextPinnedHashAnalyzer:
    """Detect hashes asserted byte-equal across a context they weren't computed in."""

    id: str = "context_pinned_hash"
    version: str = "1.1.0"

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
            if feats.hashes_serialised_floats:
                findings.append(
                    self._emit(
                        rule_id=_RULE_FLOAT,
                        axis="float_repr",
                        mitigated=feats.has_quantize,
                        mitigation_kind="floats_quantized"
                        if feats.has_quantize else None,
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
        elif axis == "float_repr":
            axis_phrase = (
                "float shortest-repr (platform float formatting can differ by one "
                "ULP across platforms, and CI is structurally blind to that drift)"
            )
            fix = "quantize floats before serialising and hashing"
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
        "float_sites", "float_quantized_sites", "has_lf_normalize",
        "hash_line",
    )

    def __init__(self) -> None:
        self.has_hash = False
        self.hashes_ast_dump = False
        self.hashes_file_bytes = False
        # Float serialisation sites in this scope, and how many of them carry a
        # visible quantization. Counted per *site* (not a single function-wide
        # flag) so one quantized site cannot mitigate an unquantized sibling.
        self.float_sites = 0
        self.float_quantized_sites = 0
        self.has_lf_normalize = False
        self.hash_line = 0

    @property
    def hashes_serialised_floats(self) -> bool:
        return self.float_sites > 0

    @property
    def has_quantize(self) -> bool:
        """True only when *every* float serialisation site is quantized."""
        return self.float_sites > 0 and self.float_quantized_sites == self.float_sites


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
    # One-hop local dataflow: which expression(s) each local name was bound to,
    # and which names are declared float. Both scope the float axis to the
    # serialised *payload* instead of "anything anywhere in this function".
    assigns = _assignment_map(fn)
    float_names = _float_annotated_names(fn)

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
            if _is_payload_serialiser(node):
                # Only a payload that demonstrably carries floats opens the axis
                # — ``json.dumps({"name": "x"})`` is not a float hash.
                has_float = False
                has_raw = False
                for arg in node.args:
                    a_float, a_raw = _payload_float_state(arg, assigns, float_names)
                    has_float = has_float or a_float
                    has_raw = has_raw or a_raw
                if has_float:
                    f.float_sites += 1
                    if not has_raw:
                        f.float_quantized_sites += 1
            if _call_format_has_float_quantize(node):
                # ``"{:.9g}".format(x)`` / ``format(x, ".9g")`` — the explicit
                # precision is both the float evidence and the quantization.
                f.float_sites += 1
                f.float_quantized_sites += 1
        elif isinstance(node, ast.JoinedStr):
            serial, quant = _joined_str_float_feats(node)
            if serial:
                f.float_sites += 1
                if quant:
                    f.float_quantized_sites += 1
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


def _is_payload_serialiser(call: ast.Call) -> bool:
    """Detect a *text* serialiser whose float output is shortest-repr sensitive.

    Primary POS-007 shape: ``json.dumps(...)`` (and sibling ``*.dumps``). This
    predicate answers "is this serialisation?" only — whether the payload is
    float-bearing is decided separately by ``_node_is_float_evidence`` against
    the call's own arguments, so ``json.dumps({"name": "x"})`` does not fire.

    Binary ``*.dumps`` (``pickle``/``marshal``/``msgpack``/…) writes IEEE-754
    bytes, which round-trip exactly, and is excluded.
    """
    fn = call.func
    if isinstance(fn, ast.Attribute) and fn.attr == "dumps":
        recv = fn.value
        if isinstance(recv, ast.Name) and recv.id in _BINARY_SERIALISER_MODULES:
            return False
        if isinstance(recv, ast.Attribute) and recv.attr in _BINARY_SERIALISER_MODULES:
            return False
        return True
    if isinstance(fn, ast.Name) and fn.id == "dumps":
        return True
    return False


def _is_quantiser(call: ast.Call) -> bool:
    """Detect in-file float quantization before serialise+hash."""
    fn = call.func
    if isinstance(fn, ast.Name) and fn.id == "round":
        return True
    if isinstance(fn, ast.Attribute) and fn.attr == "quantize":
        return True
    if _call_format_has_float_quantize(call):
        return True
    return False


def _is_float_producing_call(call: ast.Call) -> bool:
    """True when *call* returns a float (or a Decimal serialised as one)."""
    fn = call.func
    if isinstance(fn, ast.Name) and fn.id in _FLOAT_CALL_NAMES:
        return True
    if isinstance(fn, ast.Attribute):
        if fn.attr == "quantize":
            return True
        if isinstance(fn.value, ast.Name) and fn.value.id in _FLOAT_MODULES:
            return True
    return False


def _node_is_float_evidence(node: ast.AST, float_names: frozenset[str]) -> bool:
    """True when *node itself* shows the value being serialised is a float.

    Deliberately narrow — this is what keeps the ``float_repr`` axis off every
    ``dumps(...)`` of a string/int/bool payload.
    """
    if isinstance(node, ast.Constant):
        # bool is a subclass of int, not float; complex is not shortest-repr.
        return isinstance(node.value, float)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return True          # true division always yields a float
    if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Div):
        return True
    if isinstance(node, ast.Call):
        return _is_float_producing_call(node) or _call_format_has_float_quantize(node)
    if isinstance(node, ast.Name):
        return node.id in float_names
    if isinstance(node, ast.JoinedStr):
        return _joined_str_float_feats(node)[0]
    return False


def _node_is_quantiser(node: ast.AST) -> bool:
    """True when *node itself* is a visible float-quantization step."""
    if isinstance(node, ast.Call):
        return _is_quantiser(node)
    if isinstance(node, ast.JoinedStr):
        return _joined_str_float_feats(node)[1]
    return False


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[str] = []
        for el in target.elts:
            out.extend(_target_names(el))
        return out
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _assignment_map(fn: ast.AST) -> dict[str, list[ast.AST]]:
    """``name -> value expressions bound to it`` within this scope.

    One hop of local dataflow: enough to follow the ubiquitous
    ``payload = {...}; json.dumps(payload)`` shape without a real solver.
    """
    out: dict[str, list[ast.AST]] = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                for name in _target_names(tgt):
                    out.setdefault(name, []).append(node.value)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if node.value is not None:
                for name in _target_names(node.target):
                    out.setdefault(name, []).append(node.value)
        elif isinstance(node, ast.NamedExpr):
            for name in _target_names(node.target):
                out.setdefault(name, []).append(node.value)
    return out


def _payload_float_state(
    node: ast.AST,
    assigns: dict[str, list[ast.AST]],
    float_names: frozenset[str],
) -> tuple[bool, bool]:
    """Return ``(has_float, has_unquantized_float)`` for a serialised payload.

    Local names are followed one hop through *assigns*, so the ubiquitous
    ``payload = {...}; json.dumps(payload)`` shape is seen through. Descent
    **stops** at a quantization boundary — ``round(...)``, ``.quantize(...)``, a
    precision format — because everything under it is already pinned.

    Reporting the two flags separately is what stops one quantized field from
    covering for a raw sibling: ``{"a": round(x, 9), "b": y / 3}`` is float-
    bearing *and* still unquantized, so it stays MEDIUM.
    """
    seen: set[str] = set()
    has_float = False
    has_unquantized = False

    def visit(n: ast.AST) -> None:
        nonlocal has_float, has_unquantized
        if _node_is_quantiser(n):
            has_float = True
            return                              # pinned subtree — do not descend
        if _node_is_float_evidence(n, float_names):
            has_float = True
            has_unquantized = True
        if isinstance(n, ast.Name) and n.id not in seen:
            values = assigns.get(n.id)
            if values:
                seen.add(n.id)                  # terminates ``x = x / 2``
                for value in values:
                    visit(value)
        for child in ast.iter_child_nodes(n):
            visit(child)

    visit(node)
    return has_float, has_unquantized


def _annotation_is_float(ann: ast.AST | None) -> bool:
    if ann is None:
        return False
    if isinstance(ann, ast.Name):
        return ann.id in {"float", "Decimal"}
    if isinstance(ann, ast.Attribute):
        return ann.attr in {"float", "Decimal"}
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        return "float" in ann.value or "Decimal" in ann.value
    if isinstance(ann, ast.Subscript):   # list[float], Optional[float], dict[str, float]
        return _annotation_is_float(ann.slice)
    if isinstance(ann, ast.Tuple):
        return any(_annotation_is_float(e) for e in ann.elts)
    if isinstance(ann, ast.BinOp):       # float | None
        return _annotation_is_float(ann.left) or _annotation_is_float(ann.right)
    return False


def _float_annotated_names(fn: ast.AST) -> frozenset[str]:
    """Parameters / locals declared ``float`` — evidence without a literal."""
    names: set[str] = set()
    args = getattr(fn, "args", None)
    if isinstance(args, ast.arguments):
        declared = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if args.vararg is not None:
            declared.append(args.vararg)
        if args.kwarg is not None:
            declared.append(args.kwarg)
        for a in declared:
            if _annotation_is_float(a.annotation):
                names.add(a.arg)
    for node in ast.walk(fn):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if _annotation_is_float(node.annotation):
                names.add(node.target.id)
    return frozenset(names)


def _call_format_has_float_quantize(call: ast.Call) -> bool:
    fn = call.func
    # format(value, ".9g")
    if isinstance(fn, ast.Name) and fn.id == "format" and len(call.args) >= 2:
        spec = call.args[1]
        if isinstance(spec, ast.Constant) and isinstance(spec.value, str):
            return bool(_FLOAT_QUANTIZE_SPEC.search(spec.value))
    # "{:.9g}".format(value)
    if isinstance(fn, ast.Attribute) and fn.attr == "format":
        recv = fn.value
        if isinstance(recv, ast.Constant) and isinstance(recv.value, str):
            return bool(_FLOAT_QUANTIZE_SPEC.search(recv.value))
    return False


def _format_spec_parts(spec: ast.AST | None) -> tuple[str, bool]:
    """Return ``(constant_text, has_dynamic_part)`` for an f-string format spec.

    ``has_dynamic_part`` is True for a computed precision — ``f"{x:.{p}f}"``,
    whose constant text is only ``".f"`` and so never matches the precision
    regex even though the author *did* pin the precision.
    """
    if spec is None:
        return "", False
    if isinstance(spec, ast.JoinedStr):
        parts: list[str] = []
        dynamic = False
        for v in spec.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                dynamic = True
        return "".join(parts), dynamic
    if isinstance(spec, ast.Constant) and isinstance(spec.value, str):
        return spec.value, False
    return "", False


def _joined_str_float_feats(node: ast.JoinedStr) -> tuple[bool, bool]:
    """Return ``(is_float_serialiser, is_quantised)`` for an f-string.

    A field whose format-spec ends in a float presentation type (``g``/``f``/
    ``e``) serialises a float. It counts as quantised only when the spec carries
    an **explicit** precision (``.9g``, ``.6f``) or a computed one
    (``f"{x:.{p}f}"``) — the POS-007-safe shape.

    ``is_quantised`` requires *every* float-formatted field to be quantised: one
    bare ``f"{x:g}"`` leaves the whole string shortest-repr sensitive. Fields
    with no float format-spec (``f"{name}"``) are ignored either way — nothing
    marks them as floats.
    """
    serial = False
    unquantized = 0
    for v in node.values:
        if not isinstance(v, ast.FormattedValue):
            continue
        text, dynamic = _format_spec_parts(v.format_spec)
        if not text:
            continue
        has_precision = bool(_FLOAT_QUANTIZE_SPEC.search(text))
        if not (has_precision or text[-1:] in "fgFeE"):
            continue
        serial = True
        if not (has_precision or (dynamic and "." in text)):
            unquantized += 1
    return serial, serial and unquantized == 0
