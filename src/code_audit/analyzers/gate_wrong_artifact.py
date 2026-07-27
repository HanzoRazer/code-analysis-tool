"""Gate-validates-wrong-artifact detector.

A validation/gate is supposed to guard the artifact that ships. This detector
flags two ways that guarantee breaks — the gate inspects something other than
what actually leaves the function:

1. **Validated-then-modified** (the gate runs before the artifact is final,
   ordering #9): a variable is validated, then reassigned or mutated, then
   returned. The shipped value is the *post*-validation form, which was never
   checked. ``validate(x); x = finalize(x); return x``.

2. **Validated-then-abandoned** (the wrong object, Family I): a locally-built
   artifact is validated but a *different* locally-built artifact is returned,
   and the validated one is never used again. ``validate(all_contours); return
   classified`` — the gate checked ``all_contours`` and shipped ``classified``.

Both are the scale-validation bug shape: green gate, wrong artifact shipped.

**Precision over recall.** To avoid firing on the common, correct pattern
``validate(input); return transform(input)`` (where the shipped value derives
from the validated one), signal 2 requires the validated variable to be a
*local build* (not a parameter — parameters are usually preconditions/guards)
and to be entirely unused after the validation. ``Finding.metadata`` carries
``gate_covers_shipped_confirmed=False`` for a v2 pass that can trace derivation
precisely (and add write/export ship sites beyond ``return``).

Emits: the gate must inspect the shipped artifact, in its final form.
"""
from __future__ import annotations

import ast
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_MODIFIED = "GATE_WRONG_ARTIFACT_MODIFIED_001"
_RULE_ABANDONED = "GATE_WRONG_ARTIFACT_ABANDONED_001"

# In-place mutation methods that finalize/change an artifact after validation.
_MUTATOR_METHODS = frozenset({
    "append", "extend", "insert", "update", "add", "pop", "remove", "clear",
    "sort", "setdefault", "popitem", "discard", "__setitem__",
})
# kwargs commonly naming the validated instance in schema validators.
_INSTANCE_KWARGS = frozenset({"instance", "obj", "data", "value", "payload"})


class GateWrongArtifactAnalyzer:
    """Flag a validation that inspects something other than what the function ships."""

    id: str = "gate_wrong_artifact"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(src, filename=str(path))
            except (OSError, SyntaxError, ValueError):
                continue
            try:
                rel = path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                rel = path.name
            src_lines = src.splitlines()
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    findings.extend(self._analyze_fn(fn, rel, src_lines))
        findings.sort(key=lambda f: (f.location.path, f.location.line_start))
        return findings

    # ── per-function analysis ───────────────────────────────────────

    def _analyze_fn(
        self, fn: ast.AST, rel: str, src_lines: list[str]
    ) -> list[Finding]:
        info = _FnInfo(fn)
        findings: list[Finding] = []

        for var, vline in info.validations.items():
            # Signal 1: validated → modified after → returned after the modify.
            mod_lines = [ln for ln in info.mutated.get(var, []) if ln > vline]
            ret_after_mod = [
                rl for (rv, rl) in info.returns
                if rv == var and mod_lines and rl >= min(mod_lines)
            ]
            if ret_after_mod:
                findings.append(self._emit_modified(
                    var, vline, min(mod_lines), rel, src_lines))
                continue

            # Signal 2: validated local artifact, abandoned; a different local
            # artifact is returned.
            if var in info.params or var not in info.local_builds:
                continue
            used_after = any(ln > vline for ln in info.uses.get(var, []))
            if used_after:
                continue
            other_returns = [
                (rv, rl) for (rv, rl) in info.returns
                if rv != var and rv in info.local_builds
            ]
            if other_returns:
                rv, rl = other_returns[0]
                findings.append(self._emit_abandoned(
                    var, vline, rv, rl, rel, src_lines))

        return findings

    # ── finding construction ────────────────────────────────────────

    def _emit_modified(self, var, vline, mline, rel, src_lines) -> Finding:
        snippet = src_lines[vline - 1].strip() if 0 < vline <= len(src_lines) else ""
        message = (
            f"'{var}' is validated (line {vline}) but then modified (line {mline}) "
            f"before being returned — the shipped value is the post-validation form, "
            f"which was never checked. The gate runs before the artifact is final. "
            f"Fix: validate '{var}' after its last modification, on the value you ship."
        )
        fp = make_fingerprint(_RULE_MODIFIED, rel, var, f"{vline}:{mline}")
        return self._finding(_RULE_MODIFIED, fp, message, rel, vline,
                             {"validated_var": var, "validated_line": vline,
                              "modified_line": mline})

    def _emit_abandoned(self, var, vline, ship, sline, rel, src_lines) -> Finding:
        snippet = src_lines[vline - 1].strip() if 0 < vline <= len(src_lines) else ""
        message = (
            f"'{var}' is validated (line {vline}) but a different artifact '{ship}' "
            f"is returned (line {sline}), and '{var}' is never used after the check — "
            f"the gate inspects one object and ships another. "
            f"Fix: validate the shipped artifact '{ship}', not '{var}'."
        )
        fp = make_fingerprint(_RULE_ABANDONED, rel, f"{var}->{ship}", str(vline))
        return self._finding(_RULE_ABANDONED, fp, message, rel, vline,
                             {"validated_var": var, "validated_line": vline,
                              "shipped_var": ship, "shipped_line": sline})

    def _finding(self, rule_id, fp, message, rel, line, extra) -> Finding:
        meta = {"rule_id": rule_id, "gate_covers_shipped_confirmed": False}
        meta.update(extra)
        return Finding(
            finding_id=fp,
            type=AnalyzerType.GATE_WRONG_ARTIFACT,
            severity=Severity.MEDIUM,
            confidence=0.6,
            message=message,
            location=Location(path=rel, line_start=line, line_end=line),
            fingerprint=fp,
            snippet="",
            metadata=meta,
        )


# ── per-function fact collection (no descent into nested functions) ─


class _FnInfo:
    def __init__(self, fn: ast.AST) -> None:
        self.validations: dict[str, int] = {}   # var -> first validation line
        self.mutated: dict[str, list[int]] = {}  # var -> assign/mutate lines
        self.uses: dict[str, list[int]] = {}     # var -> Load lines
        self.local_builds: set[str] = set()      # vars assigned from a Call
        self.params: set[str] = set()
        self.returns: list[tuple[str, int]] = []  # (returned Name, line)

        args = getattr(fn, "args", None)
        if args is not None:
            for a in (
                list(args.args) + list(args.posonlyargs) + list(args.kwonlyargs)
            ):
                self.params.add(a.arg)
            if args.vararg:
                self.params.add(args.vararg.arg)
            if args.kwarg:
                self.params.add(args.kwarg.arg)

        for node in _walk_local(fn):
            self._visit(node)

    def _visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            self._visit_call(node)
        elif isinstance(node, ast.Assign):
            line = getattr(node, "lineno", 0)
            for t in node.targets:
                for name in _target_names(t):
                    self.mutated.setdefault(name, []).append(line)
            if isinstance(node.value, ast.Call):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.local_builds.add(t.id)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            line = getattr(node, "lineno", 0)
            for name in _target_names(node.target):
                self.mutated.setdefault(name, []).append(line)
        elif isinstance(node, ast.Return):
            if isinstance(node.value, ast.Name):
                self.returns.append((node.value.id, getattr(node, "lineno", 0)))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            self.uses.setdefault(node.id, []).append(getattr(node, "lineno", 0))

    def _visit_call(self, node: ast.Call) -> None:
        line = getattr(node, "lineno", 0)
        func = node.func
        # in-place mutation: X.append(...), X.update(...), X[k] = ... handled by Assign
        if isinstance(func, ast.Attribute):
            if func.attr in _MUTATOR_METHODS and isinstance(func.value, ast.Name):
                self.mutated.setdefault(func.value.id, []).append(line)
            # X.validate() / X.is_valid()
            if _is_validation_name(func.attr) and isinstance(func.value, ast.Name):
                self.validations.setdefault(func.value.id, line)
        # validate(X) / validate(instance=X) / mod.validate(X)
        name = _callee_name(func)
        if name is not None and _is_validation_name(name):
            for v in _validated_args(node):
                self.validations.setdefault(v, line)


# ── helpers ─────────────────────────────────────────────────────────


def _walk_local(fn: ast.AST):
    """Yield nodes inside *fn* without descending into nested function/lambda scopes."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue  # separate scope
        stack.extend(ast.iter_child_nodes(node))


def _is_validation_name(name: str) -> bool:
    if name in {"validate", "is_valid", "assert_valid"}:
        return True
    return (
        name.startswith(("validate_", "check_", "verify_"))
        or name.endswith("_valid")
    )


def _callee_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _validated_args(call: ast.Call) -> list[str]:
    out: list[str] = []
    if call.args and isinstance(call.args[0], ast.Name):
        out.append(call.args[0].id)
    for kw in call.keywords:
        if kw.arg in _INSTANCE_KWARGS and isinstance(kw.value, ast.Name):
            out.append(kw.value.id)
    return out


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    # X[k] = ...  /  X.attr = ...  → X is mutated
    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
        return [target.value.id]
    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
        return [target.value.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for e in target.elts:
            names.extend(_target_names(e))
        return names
    return []
