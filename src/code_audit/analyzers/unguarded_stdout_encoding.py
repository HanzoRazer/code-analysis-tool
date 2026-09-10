"""Unguarded stdout-encoding detector (the cp1252 class).

Flags a CLI entry module that writes non-ASCII text to stdout/stderr without
pinning the stream encoding. On Windows with a legacy locale codepage (cp1252 on
Western installs), Python below 3.15 opens a *non-console* stdout -- a pipe, a
redirect, a subprocess capture, a mintty/Git Bash terminal -- in that codepage.
An interactive console is unaffected (Python writes it via ``WriteConsoleW``),
which is why the bug survives manual testing in one shell and fails in another.

**Family II (implicit context)** -- the output-encoding sibling of
``context_pinned_hash``: the output's validity depends on a context the program
never records. It is a separate analyzer because every ``context_pinned_hash``
axis is scoped to a value that reaches a hash, and stdout is not a hash sink.

Three failure modes, depending on the stream and the character:

* ``encode_crash`` -- stdout, character outside cp1252 (``\\u2192``,
  ``\\u2500``, emoji). stdout's error handler is ``strict``, so the write raises
  ``UnicodeEncodeError`` and the process dies.
* ``escaped_output`` -- stderr, character outside cp1252. stderr uses
  ``backslashreplace``, so nothing crashes; the reader gets ``\\u2192`` text.
* ``undecodable_bytes`` -- either stream, non-ASCII character that cp1252 *can*
  encode (em-dash, bullet, ellipsis). The write succeeds as a cp1252 byte
  (``0x97`` for an em-dash) that a UTF-8 reader cannot decode -- e.g.
  ``subprocess.run(..., encoding="utf-8")`` loses the whole stream.

A module is an **entry** when it is named ``__main__.py``, has an
``if __name__ == "__main__":`` block, or imports argparse/click/typer and
defines a top-level ``main()``. A stream is **guarded** when the module calls
``<stream>.reconfigure(encoding="utf-8")`` or rebinds ``sys.stdout``/
``sys.stderr`` to a UTF-8 wrapper. ``PYTHONIOENCODING`` set *inside* the
process is not a guard -- it only affects child processes.

Two evidence tiers (one finding per module -- the fix is one guard at entry):

* **high** -- a non-ASCII string constant reaches an unguarded ``print`` /
  ``<stream>.write`` payload directly or through at most two local name
  bindings (the ``context_pinned_hash`` precedent). Through f-strings,
  concatenation, ``%``, ``*``, ``str.format``/``join``/``get`` and container
  subscripts. ``json.dumps`` (resolved through the module's imports) and
  ``ascii()`` are ASCII by construction unless ``ensure_ascii=False``.
* **low** -- nothing traces, but the module holds non-ASCII string constants
  *and* an unguarded sink prints a value the tracer could not reduce (a call
  result, a parameter, a loop variable, a name more than two bindings away).
  This is the ``print(content)`` shape, where ``content`` is assembled from a
  template constant many steps from the sink. Docstrings are not evidence
  unless the module reads them (a bare ``__doc__`` releases the module
  docstring, ``obj.__doc__`` releases class/function docstrings). Comparison
  operands, subscript and dict keys, ``re.*`` arguments, the pattern argument
  of string matchers (``startswith``, ``split``, ``replace``'s first argument,
  ...) and the key of ``.get`` are not evidence either: there the text matches
  input rather than producing output.

``guard_confirmed`` is ``False`` in v1: the guard may live outside the source
(``PYTHONIOENCODING``/``PYTHONUTF8`` in the invocation, a wrapper script, a
``requires-python`` of 3.15+ where PEP 686 makes UTF-8 mode the default). A v2
pass reads those and clears or downgrades -- enrichment, not rework.

Deliberate under-detection (stated, not hidden): a guard anywhere in the module
silences it, even if it runs after the first write; sinks in non-entry modules
(a library that prints, driven by an entry elsewhere) are not reported; logging
handlers, ``click.echo`` and argparse-rendered help are not modeled as sinks;
the codepage modeled is cp1252 (other legacy codepages fail the same way on
different characters).

Fix it emits: pin the stream at entry, before any output --
``sys.stdout.reconfigure(encoding="utf-8")`` (and stderr). Do not fix it by
setting ``PYTHONIOENCODING`` in the test harness: that keeps the test green
after the guard is deleted, destroying the regression witness.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unicodedata

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "UNGUARDED_STDOUT_ENCODING_001"
_CODEPAGE = "cp1252"
_NAME_HOPS = 2
_MAX_LISTED = 20

_STREAMS = ("stdout", "stderr")
_CLI_LIBS = frozenset({"argparse", "click", "typer"})
_UTF8 = frozenset({"utf-8", "utf8", "utf_8", "u8", "utf-8-sig"})

# String methods the tracer sees through, and which of their arguments are
# output: None = receiver only; "all" = receiver + every argument; an int n =
# receiver + positional arguments from index n on.
_SEE_THROUGH: dict[str, int | str | None] = {
    "format": "all", "join": "all", "format_map": "all",
    "get": 1, "replace": 1, "ljust": 1, "rjust": 1, "center": 1,
    "upper": None, "lower": None, "strip": None, "lstrip": None,
    "rstrip": None, "title": None, "capitalize": None, "expandtabs": None,
}
_SEE_THROUGH_BUILTINS = frozenset({"str", "repr", "format"})

# Methods whose (first) argument is a pattern matched against input, not text
# produced for output. ``replace``'s *first* argument is the needle.
_MATCHER_METHODS = frozenset({
    "startswith", "endswith", "split", "rsplit", "partition", "rpartition",
    "strip", "lstrip", "rstrip", "count", "find", "rfind", "index", "rindex",
    "removeprefix", "removesuffix", "maketrans", "translate",
})

_FAMILY = "II (implicit context)"


def _non_ascii(text: str) -> set[str]:
    return {c for c in text if ord(c) > 127}


def _cp1252_encodable(ch: str) -> bool:
    try:
        ch.encode(_CODEPAGE)
    except UnicodeEncodeError:
        return False
    return True


def _failure_modes(stream: str, chars: set[str]) -> set[str]:
    modes: set[str] = set()
    for ch in chars:
        if _cp1252_encodable(ch):
            modes.add("undecodable_bytes")
        elif stream == "stdout":
            modes.add("encode_crash")
        else:
            modes.add("escaped_output")
    return modes


def _describe(ch: str) -> str:
    """ASCII-only rendering, so the finding itself is safe on a cp1252 stream."""
    return f"U+{ord(ch):04X} {unicodedata.name(ch, 'UNNAMED')}"


def _describe_all(chars: set[str]) -> list[str]:
    return [_describe(c) for c in sorted(chars)]


# ── module facts ────────────────────────────────────────────────────


def _entry_kind(tree: ast.Module, filename: str) -> str | None:
    if filename == "__main__.py":
        return "__main__.py"
    for stmt in tree.body:
        if isinstance(stmt, ast.If) and _is_name_main_test(stmt.test):
            return "__name__ guard"
    imports_cli = False
    has_main = False
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            imports_cli |= any(a.name.split(".")[0] in _CLI_LIBS for a in stmt.names)
        elif isinstance(stmt, ast.ImportFrom) and stmt.module:
            imports_cli |= stmt.module.split(".")[0] in _CLI_LIBS
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            has_main |= stmt.name == "main"
    if imports_cli and has_main:
        return "cli main()"
    return None


def _is_name_main_test(test: ast.expr) -> bool:
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)):
        return False
    pair = (test.left, test.comparators[0])
    has_name = any(isinstance(n, ast.Name) and n.id == "__name__" for n in pair)
    has_main = any(isinstance(n, ast.Constant) and n.value == "__main__" for n in pair)
    return has_name and has_main


class _StreamRefs:
    """Resolve an expression to ``"stdout"``/``"stderr"`` through the module's
    own imports: ``sys.stdout``, ``import sys as s; s.stderr``,
    ``from sys import stderr [as err]``."""

    def __init__(self, tree: ast.Module) -> None:
        self.sys_aliases: set[str] = set()
        self.direct: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == "sys":
                        self.sys_aliases.add(a.asname or "sys")
            elif isinstance(node, ast.ImportFrom) and node.module == "sys":
                for a in node.names:
                    if a.name in _STREAMS:
                        self.direct[a.asname or a.name] = a.name

    def stream_of(self, node: ast.expr) -> str | None:
        if (isinstance(node, ast.Attribute) and node.attr in _STREAMS
                and isinstance(node.value, ast.Name)
                and node.value.id in self.sys_aliases):
            return node.attr
        if isinstance(node, ast.Name):
            return self.direct.get(node.id)
        return None


def _is_utf8_const(node: ast.expr | None) -> bool:
    return (isinstance(node, ast.Constant) and isinstance(node.value, str)
            and node.value.strip().lower() in _UTF8)


def _guarded_streams(tree: ast.Module, refs: _StreamRefs) -> set[str]:
    """Streams the module pins to UTF-8 anywhere in its source."""
    # ``for s in (sys.stdout, sys.stderr): s.reconfigure(...)`` -- the loop form.
    loop_streams: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.For) and isinstance(node.target, ast.Name)
                and isinstance(node.iter, (ast.Tuple, ast.List))):
            found = {s for e in node.iter.elts if (s := refs.stream_of(e))}
            if found:
                loop_streams.setdefault(node.target.id, set()).update(found)

    guarded: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "reconfigure"
                and any(k.arg == "encoding" and _is_utf8_const(k.value)
                        for k in node.keywords)):
            receiver = node.func.value
            stream = refs.stream_of(receiver)
            if stream:
                guarded.add(stream)
            elif isinstance(receiver, ast.Name) and receiver.id in loop_streams:
                guarded |= loop_streams[receiver.id]
            else:
                # Unknown receiver: assume it is a stream (under-detection).
                guarded.update(_STREAMS)
        elif isinstance(node, ast.Assign):
            # ``sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")``
            # / ``codecs.getwriter("utf-8")(...)``.
            utf8 = any(_is_utf8_const(n) for n in ast.walk(node.value))
            if utf8:
                for target in node.targets:
                    stream = refs.stream_of(target)
                    if stream:
                        guarded.add(stream)
    return guarded


# ── bindings & tracing ──────────────────────────────────────────────

def _own_nodes(scope: ast.AST):
    """Nodes belonging to *scope*, not descending into nested defs/classes."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(node))


class _Names:
    """Names a scope binds: ``values`` by a traceable assignment, ``other`` by
    anything else (parameter, loop/with target, import, tuple unpacking) --
    those are opaque and must shadow an outer binding of the same name."""

    __slots__ = ("values", "other")

    def __init__(self, scope: ast.AST) -> None:
        self.values: dict[str, list[ast.expr]] = {}
        self.other: set[str] = set()
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = scope.args
            for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg):
                if arg is not None:
                    self.other.add(arg.arg)
        for node in _own_nodes(scope):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    self._bind(t, node.value)
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                if node.value is not None:
                    self._bind(node.target, node.value)
            elif isinstance(node, ast.NamedExpr):
                self._bind(node.target, node.value)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self._opaque(node.target)
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                self._opaque(node.optional_vars)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self.other.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    self.other.add((alias.asname or alias.name).split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                   ast.ClassDef)):
                self.other.add(node.name)

    def _bind(self, target: ast.expr, value: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self.values.setdefault(target.id, []).append(value)
        else:
            self._opaque(target)

    def _opaque(self, target: ast.expr) -> None:
        for n in ast.walk(target):
            if isinstance(n, ast.Name):
                self.other.add(n.id)


class _Trace:
    __slots__ = ("chars", "opaque", "consumed")

    def __init__(self) -> None:
        self.chars: set[str] = set()
        self.opaque = False
        self.consumed: set[int] = set()  # id() of Constant nodes reached


class _JsonRefs:
    """``json.dumps`` as this module imports it (``import json [as j]``,
    ``from json import dumps [as d]``). Its default ``ensure_ascii=True`` output
    is pure ASCII whatever the payload holds."""

    def __init__(self, tree: ast.Module) -> None:
        self.modules: set[str] = set()
        self.funcs: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == "json":
                        self.modules.add(a.asname or "json")
            elif isinstance(node, ast.ImportFrom) and node.module == "json":
                for a in node.names:
                    if a.name == "dumps":
                        self.funcs.add(a.asname or "dumps")

    def is_dumps(self, func: ast.expr) -> bool:
        if isinstance(func, ast.Attribute):
            return (func.attr == "dumps" and isinstance(func.value, ast.Name)
                    and func.value.id in self.modules)
        return isinstance(func, ast.Name) and func.id in self.funcs


def _ensure_ascii_off(call: ast.Call) -> bool:
    for k in call.keywords:
        if k.arg == "ensure_ascii":
            return not (isinstance(k.value, ast.Constant) and k.value.value is True)
        if k.arg is None:
            return True  # **kwargs may carry ensure_ascii=False
    return False


class _Tracer:
    def __init__(self, local: _Names | None, module: _Names, json: _JsonRefs) -> None:
        self.local = local
        self.module = module
        self.json = json

    def _lookup(self, name: str) -> tuple[list[ast.expr], bool]:
        """``(bound values, also bound opaquely)`` -- the innermost scope that
        binds *name* wins, so a parameter shadows a module constant."""
        for names in (self.local, self.module):
            if names is None:
                continue
            if name in names.values or name in names.other:
                return names.values.get(name, []), name in names.other
        return [], True

    def trace(self, exprs: list[ast.expr]) -> _Trace:
        tr = _Trace()
        for e in exprs:
            self._walk(e, _NAME_HOPS, tr)
        return tr

    def _walk(self, node: ast.expr, hops: int, tr: _Trace) -> None:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                tr.chars |= _non_ascii(node.value)
                tr.consumed.add(id(node))
            return
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                self._walk(v, hops, tr)
            return
        if isinstance(node, ast.FormattedValue):
            self._walk(node.value, hops, tr)
            if node.format_spec is not None:
                self._walk(node.format_spec, hops, tr)
            return
        if isinstance(node, ast.BinOp):
            self._walk(node.left, hops, tr)
            self._walk(node.right, hops, tr)
            return
        if isinstance(node, ast.IfExp):
            self._walk(node.body, hops, tr)
            self._walk(node.orelse, hops, tr)
            return
        if isinstance(node, ast.BoolOp):
            for v in node.values:
                self._walk(v, hops, tr)
            return
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for v in node.elts:
                self._walk(v, hops, tr)
            return
        if isinstance(node, ast.Dict):
            for v in node.values:
                self._walk(v, hops, tr)
            return
        if isinstance(node, ast.Starred):
            self._walk(node.value, hops, tr)
            return
        if isinstance(node, ast.Subscript):
            self._walk(node.value, hops, tr)
            return
        if isinstance(node, ast.Call):
            self._walk_call(node, hops, tr)
            return
        if isinstance(node, ast.Name):
            values, opaque = self._lookup(node.id)
            if hops <= 0 or not values:
                tr.opaque = True
                return
            tr.opaque |= opaque
            for value in values:
                self._walk(value, hops - 1, tr)
            return
        tr.opaque = True  # attribute, comprehension, await, ...

    def _walk_call(self, node: ast.Call, hops: int, tr: _Trace) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "ascii":
            return  # ASCII by construction
        if self.json.is_dumps(func):
            if _ensure_ascii_off(node):
                for a in node.args:
                    self._walk(a, hops, tr)
            return  # ensure_ascii=True (the default): ASCII by construction
        if isinstance(func, ast.Name) and func.id in _SEE_THROUGH_BUILTINS:
            for a in node.args:
                self._walk(a, hops, tr)
            return
        if isinstance(func, ast.Attribute) and func.attr in _SEE_THROUGH:
            self._walk(func.value, hops, tr)
            spec = _SEE_THROUGH[func.attr]
            if spec == "all":
                for a in node.args:
                    self._walk(a, hops, tr)
                for k in node.keywords:
                    self._walk(k.value, hops, tr)
            elif isinstance(spec, int):
                for a in node.args[spec:]:
                    self._walk(a, hops, tr)
            return
        tr.opaque = True


# ── sinks ───────────────────────────────────────────────────────────


class _Sink:
    __slots__ = ("line", "stream", "trace", "snippet")

    def __init__(self, line: int, stream: str, trace: _Trace, snippet: str) -> None:
        self.line = line
        self.stream = stream
        self.trace = trace
        self.snippet = snippet


def _sink_payload(call: ast.Call, refs: _StreamRefs
                  ) -> tuple[str, list[ast.expr]] | None:
    """``(stream, payload expressions)`` if *call* writes text to a std stream."""
    func = call.func
    if isinstance(func, ast.Name) and func.id == "print":
        stream = "stdout"
        for k in call.keywords:
            if k.arg == "file":
                if isinstance(k.value, ast.Constant) and k.value.value is None:
                    continue  # print(file=None) writes to sys.stdout
                resolved = refs.stream_of(k.value)
                if resolved is None:
                    return None  # an explicit file: not a std stream
                stream = resolved
        payload = list(call.args) + [
            k.value for k in call.keywords if k.arg in ("sep", "end")
        ]
        return stream, payload
    if isinstance(func, ast.Attribute) and func.attr == "write":
        stream = refs.stream_of(func.value)
        if stream:
            return stream, list(call.args)
    return None


def _scopes(tree: ast.Module):
    yield tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            yield node


# ── untraced module evidence ────────────────────────────────────────


def _discarded_string_ids(tree: ast.Module) -> set[int]:
    """ids of statement-level strings, whose value is discarded -- docstrings,
    and strings that only look like one (a "docstring" placed after
    ``from __future__`` is a no-op expression). A docstring is released back to
    evidence when the module reads it: a bare ``__doc__`` (e.g.
    ``ArgumentParser(description=__doc__)``) releases the module docstring;
    ``obj.__doc__`` releases class/function docstrings. Each reference only
    releases its own kind."""
    module_doc_used = any(isinstance(n, ast.Name) and n.id == "__doc__"
                          for n in ast.walk(tree))
    member_doc_used = any(isinstance(n, ast.Attribute) and n.attr == "__doc__"
                          for n in ast.walk(tree))
    released: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module):
            if not module_doc_used:
                continue
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if not member_doc_used:
                continue
        else:
            continue
        body = node.body
        if body and isinstance(body[0], ast.Expr):
            released.add(id(body[0].value))
    return {
        id(n.value) for n in ast.walk(tree)
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
        and isinstance(n.value.value, str) and id(n.value) not in released
    }


def _re_aliases(tree: ast.Module) -> set[str]:
    return {a.asname or "re" for n in ast.walk(tree) if isinstance(n, ast.Import)
            for a in n.names if a.name == "re"}


def _matcher_ids(tree: ast.Module) -> set[int]:
    """ids of nodes whose string content matches input rather than producing
    output: comparison operands, subscript keys, dict keys, ``re.*`` arguments,
    the pattern argument of string matcher methods and the key of ``.get``."""
    re_names = _re_aliases(tree)
    roots: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            roots.append(node.left)
            roots.extend(node.comparators)
        elif isinstance(node, ast.Subscript):
            roots.append(node.slice)
        elif isinstance(node, ast.Dict):
            roots.extend(k for k in node.keys if k is not None)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            f = node.func
            if isinstance(f.value, ast.Name) and f.value.id in re_names:
                roots.extend(node.args)
                roots.extend(k.value for k in node.keywords)
            elif f.attr in _MATCHER_METHODS:
                roots.extend(node.args)
            elif f.attr in ("replace", "get") and node.args:
                roots.append(node.args[0])  # the needle / the lookup key
    ids: set[int] = set()
    for r in roots:
        ids.update(id(n) for n in ast.walk(r))
    return ids


# ── analyzer ────────────────────────────────────────────────────────


class UnguardedStdoutEncodingAnalyzer:
    """Detect CLI entry modules that write non-ASCII to an unpinned std stream."""

    id: str = "unguarded_stdout_encoding"
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
            finding = self._scan(tree, rel, path.name, src.splitlines())
            if finding is not None:
                findings.append(finding)
        findings.sort(key=lambda f: (f.location.path, f.location.line_start))
        return findings

    def _scan(self, tree: ast.Module, rel: str, filename: str,
              src_lines: list[str]) -> Finding | None:
        entry = _entry_kind(tree, filename)
        if entry is None:
            return None
        refs = _StreamRefs(tree)
        guarded = _guarded_streams(tree, refs)
        if guarded >= set(_STREAMS):
            return None

        module_names = _Names(tree)
        json_refs = _JsonRefs(tree)
        sinks: list[_Sink] = []
        consumed: set[int] = set()
        for scope in _scopes(tree):
            local = None if scope is tree else _Names(scope)
            tracer = _Tracer(local, module_names, json_refs)
            for node in _own_nodes(scope):
                if not isinstance(node, ast.Call):
                    continue
                sink = _sink_payload(node, refs)
                if sink is None:
                    continue
                stream, payload = sink
                trace = tracer.trace(payload)
                consumed |= trace.consumed
                if stream in guarded:
                    continue
                line = node.lineno
                snippet = src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""
                sinks.append(_Sink(line, stream, trace, snippet))
        if not sinks:
            return None
        sinks.sort(key=lambda s: s.line)

        traced = [s for s in sinks if s.trace.chars]
        opaque = [s for s in sinks if s.trace.opaque]

        excluded = consumed | _matcher_ids(tree) | _discarded_string_ids(tree)
        untraced: list[tuple[int, set[str]]] = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in excluded):
                chars = _non_ascii(node.value)
                if chars:
                    untraced.append((node.lineno, chars))
        untraced.sort(key=lambda t: t[0])
        if not opaque:
            untraced = []  # nothing dynamic is printed: untraced text cannot reach a sink

        if traced:
            tier, anchor, confidence = "high", traced[0], 0.7
        elif untraced:
            tier, anchor, confidence = "low", opaque[0], 0.35
        else:
            return None

        modes: set[str] = set()
        traced_chars: set[str] = set()
        for s in traced:
            modes |= _failure_modes(s.stream, s.trace.chars)
            traced_chars |= s.trace.chars
        untraced_chars: set[str] = set().union(*(c for _, c in untraced)) if untraced else set()
        untraced_modes: set[str] = set()
        for stream in {s.stream for s in opaque}:
            untraced_modes |= _failure_modes(stream, untraced_chars)

        all_chars = traced_chars | untraced_chars
        crash_chars = {c for c in all_chars if not _cp1252_encodable(c)}
        mappable_chars = all_chars - crash_chars
        unguarded = sorted({s.stream for s in sinks})

        fingerprint = make_fingerprint(_RULE_ID, rel, "module", "")
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.UNGUARDED_STDOUT_ENCODING,
            severity=Severity.LOW,  # advisory v1: never block scan exit
            confidence=confidence,
            message=self._message(rel, tier, anchor, modes, untraced_modes, unguarded),
            location=Location(path=rel, line_start=anchor.line, line_end=anchor.line),
            fingerprint=fingerprint,
            snippet=anchor.snippet,
            metadata={
                "rule_id": _RULE_ID,
                "confidence_tier": tier,
                "entry_kind": entry,
                "unguarded_streams": unguarded,
                "guarded_streams": sorted(guarded),
                "failure_modes": sorted(modes),
                "untraced_failure_modes": sorted(untraced_modes),
                "encode_crash_chars": _describe_all(crash_chars),
                "cp1252_mappable_chars": _describe_all(mappable_chars),
                "traced_sites": [
                    {"line": s.line, "stream": s.stream,
                     "chars": _describe_all(s.trace.chars)}
                    for s in traced[:_MAX_LISTED]
                ],
                "traced_site_count": len(traced),
                "untraced_constants": [
                    {"line": ln, "chars": _describe_all(c)}
                    for ln, c in untraced[:_MAX_LISTED]
                ],
                "untraced_constant_count": len(untraced),
                "codepage_modeled": _CODEPAGE,
                "guard_confirmed": False,
                "family": _FAMILY,
            },
        )

    @staticmethod
    def _message(rel: str, tier: str, anchor: _Sink, modes: set[str],
                 untraced_modes: set[str], unguarded: list[str]) -> str:
        # ASCII-only on purpose: this text is itself written to a std stream.
        streams = "/".join(unguarded)
        if tier == "high":
            head = (f"CLI entry '{rel}' writes non-ASCII text to {anchor.stream} "
                    f"(line {anchor.line}) with no UTF-8 guard on {streams}.")
        else:
            head = (f"CLI entry '{rel}' holds non-ASCII string constants and "
                    f"prints values the tracer could not follow (first at line "
                    f"{anchor.line}, {anchor.stream}) with no UTF-8 guard on "
                    f"{streams}; the constants may reach the stream (low "
                    f"confidence: not traced).")
        effects = []
        every = modes | untraced_modes
        if "encode_crash" in every:
            qualifier = "" if "encode_crash" in modes else " (via untraced constants)"
            effects.append("a write raises UnicodeEncodeError and the process "
                           f"dies{qualifier}")
        if "undecodable_bytes" in every:
            effects.append("cp1252 bytes reach a UTF-8 reader, which cannot "
                           "decode them")
        if "escaped_output" in every:
            effects.append("stderr emits backslash escapes instead of the text")
        effect = "; ".join(effects) if effects else "output is written in the locale codepage"
        return (
            f"{head} On Windows (Python < 3.15, no PYTHONUTF8/PYTHONIOENCODING) a "
            f"piped, redirected or captured stream uses the locale codepage "
            f"(cp1252): {effect}. An interactive console hides it. Fix: call "
            f"sys.stdout.reconfigure(encoding=\"utf-8\") (and stderr) at entry, "
            f"before any output. Do not set PYTHONIOENCODING in the test harness "
            f"instead: that keeps the test green after the guard is removed."
        )
