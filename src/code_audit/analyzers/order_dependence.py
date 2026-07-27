"""Order-dependence / silent-shadowing detector.

The killer sub-check of the governance-density family: find where **load /
registration order is the de-facto authority** — the same registration key is
claimed in two places with no explicit precedence, so whichever is imported or
defined first silently wins. Shuffle the order and behavior changes; that means
the ordering is load-bearing and ungoverned. **Family VI (missing authority) +
ordering.**

The classic instance is router shadowing — two handlers registered for the same
route, resolution decided by mount order. This detector generalizes it to *any*
keyed registration (a plugin/analyzer/command registry, a dict/config map), which
mainstream linters and the existing router analyzer (path-only, method-unaware)
do not cover.

Signals (v1, within a single module — where a registrar name reliably refers to
one object; cross-module composition via ``include_router``/imports is a v2
extension):

1. **Duplicate keyed registration** — the same ``@obj.method("key")`` decorator
   (route or registry) appears 2+ times. Method-aware: ``@app.get("/x")`` and
   ``@app.post("/x")`` are distinct and do NOT collide.
2. **Duplicate key in a dict/set literal** — ``{"a": 1, "a": 2}``; the later
   value silently wins and the earlier is dead.

``Finding.metadata.explicit_precedence_confirmed`` is ``False`` in v1: the
detector cannot yet tell an ordering that is *declared* (an explicit precedence /
priority) from an accidental one. A v2 pass looks for that declaration and
clears/downgrades — enrichment, not rework.

Emits: give one registration explicit precedence, or make the keys distinct —
don't let import/mount order silently decide.
"""
from __future__ import annotations

import ast
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_REGISTRY = "ORDER_DEP_REGISTRY_001"
_RULE_DUP_KEY = "ORDER_DEP_DUP_KEY_001"


class OrderDependenceAnalyzer:
    """Detect where load/registration order silently decides the winner."""

    id: str = "order_dependence"
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
            findings.extend(self._registration_collisions(tree, rel, src_lines))
            findings.extend(self._dup_literal_keys(tree, rel, src_lines))
        findings.sort(key=lambda f: (f.location.path, f.location.line_start))
        return findings

    # ── signal 1: duplicate keyed registration within a module ──────

    def _registration_collisions(
        self, tree: ast.Module, rel: str, src_lines: list[str]
    ) -> list[Finding]:
        # (registrar_repr, key) -> [(line, decorated_name)]
        sites: dict[tuple[str, str], list[tuple[int, str]]] = {}
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            for dec in node.decorator_list:
                reg = _keyed_registration(dec)
                if reg is not None:
                    registrar, key = reg
                    sites.setdefault((registrar, key), []).append(
                        (getattr(dec, "lineno", 0), node.name)
                    )

        findings: list[Finding] = []
        for (registrar, key), locs in sites.items():
            if len(locs) < 2:
                continue
            locs.sort()
            line = locs[0][0]
            names = ", ".join(n for _, n in locs)
            lines_str = ", ".join(str(ln) for ln, _ in locs)
            snippet = src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""
            message = (
                f"'{registrar}(\"{key}\")' is registered {len(locs)} times in this "
                f"module (lines {lines_str}: {names}). With no explicit precedence, "
                f"whichever is imported/defined first silently wins — load order is "
                f"the de-facto authority. Fix: make the keys distinct, or declare "
                f"one explicit precedence."
            )
            fp = make_fingerprint(_RULE_REGISTRY, rel, f"{registrar}:{key}", lines_str)
            findings.append(
                Finding(
                    finding_id=fp,
                    type=AnalyzerType.ORDER_DEPENDENCE,
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    message=message,
                    location=Location(path=rel, line_start=line, line_end=locs[-1][0]),
                    fingerprint=fp,
                    snippet=snippet,
                    metadata={
                        "rule_id": _RULE_REGISTRY,
                        "registrar": registrar,
                        "key": key,
                        "sites": [ln for ln, _ in locs],
                        "explicit_precedence_confirmed": False,
                    },
                )
            )
        return findings

    # ── signal 2: duplicate keys in a dict/set literal ──────────────

    def _dup_literal_keys(
        self, tree: ast.Module, rel: str, src_lines: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            keys: list = []
            if isinstance(node, ast.Dict):
                keys = [k for k in node.keys if k is not None]  # skip **spread
            elif isinstance(node, ast.Set):
                keys = list(node.elts)
            else:
                continue
            seen: dict[object, int] = {}
            dupes: dict[object, int] = {}
            for k in keys:
                lit = _const_value(k)
                if lit is _NO_CONST:
                    continue
                if lit in seen:
                    dupes[lit] = getattr(k, "lineno", 0)
                else:
                    seen[lit] = getattr(k, "lineno", 0)
            for lit, dline in dupes.items():
                line = getattr(node, "lineno", dline) or dline
                snippet = src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""
                kind = "dict" if isinstance(node, ast.Dict) else "set"
                tail = (
                    " — the later value silently wins; the earlier entry is dead."
                    if kind == "dict"
                    else " — the duplicate is silently discarded."
                )
                message = (
                    f"Duplicate key {lit!r} in this {kind} literal{tail} "
                    f"Order decides the survivor; make the keys distinct."
                )
                fp = make_fingerprint(_RULE_DUP_KEY, rel, f"{kind}:{lit!r}", str(line))
                findings.append(
                    Finding(
                        finding_id=fp,
                        type=AnalyzerType.ORDER_DEPENDENCE,
                        severity=Severity.LOW,
                        confidence=0.8,
                        message=message,
                        location=Location(path=rel, line_start=line, line_end=dline),
                        fingerprint=fp,
                        snippet=snippet,
                        metadata={
                            "rule_id": _RULE_DUP_KEY,
                            "literal_kind": kind,
                            "duplicate_key": repr(lit),
                            "explicit_precedence_confirmed": False,
                        },
                    )
                )
        return findings


# ── AST helpers ─────────────────────────────────────────────────────

_NO_CONST = object()
# Registrars whose string-literal first arg is a KEY claiming a shared slot — a
# duplicate is a real order-dependent collision. HTTP route verbs (the killer
# sub-check) plus explicit registries. Deliberately a whitelist: it excludes
# CONFIGURATION decorators whose string configures the decorated object
# independently (``@pytest.mark.parametrize("arg")``, ``@click.option("--x")``,
# ``@mock.patch("target")``, ``@fixture``), where the same string on different
# functions is normal and NOT a collision.
_REGISTRY_VERBS = frozenset({
    # HTTP routes — method-aware (the attr is part of the registrar repr, so
    # ``app.get`` and ``app.post`` are distinct and never collide with each other)
    "get", "post", "put", "delete", "patch", "options", "head",
    "route", "api_route", "websocket",
    # explicit registries
    "register", "command", "add_command", "add_url_rule",
})


def _keyed_registration(dec: ast.expr) -> tuple[str, str] | None:
    """If *dec* is a keyed *registry* decorator ``@obj.verb("literal", ...)`` whose
    verb claims a shared slot, return (registrar_repr, key). Configuration
    decorators (parametrize/option/patch/fixture) are excluded by the whitelist."""
    if not isinstance(dec, ast.Call) or not dec.args:
        return None
    key = _const_str(dec.args[0])
    if key is None:
        return None
    func = dec.func
    if not isinstance(func, ast.Attribute) or func.attr not in _REGISTRY_VERBS:
        return None
    registrar = _attr_chain(func)
    if registrar is None:
        return None
    return registrar, key


def _attr_chain(node: ast.expr) -> str | None:
    """Render ``a.b.c`` from an attribute chain; None if it isn't a plain chain."""
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    else:
        return None
    return ".".join(reversed(parts))


def _const_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _const_value(node: ast.expr):
    """Hashable literal value of a constant key, or _NO_CONST if not a constant."""
    if isinstance(node, ast.Constant):
        v = node.value
        try:
            hash(v)
        except TypeError:
            return _NO_CONST
        return v
    return _NO_CONST
