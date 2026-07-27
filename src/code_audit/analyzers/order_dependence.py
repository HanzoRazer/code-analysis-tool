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
2. **Duplicate key in a dict literal** — ``{"a": 1, "a": 2}``; the later value
   silently wins (last-wins) and the earlier is dead. (Set duplicates are *not*
   order-dependent — set membership is order-independent — so they are
   deliberately not reported by this detector.)

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
                f"one silently shadows the other — which one depends on registration/"
                f"import order (the framework's resolution rule), making load order "
                f"the de-facto authority. Fix: make the keys distinct, or declare one "
                f"explicit precedence. (Detection is module-scoped; cross-module "
                f"composition via include_router/imports isn't covered yet.)"
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

    # ── signal 2: duplicate keys in a dict literal ──────────────────
    # NB: only dicts — a duplicate is genuinely order-dependent (the later value
    # silently overwrites, last wins). Set duplicates are NOT order-dependent
    # (set membership is order-independent; a duplicate is merely redundant), so
    # they don't belong in an order-dependence detector and are deliberately not
    # reported here.

    def _dup_literal_keys(
        self, tree: ast.Module, rel: str, src_lines: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            by_key: dict[object, list[int]] = {}
            for k in node.keys:
                if k is None:  # ``**spread`` has no key
                    continue
                lit = _const_value(k)
                if lit is _NO_CONST:
                    continue
                by_key.setdefault(lit, []).append(getattr(k, "lineno", 0))

            for lit, lines in by_key.items():
                if len(lines) < 2:
                    continue
                lines.sort()
                line = lines[0]  # anchor at the first (shadowed) occurrence
                lines_str = ", ".join(str(ln) for ln in lines)
                snippet = (
                    src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""
                )
                message = (
                    f"Duplicate key {lit!r} in this dict literal (lines {lines_str}) "
                    f"— each later occurrence silently overwrites the earlier, so only "
                    f"the last survives and the rest are dead. Make the keys distinct."
                )
                fp = make_fingerprint(_RULE_DUP_KEY, rel, f"dict:{lit!r}", lines_str)
                findings.append(
                    Finding(
                        finding_id=fp,
                        type=AnalyzerType.ORDER_DEPENDENCE,
                        severity=Severity.LOW,
                        confidence=0.8,
                        message=message,
                        location=Location(
                            path=rel, line_start=line, line_end=lines[-1]
                        ),
                        fingerprint=fp,
                        snippet=snippet,
                        metadata={
                            "rule_id": _RULE_DUP_KEY,
                            "duplicate_key": repr(lit),
                            "sites": lines,
                            "occurrence_count": len(lines),
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

# Registrar roots that are config/mocking libraries, not app/registry objects.
# Guards the ambiguous verbs — most importantly ``@mock.patch("target")`` (attr
# ``patch`` collides with the HTTP PATCH verb) and ``@unittest.mock.patch``.
_NONROUTE_ROOTS = frozenset(
    {"mock", "unittest", "pytest", "click", "functools", "contextlib"}
)


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
    if registrar.split(".", 1)[0] in _NONROUTE_ROOTS:  # e.g. mock.patch
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
