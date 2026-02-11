"""Exceptions analyzer — detects error handling that hides bugs."""

from __future__ import annotations

import ast
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint


def _is_bare_except(handler: ast.ExceptHandler) -> bool:
    """``except:`` with no type specified."""
    return handler.type is None


def _is_broad_except(handler: ast.ExceptHandler) -> bool:
    """``except Exception`` or ``except BaseException``."""
    if isinstance(handler.type, ast.Name):
        return handler.type.id in {"Exception", "BaseException"}
    return False


def _is_swallowed(handler: ast.ExceptHandler) -> bool:
    """Handler body is just ``pass`` or ``...`` — silently ignoring errors."""
    if len(handler.body) != 1:
        return False
    stmt = handler.body[0]
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
        return stmt.value.value is ...
    return False


class ExceptionsAnalyzer:
    """Finds bare/broad excepts and swallowed exceptions."""

    id: str = "exceptions"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                continue

            rel = str(path.relative_to(root))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ExceptHandler):
                    continue

                end_line = getattr(node, "end_lineno", node.lineno) or node.lineno

                if _is_bare_except(node):
                    rule_id = "EXC-BARE-001"
                    msg = "Bare except catches everything — including keyboard interrupts"
                    severity = Severity.HIGH
                    confidence = 0.95
                elif _is_broad_except(node):
                    rule_id = "EXC-BROAD-001"
                    msg = "Broad except may hide unexpected errors"
                    severity = Severity.MEDIUM
                    confidence = 0.95

                    if _is_swallowed(node):
                        rule_id = "EXC-SWALLOW-001"
                        msg = "Exception is caught and silently ignored"
                        severity = Severity.HIGH
                        confidence = 0.85
                else:
                    continue

                # Reconstruct a minimal snippet
                type_str = ""
                if node.type and isinstance(node.type, ast.Name):
                    type_str = node.type.id
                body_str = "pass" if _is_swallowed(node) else "…"
                snippet = f"except {type_str}:\n    {body_str}" if type_str else f"except:\n    {body_str}"

                # Try to find the enclosing function name
                symbol = "<module>"
                for parent in ast.walk(tree):
                    if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for child in ast.walk(parent):
                            if child is node:
                                symbol = parent.name
                                break

                findings.append(
                    Finding(
                        finding_id="",  # filled below
                        type=AnalyzerType.EXCEPTIONS,
                        severity=severity,
                        confidence=confidence,
                        message=msg,
                        location=Location(path=rel, line_start=node.lineno, line_end=end_line),
                        fingerprint=make_fingerprint(rule_id, rel, symbol, snippet),
                        snippet=snippet,
                        metadata={"rule_id": rule_id},
                    )
                )

        # Assign stable finding IDs
        for i, f in enumerate(findings):
            object.__setattr__(f, "finding_id", f"exc_{f.fingerprint[7:15]}_{i:04d}")

        return findings


# ═══════════════════════════════════════════════════════════════════════
#  Functional API (dict-based) — used by code_audit.run_result
# ═══════════════════════════════════════════════════════════════════════

import hashlib
from typing import Any, Dict, List, Literal

_Severity = Literal["info", "low", "medium", "high", "critical"]


def _sha256(s: str) -> str:
    h = hashlib.sha256()
    h.update(s.encode("utf-8"))
    return "sha256:" + h.hexdigest()


def _truncate(s: str, n: int = 200) -> str:
    s = s.replace("\r\n", "\n")
    return s if len(s) <= n else s[: n - 1] + "…"


def _handler_type_name(handler: ast.ExceptHandler) -> str:
    """
    Returns:
      - "bare" for ``except:``
      - "Exception"/"BaseException"/etc. for named exceptions
      - "unknown" if unparseable
    """
    if handler.type is None:
        return "bare"
    if isinstance(handler.type, ast.Name):
        return handler.type.id
    if isinstance(handler.type, ast.Attribute):
        return handler.type.attr
    if isinstance(handler.type, ast.Tuple):
        names = []
        for elt in handler.type.elts:
            if isinstance(elt, ast.Name):
                names.append(elt.id)
            elif isinstance(elt, ast.Attribute):
                names.append(elt.attr)
        return ",".join(names) if names else "unknown"
    return "unknown"


def _classify_severity(handler_type: str) -> _Severity:
    """
    Beginner-first severity:
      - bare / BaseException / Exception → high
      - broad tuples containing Exception/BaseException → high
      - otherwise → medium
    """
    if handler_type in {"bare", "BaseException", "Exception"}:
        return "high"
    if "BaseException" in handler_type or "Exception" in handler_type:
        return "high"
    return "medium"


def _handler_has_raise(handler: ast.ExceptHandler) -> bool:
    """Return True if the handler body contains a ``raise`` statement."""
    for node in ast.walk(handler):
        if isinstance(node, ast.Raise):
            return True
    return False


def _handler_has_logging(handler: ast.ExceptHandler) -> bool:
    """Return True if the handler body calls a logging-like function.

    Detected patterns:
      - ``logging.{error,warning,exception,info,debug,critical}(…)``
      - ``logger.{…}(…)``  (any attribute call on a name ending in *log*/*logger*)
      - ``print(…)``  (common beginner logging)
      - ``traceback.print_exc(…)``
    """
    _LOG_METHODS = {
        "error", "warning", "exception", "info", "debug", "critical",
        "warn", "fatal", "log",
    }
    for node in ast.walk(handler):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # logging.error(…) / logger.warning(…)
        if isinstance(func, ast.Attribute):
            if func.attr in _LOG_METHODS:
                # Check the object name looks like a logger
                if isinstance(func.value, ast.Name):
                    name = func.value.id.lower()
                    if "log" in name or name in {"logging"}:
                        return True
            # traceback.print_exc()
            if func.attr == "print_exc" and isinstance(func.value, ast.Name):
                if func.value.id == "traceback":
                    return True
        # print(…) — beginner logging
        if isinstance(func, ast.Name) and func.id == "print":
            return True
    return False


def _handler_is_swallowing(handler: ast.ExceptHandler) -> bool:
    """Return True if the handler silently suppresses the exception.

    A handler is "swallowing" when it has **no raise** and **no logging**.
    """
    if _handler_has_raise(handler):
        return False
    if _handler_has_logging(handler):
        return False
    return True


def _broadness_class(handler_type: str) -> str:
    """
    Normalize how broad the handler is for rule selection/scoring.
      - bare / BaseException are the broadest
      - Exception is broad
      - tuples that include Exception/BaseException are broad
    """
    if handler_type in {"bare", "BaseException"}:
        return "very_broad"
    if handler_type == "Exception":
        return "broad"
    if "BaseException" in handler_type:
        return "very_broad"
    if "Exception" in handler_type:
        return "broad"
    return "other"


def analyze_exceptions(path: Path, *, root: Path) -> List[Dict[str, Any]]:
    """
    Functional analyzer: detect broad exception handling patterns.

    Returns a list of schema-shaped finding dicts (not dataclass objects).
    """
    try:
        src = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []

    rel = str(path.resolve().relative_to(root.resolve()))
    findings: List[Dict[str, Any]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            if not isinstance(handler, ast.ExceptHandler):
                continue

            tname = _handler_type_name(handler)
            if tname == "unknown":
                continue

            is_broad = (
                tname == "bare"
                or "Exception" in tname
                or "BaseException" in tname
            )
            if not is_broad:
                continue

            line_start = getattr(handler, "lineno", 1) or 1
            line_end = getattr(handler, "end_lineno", line_start) or line_start

            # Distinguish three cases for beginner UX + scoring:
            # 1) Swallowed: broad catch + no raise + no logging  -> EXC_SWALLOW_001 (strongest)
            # 2) Broad but logged: broad catch + logging + no raise -> EXC_BROAD_LOGGED_001 (less scary)
            # 3) Broad (generic): broad catch patterns (even if it raises) -> EXC_BROAD_001
            has_raise = _handler_has_raise(handler)
            has_log = _handler_has_logging(handler)
            is_swallow = (not has_raise) and (not has_log)

            broadness = _broadness_class(tname)

            if is_swallow:
                rule_id = "EXC_SWALLOW_001"
                sev: _Severity = "critical" if broadness == "very_broad" else "high"
                conf = 0.92
            elif has_log and (not has_raise):
                rule_id = "EXC_BROAD_LOGGED_001"
                # Logged handlers still hide stack context sometimes, but they're much safer than silent failures.
                # Keep severity lower so the confidence engine doesn't "panic".
                sev = "medium" if broadness == "very_broad" else "low"
                conf = 0.85
            else:
                rule_id = "EXC_BROAD_001"
                sev = _classify_severity(tname)
                conf = 0.9 if sev == "high" else 0.75

            # Fingerprint: stable across runs for same location/type
            fp_src = f"{rule_id}|{rel}|{line_start}|{line_end}|{tname}"
            fingerprint = _sha256(fp_src)
            finding_id = "f_" + hashlib.sha256(fp_src.encode("utf-8")).hexdigest()[:16]

            lines = src.replace("\r\n", "\n").split("\n")
            snippet = ""
            if 1 <= line_start <= len(lines):
                start = max(1, line_start - 1)
                end = min(len(lines), line_end + 1)
                snippet = "\n".join(lines[start - 1 : end])
            snippet = _truncate(snippet, 200)

            if rule_id == "EXC_SWALLOW_001":
                msg = "Error might disappear silently"
                if tname == "bare":
                    msg = "Bare except may hide errors silently"
                elif tname == "BaseException":
                    msg = "Catching BaseException may hide system-exiting errors silently"
                elif tname == "Exception":
                    msg = "Catching Exception may hide unexpected errors silently"
            elif rule_id == "EXC_BROAD_LOGGED_001":
                msg = "This logs the error, but broad catching can still make debugging harder"
                if tname == "bare":
                    msg = "This logs the error, but bare except can still hide important issues"
                elif tname == "BaseException":
                    msg = "This logs the error, but catching BaseException can still hide system-exiting issues"
                elif tname == "Exception":
                    msg = "This logs the error, but catching Exception can still hide unexpected issues"
            else:
                msg = "Broad exception handling may hide errors"
                if tname == "bare":
                    msg = "Bare except may hide errors"
                elif tname == "BaseException":
                    msg = "Catching BaseException may hide system-exiting errors"
                elif tname == "Exception":
                    msg = "Catching Exception may hide unexpected errors"

            findings.append(
                {
                    "finding_id": finding_id,
                    "type": "exceptions",
                    "severity": sev,
                    "confidence": conf,
                    "message": msg,
                    "location": {
                        "path": rel,
                        "line_start": line_start,
                        "line_end": line_end,
                    },
                    "fingerprint": fingerprint,
                    "snippet": snippet,
                    "metadata": {
                        "rule_id": rule_id,
                        "handler_type": tname,
                        "swallowed_error": (rule_id == "EXC_SWALLOW_001"),
                        "logged_error": has_log,
                        "re_raised": has_raise,
                    },
                }
            )

    return findings
