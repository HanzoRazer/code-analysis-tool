from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any


_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
_TRANSLATOR = _SRC / "code_audit" / "insights" / "translator.py"
_MANIFEST = _REPO_ROOT / "tests" / "contracts" / "translator_policy_manifest.json"


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _find_signal_logic_version() -> str:
    candidates = [
        _SRC / "code_audit" / "model" / "run_result.py",
        _SRC / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = _read_text(p)
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)
    raise AssertionError(
        "Could not locate signal_logic_version default. "
        "Expected it in src/code_audit/model/run_result.py."
    )


def _load_manifest() -> dict[str, Any]:
    if not _MANIFEST.exists():
        raise AssertionError(
            f"Missing translator policy manifest: {_MANIFEST}\n"
            "Generate it with:\n"
            "  python scripts/refresh_translator_policy_manifest.py\n"
        )
    return json.loads(_read_text(_MANIFEST))


_POLICY_SUFFIXES = (
    "_RULE_ORDER",
    "_RULE_IDS",
    "_SUMMARY_KEYS",
    "_EVIDENCE_KEYS",
)


def _is_policy_constant_name(name: str) -> bool:
    if name == "_COPY_PREFIX":
        return True
    # Namespaced evidence policy levers (preferred forward-looking convention)
    if name.startswith("EVIDENCE_"):
        return True
    return any(name.endswith(suf) for suf in _POLICY_SUFFIXES)


class _PolicyExtractor(ast.NodeVisitor):
    """
    Extract only the translator "semantic policy surface" into an AST module we can hash.

    Included:
      - _severity_rank (if present)
      - _worst_severity
      - _risk_from_worst_severity
      - _urgency_from_severity
      - _group_key
      - findings_to_signals
      - _COPY_PREFIX
      - rule ordering: any name ending with _RULE_ORDER (e.g. _EXC_RULE_ORDER)
      - evidence summary levers: any name ending with _RULE_IDS / _SUMMARY_KEYS / _EVIDENCE_KEYS

    Excluded:
      - docstrings/comments/formatting
      - unrelated helpers that shouldn't require global semantic bump
    """

    def __init__(self) -> None:
        self.nodes: list[ast.AST] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node.name in (
            "_severity_rank",
            "_worst_severity",
            "_risk_from_worst_severity",
            "_urgency_from_severity",
            "_group_key",
            "findings_to_signals",
        ):
            self.nodes.append(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # capture policy constants by name (including future _EXC_RULE_ORDER etc.)
        names: list[str] = []
        for t in node.targets:
            if isinstance(t, ast.Name):
                names.append(t.id)

        for n in names:
            if _is_policy_constant_name(n):
                self.nodes.append(node)
                break

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            n = node.target.id
            if _is_policy_constant_name(n):
                self.nodes.append(node)


def _policy_hash_from_translator(source: str) -> str:
    tree = ast.parse(source, filename=str(_TRANSLATOR))
    ex = _PolicyExtractor()
    ex.visit(tree)

    # Build a synthetic module containing only the policy nodes, in source order.
    # (AST preserves ordering; we sort by lineno as a stable rule.)
    policy_nodes = sorted(ex.nodes, key=lambda n: int(getattr(n, "lineno", 0) or 0))
    policy_module = ast.Module(body=policy_nodes, type_ignores=[])

    dumped = ast.dump(policy_module, include_attributes=False)
    h = hashlib.sha256(dumped.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def test_translator_policy_changes_require_signal_logic_version_bump() -> None:
    """
    Pre-emptive gate:
      - if translator policy surface changes, you MUST bump signal_logic_version
        even if golden fixtures do not change (coverage gaps, future-proofing).
    """
    assert _TRANSLATOR.exists(), f"missing translator: {_TRANSLATOR}"

    current_signal_logic = _find_signal_logic_version()
    manifest = _load_manifest()

    manifest_ver = manifest.get("signal_logic_version")
    manifest_hash = manifest.get("policy_hash")

    if not isinstance(manifest_ver, str) or not manifest_ver:
        raise AssertionError("Manifest missing non-empty 'signal_logic_version'")
    if not isinstance(manifest_hash, str) or not manifest_hash:
        raise AssertionError("Manifest missing non-empty 'policy_hash'")

    current_hash = _policy_hash_from_translator(_read_text(_TRANSLATOR))

    # If version bumped, manifest must be refreshed too.
    assert manifest_ver == current_signal_logic, (
        "Translator policy manifest out of date for current signal_logic_version.\n"
        f"  current signal_logic_version: {current_signal_logic!r}\n"
        f"  manifest signal_logic_version: {manifest_ver!r}\n"
        "Fix:\n"
        "  python scripts/refresh_translator_policy_manifest.py\n"
    )

    # Core enforcement: if policy hash changed, version must bump (manifest version must advance).
    if current_hash != manifest_hash:
        raise AssertionError(
            "Translator policy surface changed (grouping/risk mapping/aggregation).\n"
            f"  manifest policy_hash: {manifest_hash}\n"
            f"  current  policy_hash: {current_hash}\n\n"
            "Hard rule: bump signal_logic_version even if goldens didn't change.\n"
            "Then refresh manifest:\n"
            "  python scripts/refresh_translator_policy_manifest.py\n"
        )
