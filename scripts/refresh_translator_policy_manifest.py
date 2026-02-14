from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
TRANSLATOR = SRC / "code_audit" / "insights" / "translator.py"
OUT = REPO_ROOT / "tests" / "contracts" / "translator_policy_manifest.json"


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _find_signal_logic_version() -> str:
    candidates = [
        SRC / "code_audit" / "model" / "run_result.py",
        SRC / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = _read_text(p)
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)
    raise SystemExit("error: could not locate signal_logic_version default")


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


def _policy_hash(source: str) -> str:
    tree = ast.parse(source, filename=str(TRANSLATOR))
    ex = _PolicyExtractor()
    ex.visit(tree)
    policy_nodes = sorted(ex.nodes, key=lambda n: int(getattr(n, "lineno", 0) or 0))
    policy_module = ast.Module(body=policy_nodes, type_ignores=[])
    dumped = ast.dump(policy_module, include_attributes=False)
    h = hashlib.sha256(dumped.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def main() -> int:
    if not TRANSLATOR.exists():
        raise SystemExit(f"error: missing translator: {TRANSLATOR}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "signal_logic_version": _find_signal_logic_version(),
        "policy_hash": _policy_hash(_read_text(TRANSLATOR)),
    }
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
