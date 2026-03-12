"""Refresh the rules registry with per-rule semantic hashes.

Usage::

    python scripts/refresh_rules_registry.py
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "code_audit" / "contracts" / "rules_registry.json"
VERSIONS = ROOT / "src" / "code_audit" / "contracts" / "versions.json"

# Semantic levers for the current JS/TS rule set.
JS_TS_ANALYZER = ROOT / "src" / "code_audit" / "analyzers" / "js_ts_security.py"


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha256_file(p: Path) -> str:
    return _sha256_bytes(p.read_bytes())


def _load_signal_logic_version() -> str:
    if not VERSIONS.exists():
        raise SystemExit(f"Missing version anchor: {VERSIONS.relative_to(ROOT)}")
    obj = json.loads(VERSIONS.read_text(encoding="utf-8"))
    v = obj.get("signal_logic_version")
    if not isinstance(v, str) or not v.startswith("signals_v"):
        raise SystemExit(f"Invalid signal_logic_version in {VERSIONS.relative_to(ROOT)}: {v!r}")
    return v


@dataclass(frozen=True)
class RuleDef:
    rule_id: str
    analyzer: str
    languages: list[str]
    title: str
    semantic_inputs: list[Path]

    def semantic_hash(self) -> str:
        """Per-rule semantic hash.

        We hash a stable recipe: rule_id + ordered list of (path, sha256(file)).
        """
        parts: list[str] = [self.rule_id]
        for p in self.semantic_inputs:
            rel = p.relative_to(ROOT).as_posix()
            parts.append(rel)
            parts.append(_sha256_file(p))
        return _sha256_bytes(("\n".join(parts) + "\n").encode("utf-8"))

    def to_json(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "analyzer": self.analyzer,
            "languages": self.languages,
            "title": self.title,
            "semantic_inputs": [p.relative_to(ROOT).as_posix() for p in self.semantic_inputs],
            "semantic_hash": self.semantic_hash(),
        }


def build_registry() -> dict[str, Any]:
    # Ensure inputs exist (semantic hash must be meaningful and deterministic).
    for p in (JS_TS_ANALYZER,):
        if not p.exists():
            raise SystemExit(f"Missing semantic input: {p.relative_to(ROOT)}")

    rules: list[RuleDef] = [
        RuleDef(
            rule_id="SEC_EVAL_JS_001",
            analyzer="js_ts_security_preview",
            languages=["js", "ts"],
            title="Use of eval(...)",
            semantic_inputs=[JS_TS_ANALYZER],
        ),
        RuleDef(
            rule_id="SEC_NEW_FUNCTION_JS_001",
            analyzer="js_ts_security_preview",
            languages=["js", "ts"],
            title="Use of new Function(...)",
            semantic_inputs=[JS_TS_ANALYZER],
        ),
        RuleDef(
            rule_id="EXC_EMPTY_CATCH_JS_001",
            analyzer="js_ts_security_preview",
            languages=["js", "ts"],
            title="Empty catch block",
            semantic_inputs=[JS_TS_ANALYZER],
        ),
        RuleDef(
            rule_id="GST_GLOBAL_THIS_MUTATION_001",
            analyzer="js_ts_security_preview",
            languages=["js", "ts"],
            title="Mutation of globalThis/window properties",
            semantic_inputs=[JS_TS_ANALYZER],
        ),
        RuleDef(
            rule_id="SEC_DYNAMIC_MODULE_LOAD_JS_001",
            analyzer="js_ts_security_preview",
            languages=["js", "ts"],
            title="Dynamic module load via require/import non-literal",
            semantic_inputs=[JS_TS_ANALYZER],
        ),
    ]

    # Stable ordering
    rules_json = [r.to_json() for r in sorted(rules, key=lambda x: x.rule_id)]

    return {
        "schema_version": 1,
        "generated_by": "scripts/refresh_rules_registry.py",
        "signal_logic_version": _load_signal_logic_version(),
        "rules": rules_json,
    }


def main() -> int:
    reg = build_registry()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[code-audit] wrote {OUT.relative_to(ROOT)} ({len(reg['rules'])} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
