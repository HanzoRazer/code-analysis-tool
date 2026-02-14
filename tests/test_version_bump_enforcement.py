from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
_ANALYZERS_DIR = _SRC / "code_audit" / "analyzers"
_MANIFEST_PATH = _REPO_ROOT / "tests" / "contracts" / "logic_manifest.json"

# Analyzer modules that are not "rule logic" (optional allowlist). Keep empty by default.
_SKIP_MODULES: set[str] = set()


@dataclass(frozen=True)
class AnalyzerRecord:
    module: str
    class_name: str
    version: str
    logic_hash: str


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _load_manifest() -> dict[str, Any]:
    if not _MANIFEST_PATH.exists():
        raise AssertionError(
            f"Missing logic manifest: {_MANIFEST_PATH}\n"
            "Generate it with:\n"
            "  python scripts/refresh_logic_manifest.py\n"
        )
    return json.loads(_read_text(_MANIFEST_PATH))


def _find_signal_logic_version() -> str:
    """
    Resolve signal_logic_version without importing the runtime (keeps this test robust).
    We read it from src/code_audit/model/run_result.py (canonical default location in this repo).
    """
    candidates = [
        _SRC / "code_audit" / "model" / "run_result.py",
        _SRC / "code_audit" / "run_result.py",  # fallback for older layouts
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = _read_text(p)

        # Common patterns:
        #   signal_logic_version: str = "signals_v1"
        #   signal_logic_version="signals_v1"
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)

    raise AssertionError(
        "Could not locate signal_logic_version default. "
        "Expected it in src/code_audit/model/run_result.py.\n"
        "If it moved, update _find_signal_logic_version() in tests/test_version_bump_enforcement.py."
    )


class _LogicNormalizer(ast.NodeTransformer):
    """
    Normalize away non-logic noise so hashes only change on semantic rule changes.

    - Strip module docstring
    - In any class body, replace assignments to `version` with a constant placeholder
      so bumping version does NOT count as logic change.
    """
    def visit_Module(self, node: ast.Module) -> ast.Module:
        # Remove module docstring (Expr(Constant(str)) as first statement)
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant):
            if isinstance(node.body[0].value.value, str):
                node.body = node.body[1:]
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        new_body: list[ast.stmt] = []
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                # class attr: version = "v1"
                if any(isinstance(t, ast.Name) and t.id == "version" for t in stmt.targets):
                    new_stmt = ast.Assign(
                        targets=stmt.targets,
                        value=ast.Constant(value="__VERSION_STRIPPED__"),
                        type_comment=stmt.type_comment,
                    )
                    new_body.append(ast.copy_location(new_stmt, stmt))
                    continue
            if isinstance(stmt, ast.AnnAssign):
                # class attr: version: str = "v1"
                if isinstance(stmt.target, ast.Name) and stmt.target.id == "version":
                    new_stmt = ast.AnnAssign(
                        target=stmt.target,
                        annotation=stmt.annotation,
                        value=ast.Constant(value="__VERSION_STRIPPED__") if stmt.value is not None else None,
                        simple=stmt.simple,
                    )
                    new_body.append(ast.copy_location(new_stmt, stmt))
                    continue
            new_body.append(stmt)
        node.body = new_body
        self.generic_visit(node)
        return node


def _logic_hash_for_module(source: str, filename: str) -> str:
    """
    AST-based semantic hash:
      - ignores formatting/comments
      - ignores module docstring
      - ignores class attribute `version` values
    """
    tree = ast.parse(source, filename=filename)
    tree = _LogicNormalizer().visit(tree)
    ast.fix_missing_locations(tree)
    dumped = ast.dump(tree, include_attributes=False)
    h = hashlib.sha256(dumped.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def _discover_analyzers() -> list[AnalyzerRecord]:
    """
    Discover analyzer classes under src/code_audit/analyzers/*.py:
      - class name endswith Analyzer
      - has class attributes `id` and `version`
      - has method `run`
    """
    out: list[AnalyzerRecord] = []

    for p in sorted(_ANALYZERS_DIR.glob("*.py")):
        if p.name == "__init__.py":
            continue
        mod_name = f"code_audit.analyzers.{p.stem}"
        if mod_name in _SKIP_MODULES:
            continue

        src = _read_text(p)
        logic_hash = _logic_hash_for_module(src, filename=str(p))

        # Parse once and find class defs + their id/version literals (best-effort).
        tree = ast.parse(src, filename=str(p))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if not node.name.endswith("Analyzer"):
                continue

            # Find class attr literals for `version` (required)
            version = None
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    if any(isinstance(t, ast.Name) and t.id == "version" for t in stmt.targets):
                        if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                            version = stmt.value.value
                elif isinstance(stmt, ast.AnnAssign):
                    if isinstance(stmt.target, ast.Name) and stmt.target.id == "version":
                        if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                            version = stmt.value.value

            if version is None:
                # If a module defines Analyzer classes without version, ignore them here;
                # the registry contract test should already catch shape issues.
                continue

            out.append(
                AnalyzerRecord(
                    module=mod_name,
                    class_name=node.name,
                    version=version,
                    logic_hash=logic_hash,
                )
            )

    # Deterministic sort
    out.sort(key=lambda r: (r.module, r.class_name))
    return out


def test_rule_logic_changes_require_version_bump() -> None:
    """
    Contract:
      If semantic analyzer logic changes, the change must be acknowledged by bumping either:
        - the analyzer.version string, OR
        - the engine-level signal_logic_version

    Rationale:
      - analyzer.version is local, fine-grained
      - signal_logic_version is the global semantic contract knob (fixtures contract)
    """
    manifest = _load_manifest()
    manifest_signal_logic = manifest.get("signal_logic_version", "")
    current_signal_logic = _find_signal_logic_version()

    if not manifest_signal_logic:
        raise AssertionError(
            f"Manifest missing signal_logic_version: {_MANIFEST_PATH}\n"
            "Regenerate it with:\n"
            "  python scripts/refresh_logic_manifest.py\n"
        )

    current = _discover_analyzers()
    recorded = manifest.get("analyzers", [])
    if not isinstance(recorded, list):
        raise AssertionError("Manifest 'analyzers' must be a list")

    by_key: dict[str, dict[str, Any]] = {}
    for rec in recorded:
        k = f"{rec.get('module')}::{rec.get('class_name')}"
        by_key[k] = rec

    errors: list[str] = []

    for cur in current:
        k = f"{cur.module}::{cur.class_name}"
        old = by_key.get(k)
        if old is None:
            errors.append(
                f"[NEW] {k} added but not present in manifest. "
                "Regenerate manifest (this is a contract update)."
            )
            continue

        old_hash = old.get("logic_hash")
        old_ver = old.get("version")

        if old_hash != cur.logic_hash:
            analyzer_bumped = (old_ver != cur.version)
            engine_bumped = (manifest_signal_logic != current_signal_logic)

            if not (analyzer_bumped or engine_bumped):
                errors.append(
                    f"[NO BUMP] {k}\n"
                    f"  logic_hash changed: {old_hash} -> {cur.logic_hash}\n"
                    f"  analyzer.version unchanged: {cur.version!r}\n"
                    f"  signal_logic_version unchanged: {current_signal_logic!r}\n"
                    f"  Fix: bump {cur.class_name}.version OR bump RunResult.signal_logic_version default.\n"
                    f"  Then regenerate manifest: python scripts/refresh_logic_manifest.py"
                )

    # Detect removals / renames too (optional but useful)
    current_keys = {f"{c.module}::{c.class_name}" for c in current}
    for k in sorted(by_key.keys()):
        if k not in current_keys:
            errors.append(
                f"[REMOVED] {k} exists in manifest but not in source now. "
                "Regenerate manifest."
            )

    assert not errors, "Version bump enforcement failed:\n\n" + "\n\n".join(errors)
