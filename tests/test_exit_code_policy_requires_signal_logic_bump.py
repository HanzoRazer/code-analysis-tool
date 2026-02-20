"""Hard gate: exit-code policy surface changes require signal_logic_version bump.

If the semantic policy surface of ``src/code_audit/policy/exit_codes.py`` changes
(thresholds, mapping function, severity ranking), this test blocks the merge until:

  1) ``signal_logic_version`` in ``src/code_audit/model/run_result.py`` is bumped
  2) ``python scripts/refresh_exit_code_policy_manifest.py`` is run
  3) Updated ``tests/contracts/exit_code_policy_manifest.json`` is committed
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any


_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
_POLICY_FILE = _SRC / "code_audit" / "policy" / "exit_codes.py"
_MANIFEST = _REPO_ROOT / "tests" / "contracts" / "exit_code_policy_manifest.json"


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
            f"Missing exit-code policy manifest: {_MANIFEST}\n"
            "Generate it with:\n"
            "  python scripts/refresh_exit_code_policy_manifest.py\n"
        )
    return json.loads(_read_text(_MANIFEST))


def _strip_docstrings(tree: ast.AST) -> ast.AST:
    class Strip(ast.NodeTransformer):
        def _strip_body(self, body: list) -> list:
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                return body[1:]
            return body

        def visit_Module(self, node: ast.Module) -> ast.Module:
            node.body = self._strip_body(node.body)
            self.generic_visit(node)
            return node

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
            node.body = self._strip_body(node.body)
            self.generic_visit(node)
            return node

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
            node.body = self._strip_body(node.body)
            self.generic_visit(node)
            return node

    tree = Strip().visit(tree)
    ast.fix_missing_locations(tree)
    return tree


_KEEP_NAMES = {
    "ExitCodePolicy",
    "DEFAULT_POLICY",
    "_SEV_RANK",
    "_normalize_severity",
    "exit_code_for_worst_severity",
    "worst_severity_from_counts",
}


def _semantic_hash_policy_surface(path: Path) -> str:
    src = _read_text(path)
    tree = ast.parse(src)
    tree = _strip_docstrings(tree)

    kept: list[ast.stmt] = []
    for node in tree.body:  # type: ignore[attr-defined]
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in _KEEP_NAMES:
                    kept.append(node)
                    break
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in _KEEP_NAMES:
                kept.append(node)
        elif isinstance(node, ast.ClassDef):
            if node.name in _KEEP_NAMES:
                kept.append(node)

    surface = ast.Module(body=kept, type_ignores=[])
    dumped = ast.dump(surface, include_attributes=False, annotate_fields=True)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def test_exit_code_policy_requires_signal_logic_bump() -> None:
    """If the exit-code policy surface changes, signal_logic_version must be bumped."""
    assert _POLICY_FILE.exists(), f"Missing policy file: {_POLICY_FILE}"

    manifest = _load_manifest()

    # Structural checks
    assert manifest.get("manifest_version") == 1, (
        "Unexpected manifest_version (expected 1)"
    )
    expected_rel = _POLICY_FILE.relative_to(_REPO_ROOT).as_posix()
    assert manifest.get("policy_file") == expected_rel, (
        f"policy_file mismatch: manifest has {manifest.get('policy_file')!r}, "
        f"expected {expected_rel!r}"
    )

    recorded_sig = manifest.get("signal_logic_version")
    assert isinstance(recorded_sig, str) and recorded_sig, (
        "Manifest missing non-empty 'signal_logic_version'"
    )

    recorded_hash = manifest.get("policy_surface_sha256")
    assert isinstance(recorded_hash, str) and recorded_hash, (
        "Manifest missing non-empty 'policy_surface_sha256'"
    )

    current_sig = _find_signal_logic_version()
    current_hash = _semantic_hash_policy_surface(_POLICY_FILE)

    changed = current_hash != recorded_hash
    bumped = current_sig != recorded_sig

    if changed and not bumped:
        raise AssertionError(
            "Exit-code policy surface changed without bumping signal_logic_version.\n"
            f"  manifest policy_surface_sha256: {recorded_hash}\n"
            f"  current  policy_surface_sha256: {current_hash}\n\n"
            "Required action:\n"
            "  1) Bump signal_logic_version in src/code_audit/model/run_result.py\n"
            "  2) python scripts/refresh_exit_code_policy_manifest.py\n"
            "  3) Commit updated tests/contracts/exit_code_policy_manifest.json\n"
        )

    if bumped and not changed:
        # Provenance sync rule: if signal_logic_version bumps, refresh manifest
        # so it records the new value.
        raise AssertionError(
            "signal_logic_version bumped but exit-code policy manifest not refreshed.\n"
            f"  current signal_logic_version: {current_sig!r}\n"
            f"  manifest signal_logic_version: {recorded_sig!r}\n"
            "Fix:\n"
            "  python scripts/refresh_exit_code_policy_manifest.py\n"
        )

    # Both match: either (unchanged, not bumped) or (changed + bumped + refreshed).
    # Either way the manifest is consistent with the current state.
