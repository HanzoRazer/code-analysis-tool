"""Contract gate: confidence golden surface requires confidence_logic_version bump.

This is a confidence-SPECIFIC contract gate that lives alongside (not instead of)
the general golden manifest gate. It enforces:

  1. Forward: if any confidence-guarded file (code closure + golden fixtures)
     changes, both confidence_logic_version AND signal_logic_version must bump.
  2. Reverse: if either version changes, the confidence golden manifest must
     be refreshed.
  3. Closure stability: the dependency closure must match the manifest's
     recorded closure_files list.

Dependency-closure hashing:
  - Starts from entrypoint(s) (default: insights/confidence.py)
  - Recursively resolves all code_audit.* imports (BFS, deterministic order)
  - AST-normalizes each Python module (strips docstrings + version anchors)
  - Hashes fixture files byte-level

Override:
  CONFIDENCE_ENTRYPOINTS="src/code_audit/insights/confidence.py,..."
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterable

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "contracts" / "confidence_golden_manifest.json"
SRC_ROOT = ROOT / "src" / "code_audit"


# ── CI enforcement ───────────────────────────────────────────────────


def _is_ci() -> bool:
    v = os.environ.get("CI", "").strip()
    return v.lower() in {"1", "true", "yes", "on"}


def _require_entrypoints_in_ci() -> None:
    if _is_ci() and not os.environ.get("CONFIDENCE_ENTRYPOINTS", "").strip():
        raise AssertionError(
            "CI=true but CONFIDENCE_ENTRYPOINTS is not set.\n"
            "Set it in CI to avoid running confidence hashing in default mode.\n"
            'Example: CONFIDENCE_ENTRYPOINTS="src/code_audit/insights/confidence.py"\n'
        )


# ── Entrypoint resolution ───────────────────────────────────────────


def _entrypoints() -> list[Path]:
    _require_entrypoints_in_ci()
    override = os.environ.get("CONFIDENCE_ENTRYPOINTS", "").strip()
    if override:
        eps = [ROOT / p.strip() for p in override.split(",") if p.strip()]
        return sorted(eps, key=lambda p: p.as_posix())
    return [SRC_ROOT / "insights" / "confidence.py"]


# ── Import resolution helpers ────────────────────────────────────────


def _is_internal_module(mod: str) -> bool:
    return mod == "code_audit" or mod.startswith("code_audit.")


def _module_to_path(mod: str) -> Path | None:
    if not _is_internal_module(mod):
        return None
    rel = mod.split(".", 1)[1] if mod != "code_audit" else ""
    base = SRC_ROOT / Path(*([p for p in rel.split(".") if p] or []))
    file_py = base.with_suffix(".py")
    pkg_init = base / "__init__.py"
    if file_py.exists():
        return file_py
    if pkg_init.exists():
        return pkg_init
    return None


def _resolve_from_import(module_file: Path, node: ast.ImportFrom) -> list[Path]:
    results: list[Path] = []
    if node.level and node.level > 0:
        rel_parts = module_file.relative_to(SRC_ROOT).parts
        pkg_parts = (
            rel_parts[:-1] if rel_parts[-1] != "__init__.py" else rel_parts[:-1]
        )
        up = node.level - 1
        base_parts = pkg_parts[:-up] if up and up <= len(pkg_parts) else pkg_parts
        base_mod = "code_audit" + (
            ("." + ".".join(base_parts)) if base_parts else ""
        )
        full_mod = base_mod + ("." + node.module if node.module else "")
    else:
        full_mod = node.module or ""

    if not full_mod:
        return results

    p = _module_to_path(full_mod)
    if p:
        results.append(p)

    for alias in node.names:
        if alias.name == "*":
            continue
        sp = _module_to_path(f"{full_mod}.{alias.name}")
        if sp:
            results.append(sp)

    return results


def _extract_internal_imports(module_file: Path, src: str) -> list[Path]:
    tree = ast.parse(src)
    deps: list[Path] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _is_internal_module(a.name):
                    p = _module_to_path(a.name)
                    if p:
                        deps.append(p)
        elif isinstance(node, ast.ImportFrom):
            deps.extend(_resolve_from_import(module_file, node))
    return sorted(set(deps), key=lambda p: p.as_posix())


# ── Dependency closure ───────────────────────────────────────────────


def _closure(entrypoints: Iterable[Path]) -> list[Path]:
    missing = [p for p in entrypoints if not p.exists()]
    assert not missing, (
        "Missing confidence entrypoint(s):\n  - "
        + "\n  - ".join(str(p) for p in missing)
        + "\nSet CONFIDENCE_ENTRYPOINTS to valid paths."
    )

    seen: set[Path] = set()
    stack: list[Path] = sorted(set(entrypoints), key=lambda p: p.as_posix())
    out: list[Path] = []

    while stack:
        p = stack.pop(0)
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        src = p.read_text(encoding="utf-8")
        for d in _extract_internal_imports(p, src):
            if d not in seen and d not in stack:
                stack.append(d)
        stack.sort(key=lambda x: x.as_posix())

    return out


# ── AST normalization (semantic-only hashing) ────────────────────────

_VERSION_ANCHORS = {"confidence_logic_version", "CONFIDENCE_POLICY_VERSION"}


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


class _GoldenTransformer(ast.NodeTransformer):
    """Strip docstrings and version anchor assignments for semantic hashing."""

    def visit_Module(self, node: ast.Module) -> ast.AST:
        node.body = _strip_docstring(node.body)
        node.body = [
            s for s in (self.visit(stmt) for stmt in node.body) if s is not None
        ]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.body = _strip_docstring(node.body)
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.body = _strip_docstring(node.body)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.body = _strip_docstring(node.body)
        self.generic_visit(node)
        return node

    def visit_Assign(self, node: ast.Assign) -> ast.AST | None:
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in _VERSION_ANCHORS:
                return None
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST | None:
        if (
            isinstance(node.target, ast.Name)
            and node.target.id in _VERSION_ANCHORS
        ):
            return None
        return node


def _ast_hash(src: str) -> str:
    tree = ast.parse(src)
    tree = _GoldenTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree, include_attributes=False)


def _sha256_bytes(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Version resolution (source parse, no imports) ────────────────────


def _read_signal_logic_version() -> str:
    candidates = [
        ROOT / "src" / "code_audit" / "model" / "run_result.py",
        ROOT / "src" / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        txt = p.read_text(encoding="utf-8")
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", txt)
        if m:
            return m.group(1)
    raise AssertionError("Could not locate signal_logic_version in run_result.py")


def _read_confidence_logic_version() -> str:
    p = ROOT / "src" / "code_audit" / "insights" / "confidence.py"
    txt = p.read_text(encoding="utf-8")
    m = re.search(r'\bconfidence_logic_version\s*=\s*["\']([^"\']+)["\']', txt)
    assert m, (
        "Could not locate confidence_logic_version in "
        "src/code_audit/insights/confidence.py"
    )
    return m.group(1)


# ── Hash computation ─────────────────────────────────────────────────


def _compute_file_hash(rel: str) -> tuple[str, str]:
    """Return (hash, mode) for a file: AST for .py, bytes for JSON."""
    p = ROOT / rel
    if rel.endswith(".py"):
        src = p.read_text(encoding="utf-8")
        normalized = _ast_hash(src)
        h = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        return h, "ast"
    return _sha256_bytes(p), "bytes"


# ── Test ─────────────────────────────────────────────────────────────


@pytest.mark.contract
def test_confidence_golden_surface_requires_confidence_version_bump() -> None:
    """If confidence scoring surface changes, confidence_logic_version must bump.

    Enforces:
      - Forward: code closure OR golden fixture drift → both version bumps required
      - Reverse: version bump without manifest refresh → fail
      - Closure stability: dependency closure must match manifest's closure_files
    """
    assert MANIFEST.exists(), (
        "Missing confidence golden manifest.\n"
        "Run:\n"
        "  python scripts/refresh_confidence_golden_manifest.py\n"
        "and commit tests/contracts/confidence_golden_manifest.json"
    )

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest.get("manifest_version") == 1, "Unexpected manifest_version"

    # ── Closure stability ────────────────────────────────────────
    closure_files = _closure(_entrypoints())
    closure_rels = sorted(
        str(p.relative_to(ROOT)).replace("\\", "/") for p in closure_files
    )

    recorded_closure = manifest.get("closure_files")
    assert isinstance(recorded_closure, list), "Manifest missing closure_files list"
    assert sorted(recorded_closure) == closure_rels, (
        "Confidence dependency closure changed but manifest was not refreshed.\n"
        f"  recorded: {sorted(recorded_closure)}\n"
        f"  current:  {closure_rels}\n"
        "Run: python scripts/refresh_confidence_golden_manifest.py\n"
    )

    # ── Version anchors ──────────────────────────────────────────
    recorded_conf_v = manifest.get("confidence_logic_version")
    assert isinstance(recorded_conf_v, str) and recorded_conf_v, (
        "Manifest missing non-empty confidence_logic_version"
    )

    recorded_sig_v = manifest.get("signal_logic_version")
    assert isinstance(recorded_sig_v, str) and recorded_sig_v, (
        "Manifest missing non-empty signal_logic_version"
    )

    recorded_files = manifest.get("files")
    assert isinstance(recorded_files, dict) and recorded_files, (
        "Manifest missing files map"
    )

    recorded_modes = manifest.get("hash_modes")
    assert isinstance(recorded_modes, dict) and recorded_modes, (
        "Manifest missing hash_modes map"
    )

    # ── Recompute hashes and detect drift ────────────────────────
    drift: list[str] = []
    for rel, recorded_hash in recorded_files.items():
        p = ROOT / rel
        assert p.exists(), f"Missing file referenced by confidence manifest: {rel}"

        current_hash, mode = _compute_file_hash(rel)

        # Verify hash modes match
        assert recorded_modes.get(rel) == mode, (
            f"Hash mode mismatch for {rel}:\n"
            f"  manifest: {recorded_modes.get(rel)!r}\n"
            f"  current:  {mode!r}\n"
            "Run: python scripts/refresh_confidence_golden_manifest.py\n"
        )

        if current_hash != recorded_hash:
            drift.append(rel)

    current_conf_v = _read_confidence_logic_version()
    current_sig_v = _read_signal_logic_version()

    if drift:
        # ── Forward enforcement: drift requires version bumps ────
        assert current_conf_v != recorded_conf_v, (
            "Confidence golden contract surface changed without bumping "
            "confidence_logic_version.\n\n"
            "Changed files:\n  - " + "\n  - ".join(drift) + "\n\n"
            "Required action:\n"
            "  1) Bump confidence_logic_version in "
            "src/code_audit/insights/confidence.py\n"
            "  2) (If scoring changed) run: "
            "python scripts/refresh_golden_confidence.py\n"
            "  3) Run: python scripts/refresh_confidence_golden_manifest.py\n"
            "  4) Commit updated manifest (and expected fixtures if applicable)\n"
        )

        # Max governance: confidence semantic drift also requires
        # signal_logic_version bump since confidence is user-visible.
        assert current_sig_v != recorded_sig_v, (
            "Confidence semantic surface changed but signal_logic_version "
            "was not bumped.\n\n"
            "Confidence is a user-visible semantic surface. Required action:\n"
            "  Bump signal_logic_version in "
            "src/code_audit/model/run_result.py\n"
        )
    else:
        # ── Reverse enforcement: version bumps need manifest refresh ─
        assert current_conf_v == recorded_conf_v, (
            "confidence_logic_version changed but confidence golden manifest "
            "was not refreshed.\n"
            "Run: python scripts/refresh_confidence_golden_manifest.py\n"
        )
        assert current_sig_v == recorded_sig_v, (
            "signal_logic_version changed but confidence golden manifest "
            "was not refreshed.\n"
            "Run: python scripts/refresh_confidence_golden_manifest.py\n"
        )
