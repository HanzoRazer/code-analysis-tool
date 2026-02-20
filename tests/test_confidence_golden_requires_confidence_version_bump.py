"""Contract gate: confidence golden surface requires confidence_logic_version bump.

Confidence-specific version enforcement — separate from the general golden gate.
Enforces that changes to confidence scoring semantics (code OR golden fixtures)
require a dedicated ``confidence_logic_version`` bump AND a ``signal_logic_version``
bump (since confidence is a user-visible semantic surface).

Uses dependency-closure hashing with AST normalization:
  - Starts from entrypoint(s) (default: insights/confidence.py)
  - Recursively resolves all ``code_audit.*`` imports
  - AST-normalizes each module (strips docstrings + version anchors)
  - Hashes closure files (AST) + golden fixtures (bytes)

Override:
  CONFIDENCE_ENTRYPOINTS="src/code_audit/insights/confidence.py,..."
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.toml_subset_hash import canonical_toml_subset_hash  # noqa: E402

MANIFEST = ROOT / "tests" / "contracts" / "confidence_golden_manifest.json"
SRC_ROOT = ROOT / "src" / "code_audit"


# ── CI enforcement ───────────────────────────────────────────────────


def _is_ci() -> bool:
    v = os.environ.get("CI", "").strip()
    return v.lower() in {"1", "true", "yes", "on"}


def _require_entrypoints_in_ci() -> None:
    if _is_ci() and not os.environ.get("CONFIDENCE_ENTRYPOINTS", "").strip():
        raise AssertionError(
            "CI requires CONFIDENCE_ENTRYPOINTS to be set to avoid default "
            "entrypoint mode.\n"
            "Example:\n"
            "  CONFIDENCE_ENTRYPOINTS=src/code_audit/insights/confidence.py\n"
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


def _path_to_module(p: Path) -> str:
    """Convert a resolved file path back to a dotted module name."""
    rel = p.relative_to(SRC_ROOT)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1].removesuffix(".py").removesuffix(".pyi")
    return "code_audit" + ("." + ".".join(parts) if parts else "")


def _resolve_from_import(
    module_file: Path, node: ast.ImportFrom
) -> list[tuple[str, Path]]:
    """Resolve a from-import node to a list of (module_name, path) pairs."""
    results: list[tuple[str, Path]] = []
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
        results.append((full_mod, p))

    for alias in node.names:
        if alias.name == "*":
            continue
        sub_mod = f"{full_mod}.{alias.name}"
        sp = _module_to_path(sub_mod)
        if sp:
            results.append((sub_mod, sp))

    return results


def _extract_internal_imports(
    module_file: Path, src: str
) -> list[tuple[str, Path]]:
    """Extract internal imports as (target_module_name, resolved_path) pairs."""
    tree = ast.parse(src)
    deps: list[tuple[str, Path]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _is_internal_module(a.name):
                    p = _module_to_path(a.name)
                    if p:
                        deps.append((a.name, p))
        elif isinstance(node, ast.ImportFrom):
            deps.extend(_resolve_from_import(module_file, node))
    # Deduplicate by path, keeping first module name seen per path
    seen: set[Path] = set()
    unique: list[tuple[str, Path]] = []
    for mod_name, p in sorted(deps, key=lambda x: x[1].as_posix()):
        if p not in seen:
            seen.add(p)
            unique.append((mod_name, p))
    return unique


# ── Dependency closure ───────────────────────────────────────────────


class _ClosureResult:
    """Result of dependency closure computation."""

    def __init__(
        self,
        files: list[Path],
        edges: list[tuple[str, str]],
    ) -> None:
        self.files = files
        self.edges = edges


def _closure(entrypoints: Iterable[Path]) -> _ClosureResult:
    missing = [p for p in entrypoints if not p.exists()]
    assert not missing, (
        "Missing confidence entrypoint(s):\n  - "
        + "\n  - ".join(str(p) for p in missing)
        + "\nSet CONFIDENCE_ENTRYPOINTS to valid paths."
    )

    seen: set[Path] = set()
    stack: list[Path] = sorted(set(entrypoints), key=lambda p: p.as_posix())
    out: list[Path] = []
    edges: set[tuple[str, str]] = set()

    while stack:
        p = stack.pop(0)
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        src = p.read_text(encoding="utf-8")
        src_mod = _path_to_module(p)
        for dep_mod, dep_path in _extract_internal_imports(p, src):
            # Track graph edge even if dep already visited; structure matters.
            edges.add((src_mod, dep_mod))
            if dep_path not in seen and dep_path not in stack:
                stack.append(dep_path)
        stack.sort(key=lambda x: x.as_posix())

    return _ClosureResult(files=out, edges=sorted(edges))


# ── AST normalization ────────────────────────────────────────────────

_VERSION_KEYS = {
    "confidence_logic_version",
    "signal_logic_version",
    "CONFIDENCE_POLICY_VERSION",
}


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


class _SemanticTransformer(ast.NodeTransformer):
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
            if isinstance(t, ast.Name) and t.id in _VERSION_KEYS:
                return None
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST | None:
        if (
            isinstance(node.target, ast.Name)
            and node.target.id in _VERSION_KEYS
        ):
            return None
        return node


def _normalize_module_for_hash(src: str) -> str:
    tree = ast.parse(src)
    tree = _SemanticTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree, include_attributes=False)


# ── Hash computation ─────────────────────────────────────────────────


def _sha256_bytes(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def _fallback_stub_semantic_hash(text: str) -> str:
    """Fallback normalizer for stubs when ast.parse fails."""
    lines = []
    for line in text.splitlines():
        if "#" in line:
            line = line.split("#", 1)[0]
        lines.append(line)
    s = "\n".join(lines)
    s = re.sub(r"\s+", " ", s).strip()
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# Controlled pyproject semantic surface — must match refresh script.
PYPROJECT_ALLOWED_PATHS: list[list[str]] = [
    ["tool", "code_audit", "confidence"],
]


def _compute_file_hash(rel: str, mode: str) -> str:
    """Compute hash for a file (or synthetic key) using the specified mode."""
    # Synthetic keys first
    if rel == "pyproject.toml::confidence_scoring_keys_v1":
        pyproject = ROOT / "pyproject.toml"
        assert pyproject.exists(), "pyproject.toml missing but manifest expects it"
        h, _subset = canonical_toml_subset_hash(pyproject, PYPROJECT_ALLOWED_PATHS)
        return h

    p = ROOT / rel
    if mode == "ast":
        src = p.read_text(encoding="utf-8")
        norm = _normalize_module_for_hash(src)
        return hashlib.sha256(
            f"# {p.as_posix()}\n{norm}\n".encode("utf-8")
        ).hexdigest()
    if mode == "stub_norm":
        src = p.read_text(encoding="utf-8")
        return _fallback_stub_semantic_hash(src)
    return _sha256_bytes(p)


def _sha256_canonical_json(obj: object) -> str:
    """Deterministic SHA-256 over a canonical JSON serialization."""
    blob = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ── Version anchors ──────────────────────────────────────────────────


def _read_signal_logic_version() -> str:
    candidates = [
        ROOT / "src" / "code_audit" / "model" / "run_result.py",
        ROOT / "src" / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = p.read_text(encoding="utf-8")
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)
    raise AssertionError("Could not locate signal_logic_version")


def _read_confidence_logic_version() -> str:
    target = ROOT / "src" / "code_audit" / "insights" / "confidence.py"
    s = target.read_text(encoding="utf-8")
    m = re.search(r'\bconfidence_logic_version\s*=\s*["\']([^"\']+)["\']', s)
    assert m, "Could not locate confidence_logic_version in confidence.py"
    return m.group(1)


# ── Test ─────────────────────────────────────────────────────────────


@pytest.mark.contract
def test_confidence_golden_surface_requires_confidence_version_bump() -> None:
    """If confidence golden surface changes, confidence_logic_version must bump.

    Enforces three directions:
      1. Drift in code closure or fixtures → confidence_logic_version must change
      2. Drift in code closure or fixtures → signal_logic_version must change
      3. Version changed → manifest must be refreshed (closure list + hashes)
    """
    assert MANIFEST.exists(), (
        "Missing confidence golden manifest.\n"
        "Run:\n"
        "  python scripts/refresh_confidence_golden_manifest.py\n"
        "and commit tests/contracts/confidence_golden_manifest.json"
    )

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest.get("manifest_version") == 1

    # ── Verify closure reproducibility ───────────────────────────
    closure = _closure(_entrypoints())
    recorded_closure = manifest.get("closure_files")
    assert isinstance(recorded_closure, list), "Manifest missing closure_files list"
    current_closure = [
        str(p.relative_to(ROOT)).replace("\\", "/") for p in closure.files
    ]
    assert sorted(current_closure) == sorted(recorded_closure), (
        "Confidence dependency closure changed but manifest was not refreshed.\n"
        f"  recorded: {sorted(recorded_closure)}\n"
        f"  current:  {sorted(current_closure)}\n"
        "Run: python scripts/refresh_confidence_golden_manifest.py\n"
    )

    # ── Verify closure graph (edges) ─────────────────────────────
    recorded_graph_hash = manifest.get("closure_graph_sha256")
    assert isinstance(recorded_graph_hash, str) and recorded_graph_hash, (
        "Manifest missing closure_graph_sha256"
    )

    entrypoint_mods = [_path_to_module(p) for p in _entrypoints()]
    graph = {
        "version": 1,
        "entrypoints": entrypoint_mods,
        "edges": [list(e) for e in closure.edges],
    }
    current_graph_hash = _sha256_canonical_json(graph)
    assert current_graph_hash == recorded_graph_hash, (
        "Confidence closure graph changed (import rewiring) but manifest was "
        "not refreshed.\n"
        "Run: python scripts/refresh_confidence_golden_manifest.py\n"
    )

    # Edge list equality (more diagnostic than hash mismatch alone)
    recorded_edges = manifest.get("closure_edges")
    assert isinstance(recorded_edges, list), "Manifest missing closure_edges list"
    assert sorted(recorded_edges) == sorted(
        [list(e) for e in closure.edges]
    ), (
        "Confidence closure edges changed but manifest was not refreshed.\n"
        "Run: python scripts/refresh_confidence_golden_manifest.py\n"
    )

    # ── Verify file hashes ───────────────────────────────────────
    recorded_conf_v = manifest.get("confidence_logic_version")
    assert isinstance(recorded_conf_v, str) and recorded_conf_v

    recorded_sig_v = manifest.get("signal_logic_version")
    assert isinstance(recorded_sig_v, str) and recorded_sig_v

    recorded_files = manifest.get("files")
    assert isinstance(recorded_files, dict) and recorded_files, (
        "Manifest missing 'files' map"
    )

    recorded_modes = manifest.get("hash_modes")
    assert isinstance(recorded_modes, dict) and recorded_modes, (
        "Manifest missing 'hash_modes' map"
    )

    drift: list[str] = []
    for rel, recorded_hash in recorded_files.items():
        if "::" not in rel:
            p = ROOT / rel
            assert p.exists(), f"Missing file referenced by confidence manifest: {rel}"
        mode = recorded_modes.get(rel, "bytes")
        current_hash = _compute_file_hash(rel, mode)
        if current_hash != recorded_hash:
            drift.append(rel)

    current_conf_v = _read_confidence_logic_version()
    current_sig_v = _read_signal_logic_version()

    if drift:
        # Confidence-specific bump is required on drift
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

        # Max governance: confidence semantic drift also requires engine signal bump
        assert current_sig_v != recorded_sig_v, (
            "Confidence semantic surface changed but signal_logic_version was "
            "not bumped.\n\n"
            "Confidence is a user-visible semantic surface. Required action:\n"
            "  Bump signal_logic_version in src/code_audit/model/run_result.py\n"
        )
    else:
        # No drift → versions must match manifest for provenance clarity
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
