"""Unit tests for the unbacked-capability-claim analyzer.

Flags a comment/docstring that claims a library the module never imports — the
claimed code path cannot exist. Distinct from a mere prose mention: the claim shape
("fallback to X", "uses X", "X-based") is the discriminator, not the bare name.

Born-from-the-bug acceptance test: the MAINT-DEFER-010 shape — ``# Fallback to
scipy if available`` in a module that imports only numpy and runs a ``np.diag``
substitute — must fire HIGH, naming scipy.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.unbacked_claim import UnbackedClaimAnalyzer
from code_audit.contracts.validate import validate_finding
from code_audit.model import AnalyzerType, Severity


def _run(root: Path):
    return UnbackedClaimAnalyzer().run(root, [])


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _libs(findings):
    return sorted(f.metadata["claimed_library"] for f in findings)


# ── born-from-the-bug acceptance (MAINT-DEFER-010) ──────────────────
def test_acceptance_rayleigh_ritz_scipy_fallback(tmp_path):
    """A scipy fallback claimed in front of a numpy-only substitute — no scipy
    imported anywhere — must fire HIGH."""
    _write(tmp_path, "rayleigh_ritz.py",
           "import numpy as np\n\n"
           "def solve(K, M):\n"
           "    # Fallback to scipy if available\n"
           "    w = np.diag(K) / np.diag(M)\n"
           "    return w, np.eye(len(w))\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.UNBACKED_CLAIM
    assert f[0].severity is Severity.HIGH
    assert f[0].metadata["claimed_library"] == "scipy"
    assert f[0].metadata["claim_kind"] == "fallback"
    assert f[0].metadata["source"] == "comment"
    assert f[0].location.line_start == 4
    assert f[0].finding_id


# ── severity split ──────────────────────────────────────────────────
def test_plain_use_docstring_is_medium(tmp_path):
    _write(tmp_path, "jit.py", 'def f():\n    """A numba-based fast path."""\n    return 0\n')
    f = _run(tmp_path)
    assert _libs(f) == ["numba"]
    assert f[0].severity is Severity.MEDIUM
    assert f[0].metadata["claim_kind"] == "plain"
    assert f[0].metadata["source"] == "docstring"

def test_if_available_shape_is_high(tmp_path):
    _write(tmp_path, "m.py", "# use torch if available\nx = 1\n")
    f = _run(tmp_path)
    assert f[0].severity is Severity.HIGH and f[0].metadata["claimed_library"] == "torch"


# ── negative cases (the discriminators) ─────────────────────────────
def test_imported_library_is_silent(tmp_path):
    _write(tmp_path, "m.py", "import scipy.linalg\n# uses scipy for the eig solve\nx = 1\n")
    assert _run(tmp_path) == []

def test_from_import_backs_the_claim(tmp_path):
    _write(tmp_path, "m.py", "from scipy import linalg\n# scipy-based solve\nx = 1\n")
    assert _run(tmp_path) == []

def test_try_except_guarded_import_is_silent(tmp_path):
    _write(tmp_path, "m.py",
           "try:\n    import torch\nexcept ImportError:\n    torch = None\n"
           "# uses torch when available\nx = 1\n")
    assert _run(tmp_path) == []

def test_function_local_import_backs_the_claim(tmp_path):
    _write(tmp_path, "m.py",
           "# uses numba for the hot loop\n"
           "def f():\n    import numba\n    return numba\n")
    assert _run(tmp_path) == []

def test_dynamic_import_module_backs_the_claim(tmp_path):
    _write(tmp_path, "m.py",
           "import importlib\n"
           "# falls back to scipy if available\n"
           "mod = importlib.import_module('scipy')\n")
    assert _run(tmp_path) == []

def test_mere_prose_mention_is_silent(tmp_path):
    """'faster than scipy', 'unlike torch' are comparisons, not capability claims."""
    _write(tmp_path, "m.py",
           "import numpy as np\n"
           "# this is faster than scipy and unlike torch, similar to jax\nx = 1\n")
    assert _run(tmp_path) == []

def test_library_outside_known_set_is_silent(tmp_path):
    """Ubiquitous libs (pandas/numpy/requests) are deliberately not in the set."""
    _write(tmp_path, "m.py", "# uses pandas for the join\nx = 1\n")
    assert _run(tmp_path) == []


# ── dedup / precedence / multiline ──────────────────────────────────
def test_high_beats_medium_on_same_line(tmp_path):
    _write(tmp_path, "m.py", "# uses scipy, falls back to scipy if available\nx = 1\n")
    f = _run(tmp_path)
    assert len(f) == 1 and f[0].severity is Severity.HIGH

def test_multiline_docstring_reports_the_claim_line(tmp_path):
    _write(tmp_path, "m.py",
           'def f():\n'
           '    """Summary line.\n\n'
           '    Falls back to scipy if available.\n'
           '    """\n'
           '    return 0\n')
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["claimed_library"] == "scipy"
    assert f[0].location.line_start == 4  # the claim's physical line

def test_two_libraries_two_findings(tmp_path):
    _write(tmp_path, "m.py", "# uses cupy\n# fallback to numba if available\nx = 1\n")
    assert _libs(_run(tmp_path)) == ["cupy", "numba"]


# ── robustness / contract ───────────────────────────────────────────
def test_unparseable_file_skipped_other_survives(tmp_path):
    _write(tmp_path, "broken.py", "def (:\n")
    _write(tmp_path, "ok.py", "# fallback to scipy if available\nx = 1\n")
    assert _libs(_run(tmp_path)) == ["scipy"]

def test_internal_failure_becomes_finding_never_raises(tmp_path, monkeypatch):
    _write(tmp_path, "m.py", "# fallback to scipy if available\nx = 1\n")

    def boom(self, root):
        raise RuntimeError("synthetic scan failure")

    monkeypatch.setattr(UnbackedClaimAnalyzer, "_run_inner", boom)
    f = UnbackedClaimAnalyzer().run(tmp_path, [])
    assert len(f) == 1
    assert f[0].metadata["rule_id"] == "UNBACKED_CLAIM_ERROR"
    assert "synthetic scan failure" in f[0].message

def test_findings_contract_valid(tmp_path):
    _write(tmp_path, "a.py", "# fallback to scipy if available\nx = 1\n")
    _write(tmp_path, "b.py", 'def f():\n    """torch-based path."""\n    return 0\n')
    for f in _run(tmp_path):
        validate_finding(f.to_dict())
