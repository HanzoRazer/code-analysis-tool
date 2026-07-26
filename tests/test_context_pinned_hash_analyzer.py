"""Unit tests for the context-pinned-hash detector.

The detector flags a hash asserted byte-equal across a context it wasn't computed
in — line endings (CRLF/LF/OS) or interpreter version (ast.dump). v1 is a
source-pattern heuristic that records the axis + whether an in-file mitigation is
visible, leaving ``context_confirmed=False`` for the v2 enrichment pass.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.context_pinned_hash import ContextPinnedHashAnalyzer
from code_audit.model import AnalyzerType, Severity


def _run(tmp_path: Path, src: str, name: str = "m.py"):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    return ContextPinnedHashAnalyzer().run(tmp_path, [p])


# ── byte / line-ending axis ─────────────────────────────────────────


def test_byte_hash_of_file_flagged_unmitigated(tmp_path):
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    return hashlib.sha256(p.read_bytes()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.CONTEXT_PINNED_HASH
    assert f[0].metadata["context_axis"] == "line_ending"
    assert f[0].metadata["mitigation_detected"] is False
    assert f[0].metadata["context_confirmed"] is False
    assert f[0].severity is Severity.MEDIUM
    # finding_id must be non-empty (schema minLength) — the web_api scan path
    # validates findings and 500s on an empty id.
    assert f[0].finding_id
    assert f[0].finding_id == f[0].fingerprint


def test_byte_hash_with_lf_normalize_is_mitigated(tmp_path):
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    b = p.read_bytes().replace(b'\\r\\n', b'\\n')\n"
        "    return hashlib.sha256(b).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["mitigation_detected"] is True
    assert f[0].metadata["mitigation_kind"] == "input_lf_normalized"
    assert f[0].severity is Severity.LOW


def test_binary_open_read_flagged(tmp_path):
    src = (
        "import hashlib\n"
        "def sha(path):\n"
        "    h = hashlib.sha256()\n"
        "    with open(path, 'rb') as fh:\n"
        "        for chunk in iter(lambda: fh.read(4096), b''):\n"
        "            h.update(chunk)\n"
        "    return h.hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "line_ending"


def test_read_text_not_flagged(tmp_path):
    # read_text() uses universal newlines → normalized on read → not the risk.
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    return hashlib.sha256(p.read_text().encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert f == []


# ── ast.dump / interpreter-version axis ─────────────────────────────


def test_ast_dump_hash_flagged_unmitigated(tmp_path):
    src = (
        "import ast, hashlib\n"
        "def h(src: str):\n"
        "    tree = ast.parse(src)\n"
        "    return hashlib.sha256(ast.dump(tree).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "python_version"
    assert f[0].metadata["mitigation_detected"] is False


def test_ast_dump_hash_with_version_guard_is_mitigated(tmp_path):
    src = (
        "import ast, hashlib, sys\n"
        "def _require_ci_python():\n"
        "    assert sys.version_info[:2] == (3, 11)\n"
        "def h(src: str):\n"
        "    tree = ast.parse(src)\n"
        "    return hashlib.sha256(ast.dump(tree).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "python_version"
    assert f[0].metadata["mitigation_detected"] is True
    assert f[0].metadata["mitigation_kind"] == "generator_python_pinned"


# ── helper / wrapper indirection ────────────────────────────────────


def test_hash_wrapper_indirection_caught(tmp_path):
    # hash constructor in one function, file read in the caller — the common
    # `_sha256_file -> _sha256_bytes` helper shape (contracts_bundle).
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def _sha256_bytes(b):\n"
        "    return hashlib.sha256(b).hexdigest()\n"
        "def _sha256_file(p: Path):\n"
        "    return _sha256_bytes(p.read_bytes())\n"
    )
    f = _run(tmp_path, src)
    # _sha256_file is the context-pinned one (reads bytes, calls the wrapper).
    paths_axes = {(x.location.path, x.metadata["context_axis"]) for x in f}
    assert any(ax == "line_ending" for _, ax in paths_axes)


# ── negative cases ──────────────────────────────────────────────────


def test_no_hash_no_finding(tmp_path):
    src = "def add(a, b):\n    return a + b\n"
    assert _run(tmp_path, src) == []


def test_hash_of_non_file_literal_not_flagged(tmp_path):
    # Hashing an in-memory string constant is not context-pinned to a file.
    src = (
        "import hashlib\n"
        "def h():\n"
        "    return hashlib.sha256(b'constant').hexdigest()\n"
    )
    assert _run(tmp_path, src) == []


def test_syntax_error_file_skipped(tmp_path):
    f = _run(tmp_path, "def broken(:\n")
    assert f == []
