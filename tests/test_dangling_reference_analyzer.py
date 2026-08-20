"""Unit tests for the dangling-reference analyzer.

Flags references to first-party modules that no longer exist in the tree — the
inverse of dead_code (callee deleted, callers left in place). Distinct from a
missing third-party import: the discriminator is that the reference's *top-level*
package still resolves but its *full dotted path* does not.

Includes the born-from-the-bug acceptance test: the MAINT-DEFER-009 shape, where
``app/retopo/`` was deleted as "unused" while ``examples/retopo/run.sh`` still runs
``python -m app.retopo.run`` and a CI workflow invokes that script. The detector
must fire on the surviving caller.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.dangling_reference import DanglingReferenceAnalyzer
from code_audit.contracts.validate import validate_finding
from code_audit.model import AnalyzerType, Severity


def _run(root: Path):
    return DanglingReferenceAnalyzer().run(root, [])


def _write(root: Path, rel: str, content: str = "") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _pkg(root: Path, *rels: str) -> None:
    """Create ``app/`` as a surviving first-party package (so ``app`` resolves)."""
    _write(root, "app/__init__.py", "")
    _write(root, "app/config.py", "SETTINGS = 1\n")
    for rel in rels:
        _write(root, rel)


def _missing(findings):
    return sorted(f.metadata["missing_module"] for f in findings)


# ── positive cases (one reference context each) ─────────────────────
def test_python_import_of_deleted_module_flagged(tmp_path):
    _pkg(tmp_path)
    _write(tmp_path, "driver.py", "import app.retopo.run\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.DANGLING_REFERENCE
    assert f[0].severity is Severity.HIGH
    assert f[0].metadata["missing_module"] == "app.retopo.run"
    assert f[0].metadata["top_level"] == "app"
    assert f[0].metadata["reference_kind"] == "import"
    assert f[0].metadata["source"] == "python"
    assert f[0].location.path == "driver.py"
    assert f[0].location.line_start == 1
    assert f[0].finding_id


def test_python_from_import_of_deleted_module_flagged(tmp_path):
    _pkg(tmp_path)
    _write(tmp_path, "driver.py", "\nfrom app.retopo.run import run_pipeline\n")
    f = _run(tmp_path)
    assert _missing(f) == ["app.retopo.run"]
    assert f[0].metadata["reference_kind"] == "from-import"
    assert f[0].location.line_start == 2


def test_shell_python_m_of_deleted_module_flagged(tmp_path):
    _pkg(tmp_path)
    _write(tmp_path, "examples/retopo/run.sh", "#!/bin/sh\npython -m app.retopo.run --flag\n")
    f = _run(tmp_path)
    assert _missing(f) == ["app.retopo.run"]
    assert f[0].metadata["reference_kind"] == "python-m"
    assert f[0].metadata["source"] == "config"
    assert f[0].location.path == "examples/retopo/run.sh"


def test_yaml_inline_import_of_deleted_module_flagged(tmp_path):
    _pkg(tmp_path)
    _write(tmp_path, ".github/workflows/ci.yml",
           "jobs:\n  x:\n    steps:\n"
           "      - run: python -c 'from app.retopo.run import run_pipeline'\n")
    f = _run(tmp_path)
    assert _missing(f) == ["app.retopo.run"]
    assert f[0].location.path == ".github/workflows/ci.yml"


def test_toml_entrypoint_of_deleted_module_flagged(tmp_path):
    _pkg(tmp_path)
    _write(tmp_path, "pyproject.toml",
           '[project.scripts]\nretopo = "app.retopo.run:main"\n')
    f = _run(tmp_path)
    assert _missing(f) == ["app.retopo.run"]
    assert f[0].metadata["reference_kind"] == "entry-point"


# ── born-from-the-bug acceptance (MAINT-DEFER-009) ──────────────────
def test_acceptance_maint_defer_009_retopo_shape(tmp_path):
    """``app/retopo/`` deleted as "unused"; ``run.sh`` still calls
    ``python -m app.retopo.run`` and a CI workflow runs that script. The dangling
    caller in run.sh must fire — the deletion left a call to code that exists at no
    reachable commit. ``app/`` and a sibling ``app.config`` still resolve, proving
    the detector keys on the missing *path*, not a missing top-level package."""
    _pkg(tmp_path)  # app/ survives, app.config resolves
    _write(tmp_path, "examples/retopo/run.sh",
           "#!/usr/bin/env bash\nset -e\npython -m app.retopo.run \"$@\"\n")
    _write(tmp_path, ".github/workflows/mesh-pipeline-ci.yml",
           "jobs:\n  mesh:\n    steps:\n"
           "      - run: bash examples/retopo/run.sh\n"
           "      - run: bash examples/retopo/run.sh --second\n")
    # a live, resolvable first-party call that must stay silent
    _write(tmp_path, "app/main.py", "from app.config import SETTINGS\n")

    f = _run(tmp_path)
    assert _missing(f) == ["app.retopo.run"]
    hit = f[0]
    assert hit.severity is Severity.HIGH
    assert hit.location.path == "examples/retopo/run.sh"
    assert hit.location.line_start == 3
    assert "app.retopo.run" in hit.message
    validate_finding(hit.to_dict())


# ── negative cases (the discriminators) ─────────────────────────────
def test_resolving_reference_is_silent(tmp_path):
    _pkg(tmp_path)
    _write(tmp_path, "driver.py", "from app.config import SETTINGS\nimport app.config\n")
    assert _run(tmp_path) == []


def test_missing_third_party_import_not_flagged(tmp_path):
    """``scipy`` resolves to no package in the tree, so its top-level is not
    first-party — that is the requirements/deployment analyzer's job, not this one."""
    _pkg(tmp_path)
    _write(tmp_path, "driver.py", "import scipy\nfrom numpy.linalg import svd\n")
    assert _run(tmp_path) == []


def test_relative_import_not_flagged(tmp_path):
    _pkg(tmp_path)
    _write(tmp_path, "app/thing.py", "from . import gone\nfrom .gone import x\n")
    assert _run(tmp_path) == []


def test_symbol_level_deletion_is_deferred_not_flagged(tmp_path):
    """v1 resolves at module granularity only: if the *module* survives but a
    *name* inside it was deleted, this analyzer stays silent (documented boundary,
    mirroring dead_code's single-granularity v1)."""
    _pkg(tmp_path)
    _write(tmp_path, "driver.py", "from app.config import DELETED_NAME\n")
    assert _run(tmp_path) == []


def test_src_layout_resolution(tmp_path):
    _write(tmp_path, "src/pkg/__init__.py", "")
    _write(tmp_path, "src/pkg/mod.py", "x = 1\n")
    _write(tmp_path, "driver.py", "import pkg.mod\nimport pkg.gone\n")
    f = _run(tmp_path)
    assert _missing(f) == ["pkg.gone"]  # pkg.mod resolves, pkg.gone does not


def test_no_first_party_python_is_silent(tmp_path):
    _write(tmp_path, "run.sh", "python -m app.retopo.run\n")  # no app/ package exists
    assert _run(tmp_path) == []


def test_deleted_toplevel_is_indistinguishable_from_third_party(tmp_path):
    """Documented limitation: if the ENTIRE top-level package is deleted, its
    references are indistinguishable from third-party imports and stay silent — the
    detector only fires when a surviving top-level proves first-party ownership."""
    _write(tmp_path, "driver.py", "import app.retopo.run\n")  # no app/ anywhere
    assert _run(tmp_path) == []


# ── robustness / fail-loud ──────────────────────────────────────────
def test_unparseable_referencing_file_does_not_crash(tmp_path):
    _pkg(tmp_path)
    _write(tmp_path, "broken.py", "def (:\n")  # syntax error
    _write(tmp_path, "driver.py", "import app.retopo.run\n")
    f = _run(tmp_path)
    assert _missing(f) == ["app.retopo.run"]  # broken file skipped, real hit survives


def test_internal_failure_becomes_finding_never_raises(tmp_path, monkeypatch):
    _pkg(tmp_path)
    _write(tmp_path, "driver.py", "import app.retopo.run\n")

    def boom(self, root):
        raise RuntimeError("synthetic index failure")

    monkeypatch.setattr(DanglingReferenceAnalyzer, "_index_modules", boom)
    f = DanglingReferenceAnalyzer().run(tmp_path, [])  # must not raise
    assert len(f) == 1
    assert f[0].metadata["rule_id"] == "DANGLING_REF_ERROR"
    assert "synthetic index failure" in f[0].message


def test_all_findings_are_contract_valid(tmp_path):
    _pkg(tmp_path)
    _write(tmp_path, "driver.py", "import app.retopo.run\n")
    _write(tmp_path, "run.sh", "python -m app.retopo.gone\n")
    for finding in _run(tmp_path):
        validate_finding(finding.to_dict())
