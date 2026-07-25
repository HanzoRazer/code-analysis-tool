"""Exit code contract integration tests — subprocess-based.

Verifies the v1 Supported exit semantics:

    validate:       0 = OK, 1 = schema violation, 2 = runtime / schema missing
    debt compare:   0 = no new debt, 1 = new debt introduced
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    env["PYTHONPATH"] = str(REPO_ROOT / "src") + (
        os.pathsep + env.get("PYTHONPATH", "") if env.get("PYTHONPATH") else ""
    )
    # --ci requires CI=true; path guards require relative --out under scan-root/artifacts/
    env["CI"] = "true"
    return subprocess.run(
        [sys.executable, "-m", "code_audit", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        env=env,
    )


# ── validate exit codes ─────────────────────────────────────────────


def test_validate_ok_returns_0(tmp_path: Path) -> None:
    inst = {
        "schema_version": "debt_snapshot_v1",
        "created_at": "2000-01-01T00:00:00+00:00",
        "debt_count": 0,
        "items": [],
    }
    inst_path = tmp_path / "ok.json"
    inst_path.write_text(json.dumps(inst), encoding="utf-8")

    r = _run(["validate", str(inst_path), "debt_snapshot.schema.json"])
    assert r.returncode == 0, (r.stdout, r.stderr)


def test_validate_schema_violation_returns_1(tmp_path: Path) -> None:
    # Invalid: missing required field "created_at"
    inst = {
        "schema_version": "debt_snapshot_v1",
        "debt_count": 0,
        "items": [],
    }
    inst_path = tmp_path / "bad.json"
    inst_path.write_text(json.dumps(inst), encoding="utf-8")

    r = _run(["validate", str(inst_path), "debt_snapshot.schema.json"])
    assert r.returncode == 1, (r.stdout, r.stderr)


def test_validate_missing_schema_returns_2(tmp_path: Path) -> None:
    inst = {
        "schema_version": "debt_snapshot_v1",
        "created_at": "2000-01-01T00:00:00+00:00",
        "debt_count": 0,
        "items": [],
    }
    inst_path = tmp_path / "ok.json"
    inst_path.write_text(json.dumps(inst), encoding="utf-8")

    r = _run(["validate", str(inst_path), "does_not_exist.schema.json"])
    assert r.returncode == 2, (r.stdout, r.stderr)


# ── debt compare exit codes ─────────────────────────────────────────


def test_debt_compare_same_snapshot_returns_0(tmp_path: Path) -> None:
    work = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt", work)
    (work / "artifacts").mkdir()

    r1 = _run(
        ["debt", "snapshot", str(work), "--ci", "--out", "artifacts/baseline.json"],
        cwd=work,
    )
    assert r1.returncode == 0, r1.stderr

    r2 = _run(
        ["debt", "snapshot", str(work), "--ci", "--out", "artifacts/current.json"],
        cwd=work,
    )
    assert r2.returncode == 0, r2.stderr

    baseline = work / "artifacts" / "baseline.json"
    current = work / "artifacts" / "current.json"
    r3 = _run(
        [
            "debt", "compare", str(work),
            "--baseline", str(baseline),
            "--current", str(current),
            "--ci",
        ],
        cwd=work,
    )
    assert r3.returncode == 0, (r3.stdout, r3.stderr)


def test_debt_compare_new_debt_returns_1(tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    debt = tmp_path / "debt"
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project", clean)
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt", debt)
    (clean / "artifacts").mkdir()
    (debt / "artifacts").mkdir()

    r1 = _run(
        ["debt", "snapshot", str(clean), "--ci", "--out", "artifacts/baseline.json"],
        cwd=clean,
    )
    assert r1.returncode == 0, r1.stderr

    r2 = _run(
        ["debt", "snapshot", str(debt), "--ci", "--out", "artifacts/current.json"],
        cwd=debt,
    )
    assert r2.returncode == 0, r2.stderr

    baseline = clean / "artifacts" / "baseline.json"
    current = debt / "artifacts" / "current.json"
    r3 = _run(
        [
            "debt", "compare", str(debt),
            "--baseline", str(baseline),
            "--current", str(current),
            "--ci",
        ],
        cwd=debt,
    )
    assert r3.returncode == 1, (r3.stdout, r3.stderr)
