"""Schema-version enforcement: debt compare rejects unknown snapshot formats.

The ratchet must never silently compare a v0 baseline against v1 snapshots.
Exit code 2 = runtime / format error (not a content violation).
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


def test_debt_compare_rejects_wrong_schema_version_in_baseline(tmp_path: Path) -> None:
    """Baseline with schema_version != 'debt_snapshot_v1' must exit 2."""
    work = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt", work)
    (work / "artifacts").mkdir()

    r1 = _run(
        ["debt", "snapshot", str(work), "--ci", "--out", "artifacts/current.json"],
        cwd=work,
    )
    assert r1.returncode == 0, r1.stderr
    current = work / "artifacts" / "current.json"

    bad = {
        "schema_version": "debt_snapshot_v0",
        "created_at": "2000-01-01T00:00:00+00:00",
        "debt_count": 0,
        "items": [],
    }
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(bad), encoding="utf-8")

    r2 = _run(
        [
            "debt", "compare", str(work),
            "--baseline", str(baseline),
            "--current", str(current),
            "--ci",
        ],
        cwd=work,
    )
    assert r2.returncode == 2, (r2.stdout, r2.stderr)
    assert "schema_version" in r2.stderr


def test_debt_compare_rejects_missing_schema_version_in_baseline(tmp_path: Path) -> None:
    """Baseline without schema_version key must exit 2."""
    work = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt", work)
    (work / "artifacts").mkdir()

    r1 = _run(
        ["debt", "snapshot", str(work), "--ci", "--out", "artifacts/current.json"],
        cwd=work,
    )
    assert r1.returncode == 0, r1.stderr
    current = work / "artifacts" / "current.json"

    bad = {
        "created_at": "2000-01-01T00:00:00+00:00",
        "debt_count": 0,
        "items": [],
    }
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(bad), encoding="utf-8")

    r2 = _run(
        [
            "debt", "compare", str(work),
            "--baseline", str(baseline),
            "--current", str(current),
            "--ci",
        ],
        cwd=work,
    )
    assert r2.returncode == 2, (r2.stdout, r2.stderr)
    assert "schema_version" in r2.stderr


def test_debt_compare_rejects_wrong_schema_version_in_current(tmp_path: Path) -> None:
    """Current file with wrong schema_version must exit 2."""
    work = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt", work)
    (work / "artifacts").mkdir()

    r1 = _run(
        ["debt", "snapshot", str(work), "--ci", "--out", "artifacts/baseline.json"],
        cwd=work,
    )
    assert r1.returncode == 0, r1.stderr
    baseline = work / "artifacts" / "baseline.json"

    bad = {
        "schema_version": "debt_snapshot_v0",
        "created_at": "2000-01-01T00:00:00+00:00",
        "debt_count": 0,
        "items": [],
    }
    current = tmp_path / "current.json"
    current.write_text(json.dumps(bad), encoding="utf-8")

    r2 = _run(
        [
            "debt", "compare", str(work),
            "--baseline", str(baseline),
            "--current", str(current),
            "--ci",
        ],
        cwd=work,
    )
    assert r2.returncode == 2, (r2.stdout, r2.stderr)
    assert "schema_version" in r2.stderr
