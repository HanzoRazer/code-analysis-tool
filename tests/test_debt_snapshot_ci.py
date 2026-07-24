from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(**os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src") + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    # --ci requires CI=true; path guards then require relative --out under scan-root/artifacts/
    env["CI"] = "true"
    return subprocess.run(
        [sys.executable, "-m", "code_audit", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        env=env,
    )


def test_debt_snapshot_out_ci_is_deterministic(tmp_path: Path) -> None:
    work = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt", work)
    (work / "artifacts").mkdir()

    r1 = _run(
        "debt", "snapshot", str(work), "--out", "artifacts/snap1.json", "--ci", cwd=work
    )
    assert r1.returncode == 0, r1.stdout + "\n" + r1.stderr

    r2 = _run(
        "debt", "snapshot", str(work), "--out", "artifacts/snap2.json", "--ci", cwd=work
    )
    assert r2.returncode == 0, r2.stdout + "\n" + r2.stderr

    t1 = (work / "artifacts" / "snap1.json").read_text(encoding="utf-8")
    t2 = (work / "artifacts" / "snap2.json").read_text(encoding="utf-8")
    assert t1 == t2, "CI snapshots should be byte-identical"

    data = json.loads(t1)
    assert data["schema_version"] == "debt_snapshot_v1"
    assert data["created_at"] == "2000-01-01T00:00:00+00:00"
    assert data["debt_count"] == len(data["items"])
    assert data["debt_count"] >= 1


def test_debt_compare_file_vs_file(tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    debt = tmp_path / "debt"
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project", clean)
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt", debt)
    (clean / "artifacts").mkdir()
    (debt / "artifacts").mkdir()

    rb = _run(
        "debt", "snapshot", str(clean), "--out", "artifacts/baseline.json", "--ci",
        cwd=clean,
    )
    assert rb.returncode == 0, rb.stdout + "\n" + rb.stderr

    rc = _run(
        "debt", "snapshot", str(debt), "--out", "artifacts/current.json", "--ci",
        cwd=debt,
    )
    assert rc.returncode == 0, rc.stdout + "\n" + rc.stderr

    baseline = clean / "artifacts" / "baseline.json"
    current = debt / "artifacts" / "current.json"

    rcmp = _run(
        "debt",
        "compare",
        str(debt),
        "--baseline",
        str(baseline),
        "--current",
        str(current),
        "--ci",
        "--json",
        cwd=debt,
    )
    assert rcmp.returncode == 1, rcmp.stdout + "\n" + rcmp.stderr

    payload = json.loads(rcmp.stdout)
    assert isinstance(payload.get("new"), list)
    assert len(payload["new"]) >= 1
