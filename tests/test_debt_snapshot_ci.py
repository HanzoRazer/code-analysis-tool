from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(**os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src") + (":" + env.get("PYTHONPATH","") if env.get("PYTHONPATH") else "")
    env["CI"] = "true"
    return subprocess.run(
        [sys.executable, "-m", "code_audit", *args],
        capture_output=True,
        text=True,
        env=env,
    )


def test_debt_snapshot_out_ci_is_deterministic(tmp_path: Path) -> None:
    root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"
    out1 = tmp_path / "snap1.json"
    out2 = tmp_path / "snap2.json"

    r1 = _run("debt", "snapshot", str(root), "--out", str(out1), "--ci")
    assert r1.returncode == 0, r1.stdout + "\n" + r1.stderr

    r2 = _run("debt", "snapshot", str(root), "--out", str(out2), "--ci")
    assert r2.returncode == 0, r2.stdout + "\n" + r2.stderr

    t1 = out1.read_text(encoding="utf-8")
    t2 = out2.read_text(encoding="utf-8")
    assert t1 == t2, "CI snapshots should be byte-identical"

    data = json.loads(t1)
    assert data["schema_version"] == "debt_snapshot_v1"
    assert data["created_at"] == "2000-01-01T00:00:00+00:00"
    assert data["debt_count"] == len(data["items"])
    assert data["debt_count"] >= 1


def test_debt_compare_file_vs_file(tmp_path: Path) -> None:
    clean = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"
    debt = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"

    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    rb = _run("debt", "snapshot", str(clean), "--out", str(baseline), "--ci")
    assert rb.returncode == 0, rb.stdout + "\n" + rb.stderr

    rc = _run("debt", "snapshot", str(debt), "--out", str(current), "--ci")
    assert rc.returncode == 0, rc.stdout + "\n" + rc.stderr

    # clean baseline vs debt current should be a ratchet violation (new debt introduced)
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
    )
    assert rcmp.returncode == 1, rcmp.stdout + "\n" + rcmp.stderr

    payload = json.loads(rcmp.stdout)
    assert isinstance(payload.get("new"), list)
    assert len(payload["new"]) >= 1
