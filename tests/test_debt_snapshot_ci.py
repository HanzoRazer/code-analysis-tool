from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(
    *args: str,
    extra_env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(**os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        str(REPO_ROOT / "src") + ((os.pathsep + existing) if existing else "")
    )
    env["CI"] = "true"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "code_audit", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd is not None else None,
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


def test_debt_snapshot_out_rejects_non_temp_absolute_path_in_ci() -> None:
    root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"
    out = REPO_ROOT / "_forbidden_snapshot_out.json"
    out.unlink(missing_ok=True)

    try:
        result = _run(
            "debt",
            "snapshot",
            str(root),
            "--out",
            str(out),
            "--ci",
        )

        assert result.returncode == 2, result.stdout + "\n" + result.stderr
        temp_root = Path(tempfile.gettempdir()).resolve()
        assert (
            result.stderr.strip()
            == f"error: --out absolute paths must stay within {temp_root} in CI"
        )
        assert not out.exists()
    finally:
        out.unlink(missing_ok=True)


def test_debt_snapshot_relative_out_rejects_outside_caller_artifacts(
    tmp_path: Path,
) -> None:
    root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"
    result = _run(
        "debt",
        "snapshot",
        str(root),
        "--out",
        "not_artifacts/snap.json",
        "--ci",
        cwd=tmp_path,
    )
    assert result.returncode == 2, result.stdout + "\n" + result.stderr
    assert (
        "relative paths must stay within the caller's artifacts/ directory in CI"
        in result.stderr
    )
    assert not (tmp_path / "not_artifacts" / "snap.json").exists()


def test_debt_snapshot_relative_out_rejects_path_traversal(tmp_path: Path) -> None:
    root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"
    result = _run(
        "debt",
        "snapshot",
        str(root),
        "--out",
        "artifacts/../escape.json",
        "--ci",
        cwd=tmp_path,
    )
    assert result.returncode == 2, result.stdout + "\n" + result.stderr
    assert "must not contain '..' path traversal" in result.stderr
    assert not (tmp_path / "escape.json").exists()


def test_debt_snapshot_relative_out_uses_caller_cwd_not_scan_root(
    tmp_path: Path,
) -> None:
    root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"
    caller_out = tmp_path / "artifacts" / "snap.json"
    scan_root_out = root / "artifacts" / "snap.json"
    if scan_root_out.exists():
        scan_root_out.unlink()

    result = _run(
        "debt",
        "snapshot",
        str(root),
        "--out",
        "artifacts/snap.json",
        "--ci",
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    assert caller_out.exists()
    assert not scan_root_out.exists()

    data = json.loads(caller_out.read_text(encoding="utf-8"))
    assert data["schema_version"] == "debt_snapshot_v1"


def test_scan_out_rejects_absolute_path_in_ci(tmp_path: Path) -> None:
    root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"
    abs_out = tmp_path / "scan_out.json"
    result = _run(
        "scan",
        "--root",
        str(root),
        "--out",
        str(abs_out),
        "--ci",
        cwd=tmp_path,
    )
    assert result.returncode == 2, result.stdout + "\n" + result.stderr
    assert "must be a relative path" in result.stderr
    assert not abs_out.exists()


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
