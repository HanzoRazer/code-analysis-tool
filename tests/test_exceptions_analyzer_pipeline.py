import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_scan(fixture_root: Path, out: Path) -> subprocess.CompletedProcess:
    """Helper: invoke ``python -m code_audit scan`` via subprocess."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "code_audit",
            "scan",
            "--root",
            str(fixture_root),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT / "src")},
    )


def test_scan_finds_exceptions_and_emits_signal(tmp_path: Path):
    """
    End-to-end:
      - scan fixture repo containing broad exception handling
      - RunResult is schema valid
      - findings_raw contains exceptions
      - signals_snapshot includes exceptions signal
      - vibe tier is red (because severity high)
      - confidence score is penalized (< 100)
    """
    fixture_root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_exceptions"
    out = tmp_path / "run_result.json"

    r = _run_scan(fixture_root, out)
    assert r.returncode == 2, (
        f"Expected exit code 2 (red tier), got {r.returncode}\n"
        f"stdout: {r.stdout}\nstderr: {r.stderr}"
    )

    instance = json.loads(out.read_text(encoding="utf-8"))
    schema = json.loads(
        (REPO_ROOT / "schemas" / "run_result.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(instance=instance, schema=schema)

    assert instance["summary"]["counts"]["findings_total"] >= 1
    assert instance["summary"]["counts"]["by_type"].get("exceptions", 0) >= 1

    finding_types = {f["type"] for f in instance["findings_raw"]}
    assert "exceptions" in finding_types

    snap_types = {s["type"] for s in instance["signals_snapshot"]}
    assert "exceptions" in snap_types

    assert instance["summary"]["vibe_tier"] in {"yellow", "red"}
    assert instance["summary"]["vibe_tier"] == "red"
    assert instance["summary"]["confidence_score"] < 100


def test_scan_marks_swallowed_errors(tmp_path: Path):
    """
    The fixture has:
      - do_work: ``except Exception: return 0``  → swallowed (no log, no raise)
      - do_other_work: ``except: return None``   → swallowed (bare, no log, no raise)
      - do_logged: ``except Exception: logger.error(…)`` → logged-broad (NOT swallowed)

    Assert the analyzer distinguishes these correctly.
    """
    fixture_root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_exceptions"
    out = tmp_path / "run_result.json"

    r = _run_scan(fixture_root, out)
    # We still expect red because the swallowed findings are high/critical
    assert r.returncode == 2, (
        f"Expected exit code 2 (red tier), got {r.returncode}\n"
        f"stdout: {r.stdout}\nstderr: {r.stderr}"
    )

    instance = json.loads(out.read_text(encoding="utf-8"))
    exc = [f for f in instance["findings_raw"] if f["type"] == "exceptions"]
    assert len(exc) >= 3, f"Expected at least 3 exception findings, got {len(exc)}"

    # At least one swallowed
    swallowed = [f for f in exc if (f.get("metadata") or {}).get("rule_id") == "EXC_SWALLOW_001"]
    assert swallowed, "Expected at least one swallowed-error finding (EXC_SWALLOW_001)"

    # Logged handler should be distinguished:
    # - never swallowed
    # - uses the logged rule id
    logged = [f for f in exc if "do_logged" in (f.get("snippet") or "")]
    for f in logged:
        assert (f.get("metadata") or {}).get("rule_id") != "EXC_SWALLOW_001"

    # Require at least one logged-broad finding so the distinction is enforced by tests.
    logged_rule = [f for f in exc if (f.get("metadata") or {}).get("rule_id") == "EXC_BROAD_LOGGED_001"]
    assert logged_rule, "Expected at least one logged-broad finding (EXC_BROAD_LOGGED_001)"


def test_signal_evidence_orders_swallowed_first_and_emits_summary(tmp_path: Path):
    """
    Signal builder should:
      - order evidence finding_ids with swallowed-first preference
      - emit evidence.summary { swallowed_count, logged_count }
    """
    fixture_root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_exceptions"
    out = tmp_path / "run_result.json"

    r = _run_scan(fixture_root, out)
    # Red tier expected (swallowed findings are high/critical)
    assert r.returncode == 2, (
        f"Expected exit code 2 (red tier), got {r.returncode}\n"
        f"stdout: {r.stdout}\nstderr: {r.stderr}"
    )

    instance = json.loads(out.read_text(encoding="utf-8"))
    sigs = [s for s in instance["signals_snapshot"] if s.get("type") == "exceptions"]
    assert sigs, "Expected an exceptions signal"
    sig = sigs[0]

    evidence = sig["evidence"]
    assert "summary" in evidence
    assert set(evidence["summary"].keys()) == {"swallowed_count", "logged_count"}
    assert evidence["summary"]["swallowed_count"] >= 1
    assert evidence["summary"]["logged_count"] >= 1

    # Verify ordering: first finding_id should correspond to a swallowed rule if any exist.
    first_id = evidence["finding_ids"][0]
    by_id = {f["finding_id"]: f for f in instance["findings_raw"]}
    first = by_id[first_id]
    assert (first.get("metadata") or {}).get("rule_id") == "EXC_SWALLOW_001"
