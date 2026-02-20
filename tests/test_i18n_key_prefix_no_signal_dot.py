from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run_cli_json(*args: str) -> dict:
    """
    Run code-audit via subprocess and parse stdout as JSON.
    Forces deterministic mode so CI/local match.
    """
    env = os.environ.copy()
    # If your CI guard keys off an env var, keep it consistent.
    env.setdefault("CODE_AUDIT_DETERMINISTIC", "1")
    env["CI"] = "true"

    cmd = [sys.executable, "-m", "code_audit", *args]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode in (0, 1, 2), f"cmd failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise AssertionError(f"stdout was not JSON\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}") from e


def _iter_key_fields(signal: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for k in ("title_key", "summary_key", "why_key"):
        v = signal.get(k)
        if isinstance(v, str):
            out.append((k, v))

    action = signal.get("action")
    if isinstance(action, dict):
        v = action.get("text_key")
        if isinstance(v, str):
            out.append(("action.text_key", v))

    # Note: we intentionally do NOT require footer keys here (tightest test).
    return out


def test_cli_scan_never_emits_signal_dot_prefix() -> None:
    """
    Ultra-tight regression guard:
      - run real CLI
      - parse JSON
      - assert no i18n key starts with the old prefix "signal."
    """
    repo_root = Path(__file__).resolve().parents[1]

    # Pick any small existing fixture repo that produces findings.
    fixture_repo = repo_root / "tests" / "fixtures" / "repos" / "mixed_severity"
    assert fixture_repo.exists(), f"fixture repo missing: {fixture_repo}"

    result = _run_cli_json(str(fixture_repo), "--json", "--ci")

    signals = result.get("signals_snapshot", [])
    assert isinstance(signals, list)

    bad: list[str] = []
    for s in signals:
        if not isinstance(s, dict):
            continue
        for field, key in _iter_key_fields(s):
            if key.startswith("signal."):
                bad.append(f"{s.get('type','?')}:{field}={key}")

    assert not bad, "Found legacy i18n prefix 'signal.' in emitted keys:\n" + "\n".join(bad)
