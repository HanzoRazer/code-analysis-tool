from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run_cli_json(*args: str) -> dict:
    cmd = [sys.executable, "-m", "code_audit", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, (
        f"cmd failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise AssertionError(
            f"stdout was not JSON\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        ) from e


def _load_i18n_en(repo_root: Path) -> dict:
    p = repo_root / "i18n" / "en" / "signals.json"
    assert p.exists(), f"missing i18n file: {p}"
    return json.loads(p.read_text(encoding="utf-8"))


def _resolve_dot_path(obj: object, key: str) -> object:
    """
    Resolve dot-separated path into nested dicts.
    Example: 'signals.dead_code.action.text'
    """
    cur: object = obj
    for part in key.split("."):
        if not isinstance(cur, dict):
            raise KeyError(f"non-dict while resolving {key} at {part}")
        if part not in cur:
            raise KeyError(f"missing {part} while resolving {key}")
        cur = cur[part]
    return cur


def _iter_required_keys(signal: dict) -> list[tuple[str, str]]:
    """
    Required-by-contract keys we emit in v1.
    Keep this list tight: the test should fail only on real drift.
    """
    out: list[tuple[str, str]] = []

    for field in ("title_key", "summary_key", "why_key"):
        v = signal.get(field)
        if not isinstance(v, str) or not v:
            raise AssertionError(f"missing/invalid {field}: {v!r} in signal={signal.get('type')}")
        out.append((field, v))

    action = signal.get("action")
    if not isinstance(action, dict):
        raise AssertionError(f"missing/invalid action dict in signal={signal.get('type')}")
    v = action.get("text_key")
    if not isinstance(v, str) or not v:
        raise AssertionError(f"missing/invalid action.text_key: {v!r} in signal={signal.get('type')}")
    out.append(("action.text_key", v))

    return out


def test_cli_scan_emitted_i18n_keys_resolve_to_strings() -> None:
    repo_root = Path(__file__).resolve().parents[1]

    # Choose any small fixture that already exists and triggers at least one signal.
    fixture_repo = repo_root / "tests" / "fixtures" / "repos" / "mixed_severity"
    assert fixture_repo.exists(), f"fixture repo missing: {fixture_repo}"

    # Run real CLI deterministically.
    result = _run_cli_json(str(fixture_repo), "--json", "--ci")

    signals = result.get("signals_snapshot", [])
    assert isinstance(signals, list), f"signals_snapshot not a list: {type(signals)}"
    assert signals, "fixture produced no signals; test is not exercising copy-key paths"

    i18n = _load_i18n_en(repo_root)

    bad_prefix: list[str] = []
    missing: list[str] = []
    wrong_type: list[str] = []

    for s in signals:
        if not isinstance(s, dict):
            continue

        # Required fields present + strings
        pairs = _iter_required_keys(s)

        for field, key in pairs:
            # Old namespace must never appear again.
            if key.startswith("signal."):
                bad_prefix.append(f"{s.get('type','?')}:{field}={key}")
                continue

            # Must resolve to a string in i18n/en/signals.json
            try:
                val = _resolve_dot_path(i18n, key)
            except KeyError as e:
                missing.append(f"{s.get('type','?')}:{field}={key} ({e})")
                continue

            if not isinstance(val, str) or not val:
                wrong_type.append(f"{s.get('type','?')}:{field}={key} -> {type(val).__name__}:{val!r}")

    assert not bad_prefix, "Legacy i18n prefix 'signal.' found:\n" + "\n".join(bad_prefix)
    assert not missing, "Emitted i18n keys missing from i18n/en/signals.json:\n" + "\n".join(missing)
    assert not wrong_type, "Emitted i18n keys did not resolve to non-empty strings:\n" + "\n".join(wrong_type)
