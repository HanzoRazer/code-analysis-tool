import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "copy_lint_vibe_saas.py"
FIXT = REPO_ROOT / "tests" / "fixtures" / "i18n_invalid"

def run_lint(folder: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "lint", str(folder), "--format", "text"],
        capture_output=True,
        text=True,
    )

def test_forbidden_word_fails():
    # Contains forbidden word 'must'
    folder = FIXT / "forbidden_word"
    r = run_lint(folder)
    assert r.returncode == 1
    assert "forbidden" in (r.stdout + r.stderr).lower()

def test_missing_reassurance_fails():
    # risk_level red but summary lacks reassurance phrase
    folder = FIXT / "missing_reassurance"
    r = run_lint(folder)
    assert r.returncode == 1
    assert "reassurance" in (r.stdout + r.stderr).lower()

def test_bad_button_label_fails():
    # Button label not in allowlist
    folder = FIXT / "bad_button_label"
    r = run_lint(folder)
    assert r.returncode == 1
    assert "button" in (r.stdout + r.stderr).lower()

def test_bad_action_urgency_fails():
    # action.urgency not in allowed set
    folder = FIXT / "bad_action_urgency"
    r = run_lint(folder)
    assert r.returncode == 1
    assert "urgency" in (r.stdout + r.stderr).lower()
