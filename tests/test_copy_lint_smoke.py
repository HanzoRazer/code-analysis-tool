import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

def test_repo_i18n_en_passes_copy_lint_vibe_saas():
    """Ensure the canonical i18n/en copy passes the schema-aware linter."""
    script = REPO_ROOT / "scripts" / "copy_lint_vibe_saas.py"
    i18n_en = REPO_ROOT / "i18n" / "en"
    result = subprocess.run(
        [sys.executable, str(script), "lint", str(i18n_en), "--format", "text"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
