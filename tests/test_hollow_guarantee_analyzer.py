"""Unit tests for the hollow-guarantee / un-failable CI guard detector.

Flags CI verification steps that structurally cannot fail (`continue-on-error: true`
or `|| true` on a check). Family III (failure mimics success). Distinct from
maxfail_masking (Family IV, fail-fast truncation).

Includes the born-from-the-bug acceptance test: the exact luthiers-toolbox
`client_lint_build.yml` pattern that motivated this detector must fire on BOTH the
type-check and the eslint lanes (proving it is not hand-tuned to the one lane we
already knew about).
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.hollow_guarantee import HollowGuaranteeAnalyzer
from code_audit.model import AnalyzerType, Severity


def _run(root: Path):
    return HollowGuaranteeAnalyzer().run(root, [])


def _wf(root: Path, name: str, body: str) -> None:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(body, encoding="utf-8")


# ── positive cases ──────────────────────────────────────────────────────
def test_type_check_continue_on_error_flagged(tmp_path):
    _wf(tmp_path, "ci.yml",
        "jobs:\n  build:\n    steps:\n"
        "      - name: Type check (vue-tsc)\n"
        "        run: npm run type-check\n"
        "        continue-on-error: true\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.HOLLOW_GUARANTEE
    assert f[0].severity is Severity.LOW
    assert f[0].metadata["guard_kind"] == "continue-on-error: true"
    assert f[0].finding_id  # non-empty (schema minLength)
    assert f[0].location.path == ".github/workflows/ci.yml"
    assert f[0].location.line_start == 6  # the continue-on-error line


def test_pytest_continue_on_error_flagged(tmp_path):
    _wf(tmp_path, "test.yml",
        "jobs:\n  t:\n    steps:\n"
        "      - run: pytest -q\n"
        "        continue-on-error: true\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert "pytest" in f[0].metadata["verification_tool"].lower()


def test_swallowed_exit_flagged(tmp_path):
    _wf(tmp_path, "lint.yml",
        "jobs:\n  l:\n    steps:\n"
        "      - run: eslint . || true\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert "swallowed" in f[0].metadata["guard_kind"]
    assert f[0].confidence == 0.6


# ── negative cases (the discriminator: only VERIFICATION steps) ──────────
def test_continue_on_error_on_nonverification_step_not_flagged(tmp_path):
    _wf(tmp_path, "deploy.yml",
        "jobs:\n  d:\n    steps:\n"
        "      - name: Upload coverage\n"
        "        run: bash <(curl -s https://codecov.io/bash)\n"
        "        continue-on-error: true\n"
        "      - name: Notify slack\n"
        "        uses: slackapi/slack-github-action@v1\n"
        "        continue-on-error: true\n")
    assert _run(tmp_path) == []


def test_verification_step_that_can_fail_not_flagged(tmp_path):
    _wf(tmp_path, "ok.yml",
        "jobs:\n  b:\n    steps:\n"
        "      - name: Type check\n"
        "        run: npm run type-check\n")
    assert _run(tmp_path) == []


def test_no_workflows_dir_no_findings(tmp_path):
    assert _run(tmp_path) == []


# ── born-from-the-bug acceptance test (luthiers client_lint_build.yml) ───
_LUTHIERS_CLIENT_LINT_BUILD = (
    "name: Client Lint & Build\n"
    "on: [push, pull_request]\n"
    "jobs:\n"
    "  lint-build:\n"
    "    runs-on: ubuntu-latest\n"
    "    defaults:\n"
    "      run:\n"
    "        working-directory: packages/client\n"
    "    steps:\n"
    "      - name: Install dependencies\n"
    "        run: npm ci\n"
    "      - name: Type check (vue-tsc)\n"
    "        run: npm run type-check\n"
    "        continue-on-error: true  # TODO: Fix 400+ pre-existing type errors then remove this\n"
    "      - name: Lint (ESLint)\n"
    "        run: npm run lint\n"
    "        continue-on-error: true  # Allow warnings during initial adoption\n"
    "      - name: Run tests (Vitest)\n"
    "        run: npm test\n"
    "      - name: Build production bundle\n"
    "        run: npm run build\n"
)


def test_acceptance_luthiers_fires_on_both_lanes(tmp_path):
    """The instance that motivated the detector: BOTH the type-check and the eslint
    lanes are `continue-on-error: true` verification steps and must be flagged; the
    install/test/build steps must NOT be (they either lack the guard or aren't
    verification). Firing on both — not just the type-check we already knew about —
    proves the detector generalizes rather than being hand-tuned."""
    _wf(tmp_path, "client_lint_build.yml", _LUTHIERS_CLIENT_LINT_BUILD)
    f = _run(tmp_path)
    tools = sorted(x.metadata["verification_tool"].lower() for x in f)
    assert len(f) == 2, f"expected 2 hollow guarantees, got {len(f)}: {tools}"
    assert all(x.type is AnalyzerType.HOLLOW_GUARANTEE for x in f)
    assert all(x.metadata["guard_kind"] == "continue-on-error: true" for x in f)
    # Two DISTINCT verification lanes flagged (the type-check tool and the lint
    # tool), on two distinct lines — not just the type-check lane we already knew.
    assert tools == ["eslint", "vue-tsc"]
    assert len({x.location.line_start for x in f}) == 2


# ── parser / heuristic regression coverage ──────────────────────────────


def test_bare_dash_step_with_nested_run_and_continue_on_error_flagged(tmp_path):
    _wf(
        tmp_path,
        "ci.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      -\n"
        "        name: Type check\n"
        "        run: npm run type-check\n"
        "        continue-on-error: true\n",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["guard_kind"] == "continue-on-error: true"
    assert "type-check" in f[0].metadata["verification_tool"].lower() or "vue-tsc" in (
        f[0].metadata["verification_tool"].lower()
    ) or "npm run type-check" in f[0].metadata["verification_tool"].lower()


def test_multiline_run_block_with_swallowed_exit_flagged(tmp_path):
    _wf(
        tmp_path,
        "lint.yml",
        "jobs:\n"
        "  lint:\n"
        "    steps:\n"
        "      - name: Lint\n"
        "        run: |\n"
        "          set -e\n"
        "          npm run lint || true\n",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert "swallowed" in f[0].metadata["guard_kind"]
    assert f[0].location.line_start == 7  # the shell line with || true


def test_multiline_run_block_with_continue_on_error_flagged(tmp_path):
    _wf(
        tmp_path,
        "typecheck.yml",
        "jobs:\n"
        "  check:\n"
        "    steps:\n"
        "      - name: Type check\n"
        "        run: |\n"
        "          npm run type-check\n"
        "        continue-on-error: true\n",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["guard_kind"] == "continue-on-error: true"


def test_non_step_yaml_list_with_verification_text_not_flagged(tmp_path):
    _wf(
        tmp_path,
        "matrix.yml",
        "jobs:\n"
        "  build:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        cmd:\n"
        "          - pytest || true\n"
        "          - eslint . || true\n"
        "    steps:\n"
        "      - run: echo ok\n",
    )
    assert _run(tmp_path) == []


def test_nested_list_inside_step_does_not_break_detection(tmp_path):
    _wf(
        tmp_path,
        "ci.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - name: Type check\n"
        "        run: npm run type-check\n"
        "        env:\n"
        "          EXTRA_ARGS:\n"
        "            - --strict\n"
        "            - --pretty\n"
        "        continue-on-error: true\n",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["guard_kind"] == "continue-on-error: true"


def test_continue_on_error_yes_and_on_are_flagged(tmp_path):
    _wf(
        tmp_path,
        "ci.yml",
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "      - run: pytest -q\n"
        "        continue-on-error: yes\n"
        "  b:\n"
        "    steps:\n"
        "      - run: eslint .\n"
        "        continue-on-error: on\n",
    )
    f = _run(tmp_path)
    assert len(f) == 2
    assert all(x.metadata["guard_kind"] == "continue-on-error: true" for x in f)


def test_continue_on_error_false_not_flagged(tmp_path):
    _wf(
        tmp_path,
        "ci.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: pytest -q\n"
        "        continue-on-error: false\n",
    )
    assert _run(tmp_path) == []


def test_semicolon_true_swallow_flagged(tmp_path):
    _wf(
        tmp_path,
        "lint.yml",
        "jobs:\n"
        "  lint:\n"
        "    steps:\n"
        "      - run: eslint . ; true\n",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert "; true" in f[0].metadata["guard_kind"]


def test_exit_zero_swallow_flagged(tmp_path):
    _wf(
        tmp_path,
        "test.yml",
        "jobs:\n"
        "  t:\n"
        "    steps:\n"
        "      - run: pytest -q || exit 0\n",
    )
    f = _run(tmp_path)
    assert len(f) == 1
    assert "exit 0" in f[0].metadata["guard_kind"]


def test_benign_true_on_separate_line_not_flagged(tmp_path):
    """`; true` / bare true away from the verification command must not fire."""
    _wf(
        tmp_path,
        "lint.yml",
        "jobs:\n"
        "  lint:\n"
        "    steps:\n"
        "      - name: Lint\n"
        "        run: |\n"
        "          npm run lint\n"
        "          echo done\n"
        "          true\n",
    )
    assert _run(tmp_path) == []


def test_verification_looking_name_without_run_tool_not_enough_for_coe(tmp_path):
    """Name-only tool mention still counts as verification field content (documented);
    a step with continue-on-error and a non-tool run must not fire."""
    _wf(
        tmp_path,
        "notify.yml",
        "jobs:\n"
        "  n:\n"
        "    steps:\n"
        "      - name: Notify about build status\n"
        "        run: curl -X POST https://example.invalid/hook\n"
        "        continue-on-error: true\n",
    )
    assert _run(tmp_path) == []


def test_silencer_protocol_note_in_message(tmp_path):
    """Family V: the fix-hint tells the reader removing the silencer will expose a
    real failure it was hiding, so fix what surfaces too."""
    _wf(tmp_path, "ci.yml",
        "jobs:\n  build:\n    steps:\n"
        "      - run: npm run type-check\n"
        "        continue-on-error: true\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert "remove the silencer AND fix what surfaces" in f[0].message
