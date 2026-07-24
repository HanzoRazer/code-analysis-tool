"""Shared pytest fixtures for code-analysis-tool.

See TEST_FAILURE_REMEDIATION_REV2.md: clean_ci_env is opt-in only.
An autouse scrub would forge green / silently downgrade CI-gated governance tests.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def clean_ci_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Opt-in: strip ambient CI vars for in-process tests that do not expect them.

    NOT autouse. A global version forges green on the collection gate and
    silently downgrades tagged-CI / entrypoint contracts (Rev 2 section 2).

    Does not help subprocess tests that hardcode CI=true; those need
    cwd + relative --out when exercising --ci path guards.
    """
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("CODE_AUDIT_DETERMINISTIC", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)