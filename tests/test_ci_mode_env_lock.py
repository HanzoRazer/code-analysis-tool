"""Tests for the CI-mode environment lock.

``require_ci_true()`` must only accept the literal string ``"true"``
(case-insensitive, whitespace-trimmed).  Everything else — including
``"1"``, ``"yes"``, ``"on"``, empty string, and unset — must raise
:class:`CIModeRequiredError`.
"""

from __future__ import annotations

import pytest

from code_audit.contracts.ci_mode import CIModeRequiredError, require_ci_true


# ── Accepted values ──────────────────────────────────────────────────

@pytest.mark.parametrize(
    "ci_val",
    [
        "true",
        "True",
        "TRUE",
        "tRuE",
        " true",
        "true ",
        " true ",
        "  TRUE  ",
    ],
    ids=lambda v: repr(v),
)
def test_accepted(ci_val: str) -> None:
    """``require_ci_true`` must not raise for accepted CI values."""
    require_ci_true({"CI": ci_val})  # should not raise


# ── Rejected values ──────────────────────────────────────────────────

@pytest.mark.parametrize(
    "ci_val",
    [
        "",
        "false",
        "False",
        "FALSE",
        "0",
        "1",
        "yes",
        "Yes",
        "on",
        "prod",
        "ci",
        "Truee",
        "tru",
        "truetrue",
        " ",
    ],
    ids=lambda v: repr(v),
)
def test_rejected(ci_val: str) -> None:
    """``require_ci_true`` must raise for anything other than ``"true"``."""
    with pytest.raises(CIModeRequiredError) as exc_info:
        require_ci_true({"CI": ci_val})
    assert exc_info.value.actual == ci_val


# ── Unset (missing key) ─────────────────────────────────────────────

def test_unset_raises() -> None:
    """``require_ci_true`` must raise when ``CI`` is not in the env dict."""
    with pytest.raises(CIModeRequiredError) as exc_info:
        require_ci_true({})
    assert exc_info.value.actual is None


def test_none_env_uses_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    """When *env* is ``None``, falls back to :data:`os.environ`."""
    monkeypatch.setenv("CI", "true")
    require_ci_true()  # should not raise


def test_none_env_rejects_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """When *env* is ``None`` and ``CI`` is unset, must raise."""
    monkeypatch.delenv("CI", raising=False)
    with pytest.raises(CIModeRequiredError):
        require_ci_true()


# ── Error message contract ───────────────────────────────────────────

def test_error_message_contains_flag_name() -> None:
    """The error message must mention ``--ci`` so users know which flag failed."""
    with pytest.raises(CIModeRequiredError, match="--ci"):
        require_ci_true({"CI": "0"})


def test_error_message_contains_actual_value() -> None:
    """The error message should surface the actual CI value for debugging."""
    with pytest.raises(CIModeRequiredError, match="'nope'"):
        require_ci_true({"CI": "nope"})
