"""CI-mode environment lock.

When the CLI receives ``--ci``, the ``CI`` environment variable **must** be
set to the literal string ``"true"`` (case-insensitive, whitespace-trimmed).
Any other value — including unset — is a hard failure (exit-code 2).

This is the *reverse* of :func:`code_audit.__main__._require_ci_flag` which
errors when CI *is* active but ``--ci`` was *not* passed.
"""

from __future__ import annotations

import os


class CIModeRequiredError(RuntimeError):
    """Raised when ``--ci`` is passed but the ``CI`` env var is not ``"true"``."""

    def __init__(self, actual: str | None) -> None:
        self.actual = actual
        if actual is None:
            detail = "CI environment variable is not set"
        else:
            detail = f"CI environment variable is {actual!r}"
        super().__init__(
            f"--ci requires CI=true in the environment ({detail}). "
            f"This flag is reserved for genuine CI runners."
        )


def require_ci_true(env: dict[str, str] | None = None) -> None:
    """Assert that ``CI`` equals ``"true"`` (case-insensitive, trimmed).

    Parameters
    ----------
    env:
        Mapping to read ``CI`` from.  Defaults to :data:`os.environ`.

    Raises
    ------
    CIModeRequiredError
        If the ``CI`` value is missing or anything other than ``"true"``.
    """
    if env is None:
        env = os.environ
    raw = env.get("CI")
    if raw is None:
        raise CIModeRequiredError(None)
    if raw.strip().lower() != "true":
        raise CIModeRequiredError(raw)
