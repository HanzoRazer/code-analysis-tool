"""Centralized exit-code contract for all CLI commands.

Code  Meaning
----  -------
  0   Success — no violations detected
  1   Violation — policy / contract failure (scan found debt, fence tripped, etc.)
  2   Error — usage error, missing file, runtime failure
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    VIOLATION = 1
    ERROR = 2
