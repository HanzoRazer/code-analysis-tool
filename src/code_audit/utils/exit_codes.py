"""Centralized exit-code contract for all CLI commands.

Code  Meaning
----  -------
  0   Success — no violations detected (scan tier GREEN)
  1   Violation — policy / contract failure (scan tier YELLOW)
  2   Error — usage error, missing file, runtime failure (scan tier RED)
  3   Inconclusive — the scan could not assess the repository
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    VIOLATION = 1
    ERROR = 2
    INCONCLUSIVE = 3
