"""Parse an endpoint truth-map from Markdown into structured data.

Port of the luthiers-toolbox ``parse_truth_map.py`` helper.  Reads a Markdown
file (typically ``ENDPOINT_TRUTH_MAP.md``) containing a table of API endpoints
and returns a list of :class:`EndpointEntry` objects.

Expected Markdown table format::

    | Method | Path             | Module              | Status  |
    |--------|------------------|---------------------|---------|
    | GET    | /api/v2/widgets  | app.routes.widgets  | active  |
    | POST   | /api/v2/widgets  | app.routes.widgets  | active  |
    | GET    | /api/v1/legacy   | app.routes.legacy   | deprecated |

Columns are identified by header names (case-insensitive).  Extra columns
are stored in ``EndpointEntry.extra``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

# ── regex for Markdown table rows ─────────────────────────────────────

_TABLE_ROW = re.compile(r"^\s*\|(.+)\|\s*$")
_SEPARATOR = re.compile(r"^[\s|:-]+$")


@dataclass(frozen=True, slots=True)
class EndpointEntry:
    """One endpoint defined in the truth map."""

    method: str                   # HTTP verb (GET, POST, …)
    path: str                     # URL path
    module: str = ""              # Python/TS module that implements it
    status: str = "active"        # active | deprecated | removed
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, str]:
        d = {
            "method": self.method,
            "path": self.path,
            "module": self.module,
            "status": self.status,
        }
        if self.extra:
            d.update(self.extra)
        return d


def parse_truth_map(
    source: str | Path,
    *,
    required_columns: Sequence[str] = ("method", "path"),
) -> list[EndpointEntry]:
    """Parse a Markdown truth-map into a list of :class:`EndpointEntry`.

    Parameters
    ----------
    source:
        Markdown text **or** a :class:`Path` to a Markdown file.
    required_columns:
        Column names that must be present (case-insensitive).

    Returns
    -------
    List of parsed endpoint entries, in document order.

    Raises
    ------
    ValueError
        If the required columns are missing or no table is found.
    """
    if isinstance(source, Path):
        source = source.read_text(encoding="utf-8")

    lines = source.splitlines()
    headers: list[str] | None = None
    entries: list[EndpointEntry] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        m = _TABLE_ROW.match(line)
        if m is None:
            i += 1
            continue

        cells = [c.strip() for c in m.group(1).split("|")]

        # If we haven't found headers yet, treat this row as the header
        if headers is None:
            headers = [c.lower() for c in cells]

            # Validate required columns
            for req in required_columns:
                if req.lower() not in headers:
                    raise ValueError(
                        f"Required column '{req}' not found in table headers: "
                        f"{headers}"
                    )

            # Skip the separator row (next line)
            if i + 1 < len(lines) and _SEPARATOR.match(lines[i + 1]):
                i += 2
                continue
            i += 1
            continue

        # Data row — build entry
        row: dict[str, str] = {}
        for j, header in enumerate(headers):
            row[header] = cells[j] if j < len(cells) else ""

        method = row.get("method", "").upper()
        path = row.get("path", "")
        module = row.get("module", "")
        status = row.get("status", "active").lower()

        extra = {
            k: v for k, v in row.items()
            if k not in {"method", "path", "module", "status"}
        }

        if method and path:
            entries.append(
                EndpointEntry(
                    method=method,
                    path=path,
                    module=module,
                    status=status,
                    extra=extra if extra else {},
                )
            )

        i += 1

    if headers is None:
        raise ValueError("No Markdown table found in source.")

    return entries


def truth_map_to_set(entries: list[EndpointEntry]) -> set[tuple[str, str]]:
    """Convert entries to a set of ``(METHOD, path)`` tuples for quick lookup."""
    return {(e.method, e.path) for e in entries}


def diff_truth_map(
    declared: list[EndpointEntry],
    actual: set[tuple[str, str]],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Compare declared endpoints against actual routes.

    Returns
    -------
    (missing, unexpected):
        *missing*    — declared but not found in actual
        *unexpected* — found in actual but not declared
    """
    declared_set = truth_map_to_set(declared)
    active_declared = {
        (e.method, e.path) for e in declared if e.status == "active"
    }

    missing = sorted(active_declared - actual)
    unexpected = sorted(actual - declared_set)
    return missing, unexpected
