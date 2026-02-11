"""Debt registry — tracks debt snapshots over time for ratchet comparison.

Stores and loads JSON snapshots of ``DebtInstance`` lists.  Supports:

*  **Snapshot creation** — serialize current debt state to disk.
*  **Comparison** — diff two snapshots to find new / resolved debt.
*  **Ratchet mode** — fail CI only if *new* debt items are introduced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from code_audit.model.debt_instance import DebtInstance, DebtType, make_debt_fingerprint


@dataclass(frozen=True, slots=True)
class DebtDiff:
    """Result of comparing two debt snapshots."""

    new_items: list[DebtInstance]
    resolved_items: list[DebtInstance]
    unchanged_items: list[DebtInstance]

    @property
    def has_new_debt(self) -> bool:
        return len(self.new_items) > 0

    def summary(self) -> str:
        parts = [
            f"New: {len(self.new_items)}",
            f"Resolved: {len(self.resolved_items)}",
            f"Unchanged: {len(self.unchanged_items)}",
        ]
        return ", ".join(parts)


class DebtRegistry:
    """Manages debt snapshots on disk.

    Parameters
    ----------
    registry_dir:
        Directory to store snapshot JSON files.
    """

    def __init__(self, registry_dir: Path) -> None:
        self._dir = registry_dir

    # ── snapshot ─────────────────────────────────────────────────────

    def save_snapshot(
        self,
        name: str,
        items: list[DebtInstance],
    ) -> Path:
        """Write a named snapshot to disk.  Returns the file path."""
        self._dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        data: dict[str, Any] = {
            "name": name,
            "created_at": now,
            "debt_count": len(items),
            "items": [d.to_dict() for d in items],
        }
        path = self._dir / f"{name}.json"
        path.write_text(
            json.dumps(data, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        return path

    def load_snapshot(self, name: str) -> list[DebtInstance]:
        """Load a named snapshot from disk."""
        path = self._dir / f"{name}.json"
        if not path.exists():
            raise FileNotFoundError(f"Snapshot not found: {path}")

        data = json.loads(path.read_text(encoding="utf-8"))
        items: list[DebtInstance] = []
        for raw in data.get("items", []):
            items.append(
                DebtInstance(
                    debt_type=DebtType(raw["debt_type"]),
                    path=raw["path"],
                    symbol=raw["symbol"],
                    line_start=raw["line_start"],
                    line_end=raw["line_end"],
                    metrics=raw.get("metrics", {}),
                    strategy=raw.get("strategy", ""),
                    fingerprint=raw.get(
                        "fingerprint",
                        make_debt_fingerprint(
                            raw["debt_type"], raw["path"], raw["symbol"]
                        ),
                    ),
                )
            )
        return items

    def list_snapshots(self) -> list[str]:
        """Return the names of all saved snapshots (sorted)."""
        if not self._dir.exists():
            return []
        return sorted(
            p.stem for p in self._dir.glob("*.json") if p.is_file()
        )

    # ── comparison ──────────────────────────────────────────────────

    @staticmethod
    def compare(
        baseline: list[DebtInstance],
        current: list[DebtInstance],
    ) -> DebtDiff:
        """Compare a *baseline* snapshot against the *current* state.

        Uses fingerprints for identity.
        """
        baseline_fps = {d.fingerprint: d for d in baseline}
        current_fps = {d.fingerprint: d for d in current}

        bset = set(baseline_fps.keys())
        cset = set(current_fps.keys())

        new = [current_fps[fp] for fp in sorted(cset - bset)]
        resolved = [baseline_fps[fp] for fp in sorted(bset - cset)]
        unchanged = [current_fps[fp] for fp in sorted(bset & cset)]

        return DebtDiff(
            new_items=new,
            resolved_items=resolved,
            unchanged_items=unchanged,
        )
