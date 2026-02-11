"""Deprecation-sunset analyzer — enforces timely removal of deprecated routes/modules.

Generalization of the luthiers-toolbox ``check_deprecation_sunset.py``.
Reads a ``deprecation_registry.json`` that lists routes / modules with sunset
dates.  Produces findings for:

* **Overdue** sunsets — the sunset date has passed and the module still exists.
* **Upcoming** sunsets — the sunset date is approaching (within *upcoming_days*).

Maps to ``AnalyzerType.DEAD_CODE`` (deprecated modules are scheduled for
removal).
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint


def _parse_date(s: str) -> date:
    """Parse an ISO-8601 date string (YYYY-MM-DD)."""
    return date.fromisoformat(s)


class DeprecationAnalyzer:
    """Checks for overdue and upcoming deprecation sunsets.

    Conforms to the ``Analyzer`` protocol (``id``, ``version``, ``run()``).

    Parameters
    ----------
    registry_path:
        Path to a JSON file conforming to the deprecation_registry schema.
        If *None* the analyzer looks for ``deprecation_registry.json`` in the
        project root.
    warn_only:
        If *True*, overdue findings are emitted as MEDIUM instead of HIGH.
    upcoming_days:
        Emit an INFO-level finding for sunsets within this many days.  Set to
        *0* to disable upcoming warnings.
    reference_date:
        Override "today" — useful for deterministic tests.
    """

    id: str = "deprecation_sunset"
    version: str = "1.0.0"

    def __init__(
        self,
        *,
        registry_path: Path | str | None = None,
        warn_only: bool = False,
        upcoming_days: int = 30,
        reference_date: date | None = None,
    ) -> None:
        self._registry_path = Path(registry_path) if registry_path else None
        self._warn_only = warn_only
        self._upcoming_days = upcoming_days
        self._reference_date = reference_date

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_registry(path: Path) -> list[dict[str, Any]]:
        """Return the ``routes`` array from a deprecation-registry JSON."""
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data.get("routes", [])
        return []

    @staticmethod
    def _module_exists(root: Path, module: str) -> bool:
        """Check if the module file (or package) exists under *root*."""
        # module can be a dotted path like 'app.legacy.helpers'
        rel = Path(module.replace(".", "/"))
        # Could be a .py file or a package directory
        return (root / rel.with_suffix(".py")).exists() or (root / rel / "__init__.py").exists()

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []
        today = self._reference_date or date.today()

        # Resolve registry path
        reg_path = self._registry_path or root / "deprecation_registry.json"
        if not reg_path.exists():
            # No registry → nothing to check
            return findings

        try:
            routes = self._load_registry(reg_path)
        except (json.JSONDecodeError, KeyError):
            return findings

        for entry in routes:
            route_id: str = entry.get("id", "unknown")
            module: str = entry.get("module", "")
            sunset_str: str = entry.get("sunset_date", "")
            old_prefix: str = entry.get("old_prefix", "")
            new_prefix: str = entry.get("new_prefix", "")

            if not module or not sunset_str:
                continue

            try:
                sunset = _parse_date(sunset_str)
            except ValueError:
                continue

            module_present = self._module_exists(root, module)
            days_remaining = (sunset - today).days

            if days_remaining < 0 and module_present:
                # Overdue — module should have been removed
                sev = Severity.MEDIUM if self._warn_only else Severity.HIGH
                rule_id = "GOV-DEPR-OVERDUE"
                snippet = f"module={module}  sunset={sunset_str}"
                msg = (
                    f"Deprecated route '{route_id}' ({module}) was due for "
                    f"removal on {sunset_str} ({-days_remaining} days overdue)"
                )
                if new_prefix:
                    msg += f" — migrate to '{new_prefix}'"

                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.DEAD_CODE,
                        severity=sev,
                        confidence=0.95,
                        message=msg,
                        location=Location(
                            path=module.replace(".", "/") + ".py",
                            line_start=1,
                            line_end=1,
                        ),
                        fingerprint=make_fingerprint(rule_id, module, route_id, snippet),
                        snippet=snippet,
                        metadata={
                            "rule_id": rule_id,
                            "route_id": route_id,
                            "module": module,
                            "sunset_date": sunset_str,
                            "days_overdue": -days_remaining,
                            **({"old_prefix": old_prefix} if old_prefix else {}),
                            **({"new_prefix": new_prefix} if new_prefix else {}),
                        },
                    )
                )

            elif 0 <= days_remaining <= self._upcoming_days and module_present:
                # Approaching sunset
                rule_id = "GOV-DEPR-UPCOMING"
                snippet = f"module={module}  sunset={sunset_str}"
                msg = (
                    f"Route '{route_id}' ({module}) sunset in "
                    f"{days_remaining} day(s) ({sunset_str})"
                )

                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.DEAD_CODE,
                        severity=Severity.INFO,
                        confidence=0.90,
                        message=msg,
                        location=Location(
                            path=module.replace(".", "/") + ".py",
                            line_start=1,
                            line_end=1,
                        ),
                        fingerprint=make_fingerprint(rule_id, module, route_id, snippet),
                        snippet=snippet,
                        metadata={
                            "rule_id": rule_id,
                            "route_id": route_id,
                            "module": module,
                            "sunset_date": sunset_str,
                            "days_remaining": days_remaining,
                        },
                    )
                )

        # Assign IDs
        for i, f in enumerate(findings):
            object.__setattr__(
                f, "finding_id", f"dep_{f.fingerprint[7:15]}_{i:04d}"
            )
        return findings
