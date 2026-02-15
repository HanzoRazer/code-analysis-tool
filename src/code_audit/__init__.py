"""code_audit — confidence engine for beginner Vibe Coders."""

__all__ = [
    "__version__",
    "scan_project",
    "snapshot_debt",
    "compare_debt",
    "validate_instance",
    # Drift monitoring
    "DriftEvent",
    "DriftTracker",
    "DriftDetector",
    "DriftMonitor",
    "DriftScheduler",
]
__version__ = "0.1.0"

# Programmatic engine entrypoints (backend use) — see docs/CONTRACT.md §8.
from code_audit.api import (  # noqa: E402, F401
    compare_debt,
    scan_project,
    snapshot_debt,
    validate_instance,
)

# Drift monitoring exports
from code_audit.drift import (  # noqa: E402, F401
    DriftEvent,
    DriftTracker,
    DriftDetector,
    DriftMonitor,
    DriftScheduler,
)
