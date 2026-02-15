"""
Drift Monitor - Configuration/Code Drift Detection & GitHub Issue Management

Detects drift between code versions and automatically manages GitHub issues
to track unresolved drift events with duration tracking and severity escalation.

Fixes applied from code review:
1. JSON serialization instead of pickle for datetime handling
2. Specific exception handling instead of bare except
3. Pruning of closed_issues dict to prevent memory leaks
4. Thread-safe state access with threading.Lock
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import subprocess
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Callable, Optional

try:
    from github import Github, GithubException
    from github.Issue import Issue
    GITHUB_AVAILABLE = True
except ImportError:
    GITHUB_AVAILABLE = False
    GithubException = Exception  # Fallback for type hints

try:
    from flask import Flask, request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------

@dataclass
class DriftEvent:
    """
    Represents a detected drift event with duration tracking.

    Tracks when drift was first detected, last seen, and calculates
    duration for severity escalation.
    """
    event_id: str
    category: str  # config, schema, dependency, security, etc.
    severity: str  # info, warning, error, critical
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    first_detected: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    github_issue_number: Optional[int] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None

    @property
    def duration_hours(self) -> float:
        """Calculate how long this drift has been unresolved."""
        if self.resolved and self.resolved_at:
            return (self.resolved_at - self.first_detected).total_seconds() / 3600
        return (datetime.now(timezone.utc) - self.first_detected).total_seconds() / 3600

    @property
    def escalated_severity(self) -> str:
        """Escalate severity based on duration."""
        hours = self.duration_hours
        base_severities = ["info", "warning", "error", "critical"]
        current_idx = base_severities.index(self.severity) if self.severity in base_severities else 0

        # Escalate after thresholds
        if hours > 168:  # 1 week
            return "critical"
        elif hours > 72:  # 3 days
            return base_severities[min(current_idx + 2, 3)]
        elif hours > 24:  # 1 day
            return base_severities[min(current_idx + 1, 3)]
        return self.severity

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        data = asdict(self)
        # Convert datetime objects to ISO format strings
        for key in ["first_detected", "last_seen", "resolved_at"]:
            if data[key] is not None:
                data[key] = data[key].isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DriftEvent":
        """Create from dict, parsing datetime strings."""
        # Parse datetime strings back to datetime objects
        for key in ["first_detected", "last_seen", "resolved_at"]:
            if data.get(key) is not None and isinstance(data[key], str):
                data[key] = datetime.fromisoformat(data[key])
        return cls(**data)


# -----------------------------------------------------------------------------
# State Persistence (JSON-based, thread-safe)
# -----------------------------------------------------------------------------

class DriftTracker:
    """
    Persists drift events to disk using JSON for reliable datetime handling.
    Thread-safe with lock protection.
    """

    CLOSED_ISSUES_MAX_AGE_DAYS = 30  # Prune closed issues older than this

    def __init__(self, state_path: Path | str = ".drift_state.json"):
        self.state_path = Path(state_path)
        self._lock = threading.Lock()
        self._events: dict[str, DriftEvent] = {}
        self._closed_issues: dict[str, datetime] = {}  # event_id -> closed_at
        self._load_state()

    def _load_state(self) -> None:
        """Load state from JSON file."""
        if not self.state_path.exists():
            return

        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Load events
            for event_id, event_data in data.get("events", {}).items():
                self._events[event_id] = DriftEvent.from_dict(event_data)

            # Load closed issues with datetime parsing
            for event_id, closed_at_str in data.get("closed_issues", {}).items():
                self._closed_issues[event_id] = datetime.fromisoformat(closed_at_str)

            logger.info(f"Loaded {len(self._events)} drift events from {self.state_path}")
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Failed to load drift state: {e}")

    def save_state(self) -> None:
        """Save state to JSON file (thread-safe)."""
        with self._lock:
            self._prune_closed_issues()

            data = {
                "events": {eid: event.to_dict() for eid, event in self._events.items()},
                "closed_issues": {
                    eid: dt.isoformat() for eid, dt in self._closed_issues.items()
                },
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            # Atomic write
            tmp_path = self.state_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            tmp_path.replace(self.state_path)

    def _prune_closed_issues(self) -> None:
        """Remove closed issues older than MAX_AGE_DAYS to prevent memory leak."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.CLOSED_ISSUES_MAX_AGE_DAYS)
        expired = [eid for eid, closed_at in self._closed_issues.items() if closed_at < cutoff]
        for eid in expired:
            del self._closed_issues[eid]
        if expired:
            logger.debug(f"Pruned {len(expired)} old closed issues")

    def add_event(self, event: DriftEvent) -> None:
        """Add or update a drift event (thread-safe)."""
        with self._lock:
            if event.event_id in self._events:
                # Update last_seen for existing event
                existing = self._events[event.event_id]
                existing.last_seen = datetime.now(timezone.utc)
            else:
                self._events[event.event_id] = event
        self.save_state()

    def get_event(self, event_id: str) -> Optional[DriftEvent]:
        """Get event by ID (thread-safe)."""
        with self._lock:
            return self._events.get(event_id)

    def get_active_events(self) -> list[DriftEvent]:
        """Get all unresolved events (thread-safe)."""
        with self._lock:
            return [e for e in self._events.values() if not e.resolved]

    def resolve_event(self, event_id: str) -> bool:
        """Mark event as resolved (thread-safe)."""
        with self._lock:
            if event_id in self._events:
                event = self._events[event_id]
                event.resolved = True
                event.resolved_at = datetime.now(timezone.utc)
                self._closed_issues[event_id] = datetime.now(timezone.utc)
                self.save_state()
                return True
            return False

    def reopen_event(self, event_id: str) -> bool:
        """Reopen a resolved event (thread-safe)."""
        with self._lock:
            if event_id in self._events:
                event = self._events[event_id]
                event.resolved = False
                event.resolved_at = None
                event.last_seen = datetime.now(timezone.utc)
                self._closed_issues.pop(event_id, None)
                self.save_state()
                return True
            return False

    def is_in_cooldown(self, event_id: str, cooldown_hours: float = 24.0) -> bool:
        """
        Check if event was recently closed (in cooldown period).
        Prevents issue flapping from transient fixes.
        """
        with self._lock:
            if event_id in self._closed_issues:
                closed_at = self._closed_issues[event_id]
                hours_since_close = (datetime.now(timezone.utc) - closed_at).total_seconds() / 3600
                return hours_since_close < cooldown_hours
            return False


# -----------------------------------------------------------------------------
# Git-based Drift Detection
# -----------------------------------------------------------------------------

class DriftDetector:
    """
    Detects drift by comparing git commits for configuration and code changes.
    """

    DEFAULT_WATCHED_PATTERNS = [
        "*.json",
        "*.yaml",
        "*.yml",
        "*.toml",
        "*.ini",
        "*.env*",
        "requirements*.txt",
        "pyproject.toml",
        "package.json",
        "Dockerfile*",
        "docker-compose*.yml",
    ]

    def __init__(
        self,
        repo_path: Path | str = ".",
        watched_patterns: Optional[list[str]] = None,
        base_ref: str = "HEAD~1",
    ):
        self.repo_path = Path(repo_path)
        self.watched_patterns = watched_patterns or self.DEFAULT_WATCHED_PATTERNS
        self.base_ref = base_ref

    def _run_git(self, *args: str) -> str:
        """Run git command and return output."""
        result = subprocess.run(
            ["git", "-C", str(self.repo_path), *args],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Git command failed: {result.stderr}")
        return result.stdout.strip()

    def get_changed_files(self, target_ref: str = "HEAD") -> list[str]:
        """Get list of files changed between base_ref and target_ref."""
        try:
            output = self._run_git("diff", "--name-only", self.base_ref, target_ref)
            return [f for f in output.split("\n") if f]
        except RuntimeError as e:
            logger.error(f"Failed to get changed files: {e}")
            return []

    def detect_config_drift(self, target_ref: str = "HEAD") -> list[DriftEvent]:
        """Detect configuration file changes that may indicate drift."""
        events = []
        changed_files = self.get_changed_files(target_ref)

        for file_path in changed_files:
            if not self._matches_patterns(file_path):
                continue

            event_id = self._generate_event_id(file_path, "config_change")

            # Get diff details
            try:
                diff_output = self._run_git("diff", self.base_ref, target_ref, "--", file_path)
                lines_changed = len([l for l in diff_output.split("\n") if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))])
            except RuntimeError:
                diff_output = ""
                lines_changed = 0

            severity = "warning" if lines_changed > 10 else "info"
            if any(kw in file_path.lower() for kw in ["secret", "credential", "password", "key"]):
                severity = "critical"

            event = DriftEvent(
                event_id=event_id,
                category="config",
                severity=severity,
                title=f"Configuration drift detected: {file_path}",
                description=f"File changed with {lines_changed} line modifications",
                file_path=file_path,
            )
            events.append(event)

        return events

    def detect_dependency_drift(self, target_ref: str = "HEAD") -> list[DriftEvent]:
        """Detect dependency changes in requirements/package files."""
        events = []
        dep_files = [
            "requirements.txt",
            "requirements-dev.txt",
            "pyproject.toml",
            "package.json",
            "package-lock.json",
        ]

        changed_files = self.get_changed_files(target_ref)

        for file_path in changed_files:
            if not any(file_path.endswith(df) for df in dep_files):
                continue

            event_id = self._generate_event_id(file_path, "dependency_change")

            event = DriftEvent(
                event_id=event_id,
                category="dependency",
                severity="warning",
                title=f"Dependency drift detected: {file_path}",
                description="Dependency file has been modified - verify compatibility",
                file_path=file_path,
            )
            events.append(event)

        return events

    def detect_schema_drift(self, schema_dir: str = "contracts") -> list[DriftEvent]:
        """Detect schema file changes that may break contracts."""
        events = []
        schema_path = self.repo_path / schema_dir

        if not schema_path.exists():
            return events

        changed_files = self.get_changed_files()

        for file_path in changed_files:
            if not file_path.startswith(schema_dir):
                continue
            if not file_path.endswith((".json", ".yaml", ".yml")):
                continue

            event_id = self._generate_event_id(file_path, "schema_change")

            event = DriftEvent(
                event_id=event_id,
                category="schema",
                severity="error",
                title=f"Schema drift detected: {file_path}",
                description="Schema file changed - ensure backward compatibility",
                file_path=file_path,
            )
            events.append(event)

        return events

    def detect_all_drift(self, target_ref: str = "HEAD") -> list[DriftEvent]:
        """Run all drift detection methods."""
        events = []
        events.extend(self.detect_config_drift(target_ref))
        events.extend(self.detect_dependency_drift(target_ref))
        events.extend(self.detect_schema_drift())
        return events

    def _matches_patterns(self, file_path: str) -> bool:
        """Check if file matches any watched pattern."""
        from fnmatch import fnmatch
        return any(fnmatch(file_path, p) or fnmatch(os.path.basename(file_path), p)
                   for p in self.watched_patterns)

    def _generate_event_id(self, file_path: str, event_type: str) -> str:
        """Generate stable event ID from file path and type."""
        content = f"{file_path}:{event_type}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


# -----------------------------------------------------------------------------
# GitHub Issue Management
# -----------------------------------------------------------------------------

class GitHubDriftManager:
    """
    Manages GitHub issues for drift events with auto-create, update, and close.
    """

    DRIFT_LABEL = "drift-detected"
    SEVERITY_LABELS = {
        "info": "drift-info",
        "warning": "drift-warning",
        "error": "drift-error",
        "critical": "drift-critical",
    }

    def __init__(
        self,
        repo: str,  # "owner/repo"
        token: Optional[str] = None,
    ):
        if not GITHUB_AVAILABLE:
            raise ImportError("PyGithub required: pip install PyGithub")

        self.token = token or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("GitHub token required (env GITHUB_TOKEN or token param)")

        self.gh = Github(self.token)
        self.repo = self.gh.get_repo(repo)
        self._ensure_labels()

    def _ensure_labels(self) -> None:
        """Ensure drift labels exist in the repository."""
        existing = {label.name for label in self.repo.get_labels()}

        labels_to_create = [
            (self.DRIFT_LABEL, "0366D6", "Automated drift detection"),
            ("drift-info", "C5DEF5", "Informational drift"),
            ("drift-warning", "FBCA04", "Warning-level drift"),
            ("drift-error", "D93F0B", "Error-level drift"),
            ("drift-critical", "B60205", "Critical drift requiring immediate action"),
        ]

        for name, color, description in labels_to_create:
            if name not in existing:
                try:
                    self.repo.create_label(name, color, description)
                    logger.info(f"Created label: {name}")
                except GithubException as e:
                    logger.warning(f"Failed to create label {name}: {e}")

    def create_or_update_issue(self, event: DriftEvent) -> Optional[Issue]:
        """Create new issue or update existing one for drift event."""
        # Check for existing open issue
        existing = self._find_existing_issue(event.event_id)

        body = self._format_issue_body(event)
        labels = [self.DRIFT_LABEL, self.SEVERITY_LABELS.get(event.escalated_severity, "drift-info")]

        if existing:
            # Update existing issue
            existing.edit(body=body)
            self._update_labels(existing, labels)
            logger.info(f"Updated issue #{existing.number} for event {event.event_id}")
            return existing
        else:
            # Create new issue
            issue = self.repo.create_issue(
                title=event.title,
                body=body,
                labels=labels,
            )
            logger.info(f"Created issue #{issue.number} for event {event.event_id}")
            return issue

    def close_issue(self, event: DriftEvent) -> bool:
        """Close issue when drift is resolved."""
        issue = self._find_existing_issue(event.event_id)
        if issue and issue.state == "open":
            resolution_comment = (
                f"Drift resolved automatically.\n\n"
                f"- Duration: {event.duration_hours:.1f} hours\n"
                f"- Resolved at: {datetime.now(timezone.utc).isoformat()}\n"
            )
            issue.create_comment(resolution_comment)
            issue.edit(state="closed")
            logger.info(f"Closed issue #{issue.number}")
            return True
        return False

    def reopen_issue(self, event: DriftEvent) -> bool:
        """Reopen issue if drift reappears."""
        issue = self._find_existing_issue(event.event_id)
        if issue and issue.state == "closed":
            issue.edit(state="open")
            issue.create_comment(
                f"Drift redetected after being resolved.\n"
                f"- Reopened at: {datetime.now(timezone.utc).isoformat()}\n"
            )
            logger.info(f"Reopened issue #{issue.number}")
            return True
        return False

    def _find_existing_issue(self, event_id: str) -> Optional[Issue]:
        """Find existing issue by event ID marker in body."""
        marker = f"<!-- drift-event-id: {event_id} -->"

        for issue in self.repo.get_issues(state="all", labels=[self.DRIFT_LABEL]):
            if marker in (issue.body or ""):
                return issue
        return None

    def _format_issue_body(self, event: DriftEvent) -> str:
        """Format issue body with drift details."""
        marker = f"<!-- drift-event-id: {event.event_id} -->"

        body = f"""{marker}

## Drift Details

| Field | Value |
|-------|-------|
| **Category** | {event.category} |
| **Severity** | {event.severity} (escalated: {event.escalated_severity}) |
| **First Detected** | {event.first_detected.isoformat()} |
| **Last Seen** | {event.last_seen.isoformat()} |
| **Duration** | {event.duration_hours:.1f} hours |

### Description

{event.description}

"""

        if event.file_path:
            body += f"**File:** `{event.file_path}`"
            if event.line_number:
                body += f":{event.line_number}"
            body += "\n\n"

        if event.old_value or event.new_value:
            body += "### Changes\n\n"
            if event.old_value:
                body += f"**Before:**\n```\n{event.old_value}\n```\n\n"
            if event.new_value:
                body += f"**After:**\n```\n{event.new_value}\n```\n\n"

        body += (
            "\n---\n"
            "*This issue is managed automatically by the Drift Monitor. "
            "It will be closed when the drift is resolved.*"
        )

        return body

    def _update_labels(self, issue: Issue, labels: list[str]) -> None:
        """Update issue labels, removing old severity labels."""
        current_labels = {label.name for label in issue.labels}

        # Remove old severity labels
        for sev_label in self.SEVERITY_LABELS.values():
            if sev_label in current_labels and sev_label not in labels:
                issue.remove_from_labels(sev_label)

        # Add new labels
        for label in labels:
            if label not in current_labels:
                issue.add_to_labels(label)


# -----------------------------------------------------------------------------
# Main Orchestrator
# -----------------------------------------------------------------------------

class DriftMonitor:
    """
    Main orchestrator combining drift detection, tracking, and GitHub management.
    """

    def __init__(
        self,
        repo_path: Path | str = ".",
        github_repo: Optional[str] = None,
        github_token: Optional[str] = None,
        state_path: Path | str = ".drift_state.json",
        cooldown_hours: float = 24.0,
    ):
        self.detector = DriftDetector(repo_path)
        self.tracker = DriftTracker(state_path)
        self.cooldown_hours = cooldown_hours

        self.github_manager: Optional[GitHubDriftManager] = None
        if github_repo and GITHUB_AVAILABLE:
            try:
                self.github_manager = GitHubDriftManager(github_repo, github_token)
            except (ValueError, ImportError) as e:
                logger.warning(f"GitHub integration disabled: {e}")

    def run_detection(self, target_ref: str = "HEAD") -> list[DriftEvent]:
        """Run drift detection and process events."""
        detected_events = self.detector.detect_all_drift(target_ref)
        processed_events = []

        for event in detected_events:
            # Check cooldown
            if self.tracker.is_in_cooldown(event.event_id, self.cooldown_hours):
                logger.debug(f"Event {event.event_id} in cooldown, skipping")
                continue

            # Check if this is a reappearing event
            existing = self.tracker.get_event(event.event_id)
            if existing and existing.resolved:
                # Drift reappeared - reopen
                self.tracker.reopen_event(event.event_id)
                if self.github_manager:
                    self.github_manager.reopen_issue(existing)
            else:
                # New or ongoing drift
                self.tracker.add_event(event)

            # Create/update GitHub issue
            if self.github_manager:
                tracked_event = self.tracker.get_event(event.event_id)
                if tracked_event:
                    issue = self.github_manager.create_or_update_issue(tracked_event)
                    if issue:
                        tracked_event.github_issue_number = issue.number
                        self.tracker.save_state()

            processed_events.append(event)

        # Check for resolved events (no longer detected)
        self._check_resolved_events(detected_events)

        return processed_events

    def _check_resolved_events(self, current_events: list[DriftEvent]) -> None:
        """Check if any tracked events are no longer detected (resolved)."""
        current_ids = {e.event_id for e in current_events}

        for event in self.tracker.get_active_events():
            if event.event_id not in current_ids:
                # Event no longer detected - mark resolved
                self.tracker.resolve_event(event.event_id)
                if self.github_manager:
                    self.github_manager.close_issue(event)
                logger.info(f"Resolved drift event: {event.event_id}")

    def get_status(self) -> dict[str, Any]:
        """Get current drift monitoring status."""
        active = self.tracker.get_active_events()

        by_severity = {"info": 0, "warning": 0, "error": 0, "critical": 0}
        by_category = {}

        for event in active:
            sev = event.escalated_severity
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_category[event.category] = by_category.get(event.category, 0) + 1

        return {
            "active_events": len(active),
            "by_severity": by_severity,
            "by_category": by_category,
            "oldest_event_hours": max((e.duration_hours for e in active), default=0),
            "github_enabled": self.github_manager is not None,
        }


# -----------------------------------------------------------------------------
# Webhook Server (Flask-based)
# -----------------------------------------------------------------------------

class WebhookServer:
    """
    Flask-based webhook server for receiving GitHub events and triggering scans.
    """

    def __init__(
        self,
        monitor: DriftMonitor,
        webhook_secret: Optional[str] = None,
        port: int = 8080,
    ):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask required: pip install Flask")

        self.monitor = monitor
        self.webhook_secret = webhook_secret or os.environ.get("WEBHOOK_SECRET")
        self.port = port
        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Setup Flask routes."""

        @self.app.route("/health", methods=["GET"])
        def health():
            return jsonify({"status": "ok"})

        @self.app.route("/webhook", methods=["POST"])
        def webhook():
            # Verify signature if secret configured
            if self.webhook_secret:
                signature = request.headers.get("X-Hub-Signature-256", "")
                if not self._verify_signature(request.data, signature):
                    return jsonify({"error": "Invalid signature"}), 401

            event_type = request.headers.get("X-GitHub-Event", "")

            if event_type == "push":
                # Trigger drift detection on push
                events = self.monitor.run_detection()
                return jsonify({
                    "processed": len(events),
                    "status": self.monitor.get_status(),
                })

            return jsonify({"status": "ignored", "event": event_type})

        @self.app.route("/status", methods=["GET"])
        def status():
            return jsonify(self.monitor.get_status())

        @self.app.route("/scan", methods=["POST"])
        def scan():
            events = self.monitor.run_detection()
            return jsonify({
                "processed": len(events),
                "events": [e.to_dict() for e in events],
            })

    def _verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub webhook signature."""
        if not self.webhook_secret:
            return True

        expected = "sha256=" + hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(signature, expected)

    def run(self, debug: bool = False) -> None:
        """Run the webhook server."""
        self.app.run(host="0.0.0.0", port=self.port, debug=debug)


# -----------------------------------------------------------------------------
# Scheduled Monitoring
# -----------------------------------------------------------------------------

class DriftScheduler:
    """
    Runs drift detection on a schedule using the schedule library.
    """

    def __init__(
        self,
        monitor: DriftMonitor,
        interval_minutes: int = 30,
        on_drift: Optional[Callable[[list[DriftEvent]], None]] = None,
    ):
        if not SCHEDULE_AVAILABLE:
            raise ImportError("schedule required: pip install schedule")

        self.monitor = monitor
        self.interval_minutes = interval_minutes
        self.on_drift = on_drift
        self._running = False

    def _run_check(self) -> None:
        """Run a drift detection check."""
        logger.info("Running scheduled drift check")
        try:
            events = self.monitor.run_detection()
            if events and self.on_drift:
                self.on_drift(events)
        except (RuntimeError, IOError) as e:
            logger.error(f"Drift check failed: {e}")

    def start(self) -> None:
        """Start the scheduler."""
        schedule.every(self.interval_minutes).minutes.do(self._run_check)
        self._running = True

        logger.info(f"Drift scheduler started (every {self.interval_minutes} min)")

        while self._running:
            schedule.run_pending()
            import time
            time.sleep(1)

    def stop(self) -> None:
        """Stop the scheduler."""
        self._running = False
        schedule.clear()


# -----------------------------------------------------------------------------
# CLI Entry Point
# -----------------------------------------------------------------------------

def main() -> None:
    """CLI entry point for drift monitoring."""
    import argparse

    parser = argparse.ArgumentParser(description="Drift Monitor CLI")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--github-repo", help="GitHub repo (owner/repo)")
    parser.add_argument("--state-file", default=".drift_state.json", help="State file path")
    parser.add_argument("--scan", action="store_true", help="Run single scan")
    parser.add_argument("--status", action="store_true", help="Show status")
    parser.add_argument("--schedule", type=int, help="Run scheduled (minutes)")
    parser.add_argument("--webhook", action="store_true", help="Run webhook server")
    parser.add_argument("--port", type=int, default=8080, help="Webhook server port")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    monitor = DriftMonitor(
        repo_path=args.repo,
        github_repo=args.github_repo,
        state_path=args.state_file,
    )

    if args.status:
        status = monitor.get_status()
        print(json.dumps(status, indent=2))
    elif args.scan:
        events = monitor.run_detection()
        print(f"Detected {len(events)} drift events")
        for event in events:
            print(f"  - [{event.escalated_severity}] {event.title}")
    elif args.schedule:
        scheduler = DriftScheduler(monitor, args.schedule)
        scheduler.start()
    elif args.webhook:
        server = WebhookServer(monitor, port=args.port)
        server.run()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
