"""Tests for drift monitoring functionality."""

import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from code_audit.drift.drift_monitor import (
    DriftEvent,
    DriftTracker,
    DriftDetector,
    DriftMonitor,
)


# -----------------------------------------------------------------------------
# DriftEvent Tests
# -----------------------------------------------------------------------------

class TestDriftEvent:
    """Tests for DriftEvent dataclass."""

    def test_duration_hours_unresolved(self):
        """Test duration calculation for unresolved event."""
        past = datetime.now(timezone.utc) - timedelta(hours=5)
        event = DriftEvent(
            event_id="test-001",
            category="config",
            severity="warning",
            title="Test drift",
            description="Test description",
            first_detected=past,
        )

        # Should be approximately 5 hours
        assert 4.9 < event.duration_hours < 5.1

    def test_duration_hours_resolved(self):
        """Test duration calculation for resolved event."""
        start = datetime.now(timezone.utc) - timedelta(hours=10)
        end = datetime.now(timezone.utc) - timedelta(hours=5)

        event = DriftEvent(
            event_id="test-002",
            category="config",
            severity="warning",
            title="Test drift",
            description="Test description",
            first_detected=start,
            resolved=True,
            resolved_at=end,
        )

        # Should be exactly 5 hours
        assert 4.9 < event.duration_hours < 5.1

    def test_escalated_severity_within_day(self):
        """Test severity not escalated within 24 hours."""
        event = DriftEvent(
            event_id="test-003",
            category="config",
            severity="info",
            title="Test drift",
            description="Test description",
            first_detected=datetime.now(timezone.utc) - timedelta(hours=12),
        )

        assert event.escalated_severity == "info"

    def test_escalated_severity_after_day(self):
        """Test severity escalates after 24 hours."""
        event = DriftEvent(
            event_id="test-004",
            category="config",
            severity="info",
            title="Test drift",
            description="Test description",
            first_detected=datetime.now(timezone.utc) - timedelta(hours=30),
        )

        assert event.escalated_severity == "warning"

    def test_escalated_severity_after_week(self):
        """Test severity escalates to critical after 1 week."""
        event = DriftEvent(
            event_id="test-005",
            category="config",
            severity="info",
            title="Test drift",
            description="Test description",
            first_detected=datetime.now(timezone.utc) - timedelta(days=8),
        )

        assert event.escalated_severity == "critical"

    def test_to_dict_serialization(self):
        """Test conversion to JSON-serializable dict."""
        event = DriftEvent(
            event_id="test-006",
            category="config",
            severity="warning",
            title="Test drift",
            description="Test description",
        )

        data = event.to_dict()

        # Should be JSON serializable
        json_str = json.dumps(data)
        assert "test-006" in json_str

        # Datetimes should be ISO strings
        assert isinstance(data["first_detected"], str)
        assert isinstance(data["last_seen"], str)

    def test_from_dict_deserialization(self):
        """Test creation from dict with datetime parsing."""
        data = {
            "event_id": "test-007",
            "category": "config",
            "severity": "error",
            "title": "Test drift",
            "description": "Test description",
            "first_detected": "2024-01-15T10:30:00+00:00",
            "last_seen": "2024-01-15T12:00:00+00:00",
            "resolved": False,
            "resolved_at": None,
            "file_path": "config.json",
            "line_number": None,
            "old_value": None,
            "new_value": None,
            "github_issue_number": None,
        }

        event = DriftEvent.from_dict(data)

        assert event.event_id == "test-007"
        assert event.severity == "error"
        assert isinstance(event.first_detected, datetime)
        assert event.first_detected.year == 2024


# -----------------------------------------------------------------------------
# DriftTracker Tests
# -----------------------------------------------------------------------------

class TestDriftTracker:
    """Tests for DriftTracker state persistence."""

    def test_add_and_get_event(self, tmp_path):
        """Test adding and retrieving events."""
        state_file = tmp_path / "drift_state.json"
        tracker = DriftTracker(state_file)

        event = DriftEvent(
            event_id="track-001",
            category="config",
            severity="warning",
            title="Test drift",
            description="Test description",
        )

        tracker.add_event(event)
        retrieved = tracker.get_event("track-001")

        assert retrieved is not None
        assert retrieved.event_id == "track-001"

    def test_persistence_roundtrip(self, tmp_path):
        """Test that events survive save/load cycle."""
        state_file = tmp_path / "drift_state.json"

        # Create and save
        tracker1 = DriftTracker(state_file)
        event = DriftEvent(
            event_id="persist-001",
            category="schema",
            severity="error",
            title="Schema drift",
            description="Schema changed",
        )
        tracker1.add_event(event)

        # Load in new tracker instance
        tracker2 = DriftTracker(state_file)
        retrieved = tracker2.get_event("persist-001")

        assert retrieved is not None
        assert retrieved.category == "schema"
        assert retrieved.severity == "error"

    def test_resolve_event(self, tmp_path):
        """Test marking event as resolved."""
        state_file = tmp_path / "drift_state.json"
        tracker = DriftTracker(state_file)

        event = DriftEvent(
            event_id="resolve-001",
            category="config",
            severity="warning",
            title="Test drift",
            description="Test description",
        )
        tracker.add_event(event)

        result = tracker.resolve_event("resolve-001")

        assert result is True
        resolved_event = tracker.get_event("resolve-001")
        assert resolved_event.resolved is True
        assert resolved_event.resolved_at is not None

    def test_get_active_events(self, tmp_path):
        """Test filtering to active (unresolved) events."""
        state_file = tmp_path / "drift_state.json"
        tracker = DriftTracker(state_file)

        # Add two events
        for i, resolved in enumerate([False, True]):
            event = DriftEvent(
                event_id=f"active-{i}",
                category="config",
                severity="warning",
                title=f"Drift {i}",
                description="Description",
                resolved=resolved,
            )
            tracker.add_event(event)

        active = tracker.get_active_events()

        assert len(active) == 1
        assert active[0].event_id == "active-0"

    def test_cooldown_check(self, tmp_path):
        """Test cooldown period for recently closed events."""
        state_file = tmp_path / "drift_state.json"
        tracker = DriftTracker(state_file)

        event = DriftEvent(
            event_id="cooldown-001",
            category="config",
            severity="warning",
            title="Test drift",
            description="Test description",
        )
        tracker.add_event(event)
        tracker.resolve_event("cooldown-001")

        # Should be in cooldown (just resolved)
        assert tracker.is_in_cooldown("cooldown-001", cooldown_hours=24.0) is True

        # Should not be in cooldown with 0 hour window
        assert tracker.is_in_cooldown("cooldown-001", cooldown_hours=0.0) is False

    def test_reopen_event(self, tmp_path):
        """Test reopening a resolved event."""
        state_file = tmp_path / "drift_state.json"
        tracker = DriftTracker(state_file)

        event = DriftEvent(
            event_id="reopen-001",
            category="config",
            severity="warning",
            title="Test drift",
            description="Test description",
        )
        tracker.add_event(event)
        tracker.resolve_event("reopen-001")
        tracker.reopen_event("reopen-001")

        reopened = tracker.get_event("reopen-001")
        assert reopened.resolved is False
        assert reopened.resolved_at is None

    def test_prune_old_closed_issues(self, tmp_path):
        """Test that old closed issues are pruned."""
        state_file = tmp_path / "drift_state.json"
        tracker = DriftTracker(state_file)

        # Manually add old closed issue
        old_time = datetime.now(timezone.utc) - timedelta(days=40)
        tracker._closed_issues["old-event"] = old_time

        # Save should trigger pruning
        tracker.save_state()

        # Old entry should be removed
        assert "old-event" not in tracker._closed_issues


# -----------------------------------------------------------------------------
# DriftDetector Tests
# -----------------------------------------------------------------------------

class TestDriftDetector:
    """Tests for git-based drift detection."""

    def test_matches_patterns_json(self, tmp_path):
        """Test pattern matching for JSON files."""
        detector = DriftDetector(tmp_path)

        assert detector._matches_patterns("config.json") is True
        assert detector._matches_patterns("src/settings.yaml") is True
        assert detector._matches_patterns("main.py") is False

    def test_matches_patterns_env(self, tmp_path):
        """Test pattern matching for env files."""
        detector = DriftDetector(tmp_path)

        assert detector._matches_patterns(".env") is True
        assert detector._matches_patterns(".env.local") is True
        assert detector._matches_patterns("README.md") is False

    def test_generate_event_id_stable(self, tmp_path):
        """Test that event IDs are stable for same input."""
        detector = DriftDetector(tmp_path)

        id1 = detector._generate_event_id("config.json", "config_change")
        id2 = detector._generate_event_id("config.json", "config_change")

        assert id1 == id2

    def test_generate_event_id_unique(self, tmp_path):
        """Test that event IDs differ for different inputs."""
        detector = DriftDetector(tmp_path)

        id1 = detector._generate_event_id("config.json", "config_change")
        id2 = detector._generate_event_id("settings.yaml", "config_change")

        assert id1 != id2

    @patch("subprocess.run")
    def test_get_changed_files(self, mock_run, tmp_path):
        """Test getting changed files from git."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="config.json\npyproject.toml\nsrc/main.py\n",
        )

        detector = DriftDetector(tmp_path)
        files = detector.get_changed_files()

        assert len(files) == 3
        assert "config.json" in files

    @patch("subprocess.run")
    def test_detect_config_drift(self, mock_run, tmp_path):
        """Test config drift detection."""
        # Mock git diff --name-only
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="config.json\nmain.py\n"),
            MagicMock(returncode=0, stdout="+new_value\n-old_value\n"),
        ]

        detector = DriftDetector(tmp_path)
        events = detector.detect_config_drift()

        # Should detect config.json but not main.py
        assert len(events) == 1
        assert events[0].category == "config"
        assert "config.json" in events[0].title


# -----------------------------------------------------------------------------
# DriftMonitor Integration Tests
# -----------------------------------------------------------------------------

class TestDriftMonitor:
    """Integration tests for DriftMonitor."""

    def test_get_status_empty(self, tmp_path):
        """Test status with no events."""
        state_file = tmp_path / "drift_state.json"

        monitor = DriftMonitor(
            repo_path=tmp_path,
            state_path=state_file,
        )

        status = monitor.get_status()

        assert status["active_events"] == 0
        assert status["github_enabled"] is False

    def test_get_status_with_events(self, tmp_path):
        """Test status with tracked events."""
        state_file = tmp_path / "drift_state.json"

        monitor = DriftMonitor(
            repo_path=tmp_path,
            state_path=state_file,
        )

        # Add test event
        event = DriftEvent(
            event_id="status-001",
            category="config",
            severity="warning",
            title="Test drift",
            description="Test description",
        )
        monitor.tracker.add_event(event)

        status = monitor.get_status()

        assert status["active_events"] == 1
        assert status["by_severity"]["warning"] == 1
        assert status["by_category"]["config"] == 1

    @patch.object(DriftDetector, "detect_all_drift")
    def test_run_detection_new_event(self, mock_detect, tmp_path):
        """Test detection adds new events to tracker."""
        state_file = tmp_path / "drift_state.json"

        mock_detect.return_value = [
            DriftEvent(
                event_id="new-001",
                category="config",
                severity="warning",
                title="New drift",
                description="Description",
            )
        ]

        monitor = DriftMonitor(
            repo_path=tmp_path,
            state_path=state_file,
        )

        events = monitor.run_detection()

        assert len(events) == 1
        assert monitor.tracker.get_event("new-001") is not None

    @patch.object(DriftDetector, "detect_all_drift")
    def test_run_detection_resolves_missing(self, mock_detect, tmp_path):
        """Test that undetected events get resolved."""
        state_file = tmp_path / "drift_state.json"

        monitor = DriftMonitor(
            repo_path=tmp_path,
            state_path=state_file,
        )

        # Add existing event
        existing = DriftEvent(
            event_id="existing-001",
            category="config",
            severity="warning",
            title="Existing drift",
            description="Description",
        )
        monitor.tracker.add_event(existing)

        # Detection returns no events (drift resolved)
        mock_detect.return_value = []

        monitor.run_detection()

        # Event should be marked resolved
        resolved_event = monitor.tracker.get_event("existing-001")
        assert resolved_event.resolved is True


# -----------------------------------------------------------------------------
# Thread Safety Tests
# -----------------------------------------------------------------------------

class TestThreadSafety:
    """Tests for thread-safe operations."""

    def test_concurrent_add_events(self, tmp_path):
        """Test adding events from multiple threads."""
        import threading

        state_file = tmp_path / "drift_state.json"
        tracker = DriftTracker(state_file)

        def add_event(event_id: str):
            event = DriftEvent(
                event_id=event_id,
                category="config",
                severity="warning",
                title=f"Event {event_id}",
                description="Description",
            )
            tracker.add_event(event)

        threads = [
            threading.Thread(target=add_event, args=(f"thread-{i}",))
            for i in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All events should be added
        assert len(tracker.get_active_events()) == 10
