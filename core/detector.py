import threading
from collections import Counter, deque
from datetime import datetime, timedelta, timezone

from config import (
    DELETE_RECREATE_WINDOW_SECONDS,
    ENTROPY_SPIKE_THRESHOLD,
    HIGH_ENTROPY_THRESHOLD,
    INCIDENT_COOLDOWN_SECONDS,
    MAX_RECENT_EVENTS,
    MAX_RECENT_FILES,
    MONITOR_WINDOW_SECONDS,
    SUSPICIOUS_EXTENSIONS,
)
from core.scorer import score_behavior


class DetectionEngine:
    """
    Watches a rolling window of recent file events and produces a risk assessment.
    Every new file event is scored against the history of the last 15 seconds.
    """

    def __init__(self) -> None:
        # Lock is needed because the file monitor fires events from a background thread.
        self._lock = threading.Lock()
        self.recent_events = deque(maxlen=MAX_RECENT_EVENTS)
        self.last_incident_at = None
        self.last_assessment = {
            "score": 0,
            "severity": "LOW",
            "reasons": ["System initialized and watching for events."],
            "recent_files": [],
        }

    def analyze_event(self, event: dict) -> dict:
        """Add a new file event and return an updated risk assessment."""
        with self._lock:
            event["dt"] = datetime.now(timezone.utc)
            self.recent_events.append(event)
            self._drop_expired_events()

            summary = self._build_summary()
            assessment = score_behavior(summary)
            assessment["recent_files"] = summary["recent_files"]
            assessment["summary"] = summary
            assessment["trigger_incident"] = self._cooldown_allows_incident(assessment["severity"])
            self.last_assessment = assessment
            return assessment

    def _drop_expired_events(self) -> None:
        """Remove events older than the monitoring window (default: 15 seconds)."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=MONITOR_WINDOW_SECONDS)
        while self.recent_events and self.recent_events[0]["dt"] < cutoff:
            self.recent_events.popleft()

    def _build_summary(self) -> dict:
        """
        Loop through all recent events and count each suspicious signal.
        Each counter below maps to one scoring rule in scorer.py.
        """
        now = datetime.now(timezone.utc)

        modified_count        = 0  # Signal: many files modified rapidly
        renamed_count         = 0  # Signal: many files renamed (e.g. file.txt -> file.txt.locked)
        suspicious_ext_count  = 0  # Signal: file got a ransomware-like extension
        delete_recreate_count = 0  # Signal: file deleted then recreated (encrypt-in-place trick)
        entropy_spike_count   = 0  # Signal: file content became highly random (= encrypted)
        process_counter       = Counter()  # Which process caused the most events?
        deleted_paths         = {}  # Tracks deleted paths to detect the delete-recreate pattern
        unique_paths          = set()
        recent_files          = []

        for event in self.recent_events:
            path       = event["file_path"]
            event_type = event["event_type"]
            unique_paths.add(path)
            recent_files.append(path)

            # --- Count basic event types ---
            if event_type == "modified":
                modified_count += 1
            elif event_type == "renamed":
                renamed_count += 1
            elif event_type == "deleted":
                # Remember when this path was deleted so we can detect if it comes back.
                deleted_paths[path] = event["dt"]
            elif event_type == "created":
                # If the same path was deleted moments ago and is now recreated, that is
                # a classic ransomware encrypt-in-place pattern.
                deleted_at = deleted_paths.get(path)
                if deleted_at and (event["dt"] - deleted_at).total_seconds() <= DELETE_RECREATE_WINDOW_SECONDS:
                    delete_recreate_count += 1

            # --- Check for ransomware-like file extensions (.locked, .enc, .cry ...) ---
            if any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                suspicious_ext_count += 1

            # --- Check for entropy spike (file content randomness jumped = likely encrypted) ---
            entropy_before = event.get("entropy_before")
            entropy_after  = event.get("entropy_after")
            if (
                entropy_before is not None
                and entropy_after is not None
                and entropy_after >= HIGH_ENTROPY_THRESHOLD
                and entropy_after - entropy_before >= ENTROPY_SPIKE_THRESHOLD
            ):
                entropy_spike_count += 1

            # --- Track which process is linked to the most file events ---
            process_name = event.get("process_name")
            if process_name:
                process_counter[process_name] += 1

        # Find the single process responsible for the most events.
        dominant_process       = None
        dominant_process_count = 0
        if process_counter:
            dominant_process, dominant_process_count = process_counter.most_common(1)[0]

        return {
            "total_events":               len(self.recent_events),
            "modified_count":             modified_count,
            "renamed_count":              renamed_count,
            "suspicious_extension_count": suspicious_ext_count,
            "delete_recreate_count":      delete_recreate_count,
            "entropy_spike_count":        entropy_spike_count,
            "same_process_count":         dominant_process_count,
            "dominant_process_name":      dominant_process,
            "unique_files":               len(unique_paths),
            "window_seconds":             MONITOR_WINDOW_SECONDS,
            "recent_files":               list(dict.fromkeys(recent_files))[-MAX_RECENT_FILES:],
            "timestamp":                  now.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _cooldown_allows_incident(self, severity: str) -> bool:
        """
        Returns True only when severity is HIGH and enough time has passed
        since the last incident. This prevents repeated alerts during one attack.
        """
        if severity != "HIGH":
            return False

        now = datetime.now(timezone.utc)

        if self.last_incident_at is None:
            self.last_incident_at = now
            return True

        seconds_since_last_incident = (now - self.last_incident_at).total_seconds()
        if seconds_since_last_incident >= INCIDENT_COOLDOWN_SECONDS:
            self.last_incident_at = now
            return True

        return False