import threading
from collections import Counter, deque
from datetime import datetime, timedelta

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
    def __init__(self) -> None:
        # The watchdog monitor runs in a background thread, so we need a lock
        # to prevent two events from being analyzed at the same time.
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
        with self._lock:
            now = datetime.utcnow()
            event["dt"] = now
            self.recent_events.append(event)
            self._prune_old_events(now)
            summary = self._build_summary(now)
            assessment = score_behavior(summary)
            assessment["recent_files"] = summary["recent_files"]
            assessment["summary"] = summary
            assessment["trigger_incident"] = self._should_trigger_incident(
                now,
                assessment["severity"],
            )
            self.last_assessment = assessment
            return assessment

    def _prune_old_events(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=MONITOR_WINDOW_SECONDS)
        while self.recent_events and self.recent_events[0]["dt"] < cutoff:
            self.recent_events.popleft()

    def _build_summary(self, now: datetime) -> dict:
        modified_count = 0
        renamed_count = 0
        suspicious_extension_count = 0
        delete_recreate_count = 0
        entropy_spike_count = 0
        recent_files = []
        process_counter = Counter()
        deleted_paths = {}
        unique_paths = set()

        for event in self.recent_events:
            path = event["file_path"]
            unique_paths.add(path)
            recent_files.append(path)

            if event["event_type"] == "modified":
                modified_count += 1
            if event["event_type"] == "renamed":
                renamed_count += 1
            if event["event_type"] == "deleted":
                deleted_paths[path] = event["dt"]
            if event["event_type"] == "created":
                deleted_at = deleted_paths.get(path)
                if deleted_at and (event["dt"] - deleted_at).total_seconds() <= DELETE_RECREATE_WINDOW_SECONDS:
                    delete_recreate_count += 1

            if any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                suspicious_extension_count += 1

            entropy_before = event.get("entropy_before")
            entropy_after = event.get("entropy_after")
            if (
                entropy_before is not None
                and entropy_after is not None
                and entropy_after >= HIGH_ENTROPY_THRESHOLD
                and entropy_after - entropy_before >= ENTROPY_SPIKE_THRESHOLD
            ):
                entropy_spike_count += 1

            process_name = event.get("process_name")
            if process_name:
                process_counter[process_name] += 1

        dominant_process_name = None
        same_process_count = 0
        if process_counter:
            dominant_process_name, same_process_count = process_counter.most_common(1)[0]

        return {
            "total_events": len(self.recent_events),
            "modified_count": modified_count,
            "renamed_count": renamed_count,
            "suspicious_extension_count": suspicious_extension_count,
            "delete_recreate_count": delete_recreate_count,
            "entropy_spike_count": entropy_spike_count,
            "same_process_count": same_process_count,
            "dominant_process_name": dominant_process_name,
            "unique_files": len(unique_paths),
            "window_seconds": MONITOR_WINDOW_SECONDS,
            "recent_files": list(dict.fromkeys(recent_files))[-MAX_RECENT_FILES:],
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _should_trigger_incident(self, now: datetime, severity: str) -> bool:
        if severity != "HIGH":
            return False

        if self.last_incident_at is None:
            self.last_incident_at = now
            return True

        elapsed = (now - self.last_incident_at).total_seconds()
        if elapsed >= INCIDENT_COOLDOWN_SECONDS:
            self.last_incident_at = now
            return True
        return False
