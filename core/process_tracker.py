import os
import threading
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional

import psutil

_SNAPSHOT_REFRESH_SECONDS = 30


class ProcessTracker:
    """
    Student-friendly process attribution helper.

    Reliable per-file process ownership is difficult on Windows without kernel tooling, so
    this tracker uses a safe approximation:
    1. The simulator explicitly registers its own PID while it runs.
    2. The dashboard shows a live process snapshot for operator visibility.
    """

    def __init__(self) -> None:
        self._recent_context = deque(maxlen=128)
        self._lock = threading.Lock()
        self._snapshot_cache: Optional[list] = None
        self._snapshot_ttl = timedelta(seconds=_SNAPSHOT_REFRESH_SECONDS)
        # First scan runs now so the cache is populated before any page loads.
        self._snapshot_cache = self._build_snapshot()
        # Background thread keeps it fresh every 30 seconds after that.
        self._start_background_refresh()

    def register_context(self, process_name: str, pid: int, description: str) -> None:
        with self._lock:
            self._recent_context.append(
                {
                    "timestamp": datetime.utcnow(),
                    "process_name": process_name,
                    "pid": pid,
                    "description": description,
                }
            )

    @contextmanager
    def simulator_activity(self, description: str):
        self.register_context("python-simulator", os.getpid(), description)
        try:
            yield
        finally:
            self.register_context("python-simulator", os.getpid(), "simulator-idle")

    def correlate_recent_process(self, window_seconds: int = 15) -> dict | None:
        cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
        with self._lock:
            for item in reversed(self._recent_context):
                if item["timestamp"] >= cutoff:
                    return {
                        "process_name": item["process_name"],
                        "pid": item["pid"],
                        "description": item["description"],
                    }
        return None

    def _build_snapshot(self, limit: int = 8) -> list[dict]:
        """Scan only recently active processes (cpu_percent > 0)."""
        rows = []
        for process in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                info = process.info
                cpu = info["cpu_percent"] or 0
                if cpu == 0:
                    continue
                memory = info["memory_info"].rss / (1024 * 1024) if info["memory_info"] else 0
                rows.append({
                    "pid":       info["pid"],
                    "name":      info["name"] or "unknown",
                    "cpu":       cpu,
                    "memory_mb": round(memory, 1),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        rows.sort(key=lambda item: (item["cpu"], item["memory_mb"]), reverse=True)
        return rows[:limit]

    def _refresh(self) -> None:
        try:
            fresh = self._build_snapshot()
            with self._lock:
                self._snapshot_cache = fresh
        except Exception:
            pass

    def _start_background_refresh(self) -> None:
        def loop():
            while True:
                self._refresh()
                threading.Event().wait(_SNAPSHOT_REFRESH_SECONDS)
        threading.Thread(target=loop, daemon=True).start()

    def process_snapshot(self, limit: int = 8) -> list[dict]:
        with self._lock:
            return self._snapshot_cache or []
