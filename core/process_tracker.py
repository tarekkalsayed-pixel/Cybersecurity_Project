import os
import threading
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta

import psutil


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

    def process_snapshot(self, limit: int = 8) -> list[dict]:
        rows = []
        for process in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                info = process.info
                memory = info["memory_info"].rss / (1024 * 1024) if info["memory_info"] else 0
                rows.append(
                    {
                        "pid": info["pid"],
                        "name": info["name"] or "unknown",
                        "cpu": info["cpu_percent"] or 0,
                        "memory_mb": round(memory, 1),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        rows.sort(key=lambda item: (item["cpu"], item["memory_mb"]), reverse=True)
        return rows[:limit]
