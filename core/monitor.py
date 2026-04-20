from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core.entropy import file_profile
from core.utils import relative_display_path, utc_now_text


class ProtectedFolderMonitor:
    def __init__(self, protected_folder: Path, callback, process_tracker) -> None:
        self.protected_folder = protected_folder
        self.callback = callback
        self.process_tracker = process_tracker
        self.observer = Observer()
        self.handler = _MonitorHandler(self)
        self.snapshot: dict[Path, dict] = {}
        self.running = False
        self.suppressed = False
        self.protected_folder.mkdir(parents=True, exist_ok=True)

    def build_snapshot(self) -> None:
        self.snapshot = {}
        for file_path in self.protected_folder.rglob("*"):
            if file_path.is_file():
                self.snapshot[file_path.resolve()] = file_profile(file_path)

    def start(self) -> None:
        if self.running:
            return
        self.build_snapshot()
        self.observer.schedule(self.handler, str(self.protected_folder), recursive=True)
        self.observer.start()
        self.running = True

    def stop(self) -> None:
        if not self.running:
            return
        self.observer.stop()
        self.observer.join(timeout=5)
        self.running = False
        self.observer = Observer()
        self.handler = _MonitorHandler(self)

    def handle_created(self, src_path: str) -> None:
        file_path = Path(src_path)
        self._emit_event("created", file_path, None, file_path)

    def handle_modified(self, src_path: str) -> None:
        file_path = Path(src_path)
        self._emit_event("modified", file_path, None, file_path)

    def handle_deleted(self, src_path: str) -> None:
        file_path = Path(src_path)
        self._emit_event("deleted", file_path, None, None)

    def handle_moved(self, src_path: str, dest_path: str) -> None:
        old_path = Path(src_path)
        new_path = Path(dest_path)
        self._emit_event("renamed", new_path, old_path, new_path)

    def _emit_event(
        self,
        event_type: str,
        file_path: Path,
        old_path: Path | None,
        profile_target: Path | None,
    ) -> None:
        resolved_path = file_path.resolve()
        before_profile = None
        if old_path is not None:
            before_profile = self.snapshot.pop(old_path.resolve(), None)
        else:
            before_profile = self.snapshot.get(resolved_path)

        after_profile = file_profile(profile_target) if profile_target else {
            "exists": False,
            "size": 0,
            "entropy": None,
            "sha256": None,
        }

        if after_profile["exists"]:
            self.snapshot[resolved_path] = after_profile
        else:
            self.snapshot.pop(resolved_path, None)

        process_info = self.process_tracker.correlate_recent_process()

        event = {
            "timestamp": utc_now_text(),
            "event_type": event_type,
            "file_path": relative_display_path(self.protected_folder, file_path),
            "old_path": relative_display_path(self.protected_folder, old_path) if old_path else None,
            "process_name": process_info["process_name"] if process_info else None,
            "pid": process_info["pid"] if process_info else None,
            "entropy_before": before_profile["entropy"] if before_profile else None,
            "entropy_after": after_profile["entropy"],
            "hash_before": before_profile["sha256"] if before_profile else None,
            "hash_after": after_profile["sha256"],
            "extra": {
                "size_before": before_profile["size"] if before_profile else None,
                "size_after": after_profile["size"],
            },
        }
        if not self.suppressed:
            self.callback(event)

    def suspend_callbacks(self) -> None:
        self.suppressed = True

    def resume_callbacks(self) -> None:
        self.build_snapshot()
        self.suppressed = False


class _MonitorHandler(FileSystemEventHandler):
    def __init__(self, monitor: ProtectedFolderMonitor) -> None:
        self.monitor = monitor

    def on_created(self, event):
        if not event.is_directory:
            self.monitor.handle_created(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.monitor.handle_modified(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.monitor.handle_deleted(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.monitor.handle_moved(event.src_path, event.dest_path)
