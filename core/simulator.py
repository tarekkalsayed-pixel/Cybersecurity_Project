import os
import shutil
import threading
import time
from pathlib import Path

from config import ALLOWED_SIMULATOR_SCENARIOS
from core.utils import ensure_within, relative_display_path


class SafeRansomwareSimulator:
    def __init__(self, protected_folder: Path, demo_files_folder: Path, process_tracker):
        self.protected_folder = protected_folder
        self.demo_files_folder = demo_files_folder
        self.process_tracker = process_tracker
        self.active = False
        self.stop_requested = False
        self._stop_event = threading.Event()
        self.last_message = "Idle"
        self.last_run = None
        self.protected_folder.mkdir(parents=True, exist_ok=True)
        self.demo_files_folder.mkdir(parents=True, exist_ok=True)

    def seed_demo_files(self) -> dict:
        for item in self.protected_folder.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink(missing_ok=True)

        copied = []
        for source_file in sorted(self.demo_files_folder.rglob("*")):
            if not source_file.is_file():
                continue
            relative_path = source_file.relative_to(self.demo_files_folder)
            target_path = ensure_within(self.protected_folder, self.protected_folder / relative_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target_path)
            copied.append(relative_display_path(self.protected_folder, target_path))

        self.last_message = f"Seeded {len(copied)} demo files into the protected folder."
        return {"copied_files": copied, "message": self.last_message}

    def run_async(self, scenario: str) -> dict:
        if scenario not in ALLOWED_SIMULATOR_SCENARIOS:
            raise ValueError("Unsupported simulator scenario.")
        if self.active:
            return {"started": False, "message": "Simulator is already running."}

        self.stop_requested = False
        self._stop_event.clear()
        worker = threading.Thread(target=self._run, args=(scenario,), daemon=True)
        worker.start()
        return {"started": True, "message": f"Started simulator scenario: {scenario}"}

    def _run(self, scenario: str) -> None:
        self.active = True
        self.last_run = scenario
        self.last_message = f"Running {scenario}"

        try:
            with self.process_tracker.simulator_activity(f"simulator:{scenario}"):
                if scenario == "rename_storm":
                    self._rename_storm()
                elif scenario == "entropy_burst":
                    self._entropy_burst()
                elif scenario == "mixed_attack":
                    self._mixed_attack()
            self.last_message = (
                f"Scenario stopped safely: {scenario}"
                if self.stop_requested
                else f"Scenario completed: {scenario}"
            )
        except Exception as error:
            self.last_message = f"Scenario failed: {error}"
        finally:
            self.active = False

    def request_stop(self) -> None:
        self.stop_requested = True
        self._stop_event.set()  # wake the simulator instantly from any sleep

    def wait_until_stopped(self, timeout: float = 3.0) -> None:
        """Block until the simulator finishes its current file operation."""
        deadline = time.time() + timeout
        while self.active and time.time() < deadline:
            time.sleep(0.05)

    def _should_stop(self) -> bool:
        return self.stop_requested

    def _target_files(self) -> list[Path]:
        return [path for path in sorted(self.protected_folder.rglob("*")) if path.is_file()]

    def _write_retry(self, file_path: Path, content: str) -> None:
        for _ in range(5):
            try:
                ensure_within(self.protected_folder, file_path).write_text(content, encoding="utf-8")
                return
            except PermissionError:
                time.sleep(0.15)
        raise PermissionError(f"Unable to write demo file: {file_path}")

    def _rename_retry(self, source_path: Path, target_path: Path) -> None:
        for _ in range(5):
            try:
                safe_target = ensure_within(self.protected_folder, target_path)
                if safe_target.exists():
                    safe_target.unlink(missing_ok=True)
                ensure_within(self.protected_folder, source_path).rename(
                    safe_target
                )
                return
            except PermissionError:
                time.sleep(0.2)
        raise PermissionError(f"Unable to rename demo file: {source_path}")

    def _rename_storm(self) -> None:
        for file_path in self._target_files()[:8]:
            if self._should_stop():
                break
            locked_path = ensure_within(
                self.protected_folder,
                file_path.with_name(f"{file_path.name}.locked"),
            )
            if file_path.exists():
                self._rename_retry(file_path, locked_path)
                self._stop_event.wait(0.15)

    def _entropy_burst(self) -> None:
        for file_path in self._target_files()[:12]:
            if self._should_stop():
                break
            random_text = os.urandom(2048).hex()
            self._write_retry(file_path, random_text)
            self._stop_event.wait(0.1)

    def _mixed_attack(self) -> None:
        for index, file_path in enumerate(self._target_files()[:14]):
            if self._should_stop():
                break
            safe_path = ensure_within(self.protected_folder, file_path)
            self._write_retry(safe_path, os.urandom(1536).hex())
            self._stop_event.wait(0.16)
            if index % 2 == 0:
                renamed = ensure_within(
                    self.protected_folder,
                    safe_path.with_name(f"{safe_path.stem}_recovered_copy{safe_path.suffix}.enc"),
                )
                self._rename_retry(safe_path, renamed)
            else:
                safe_path.unlink(missing_ok=True)
                time.sleep(0.05)
                self._write_retry(safe_path, "SIMULATED_OVERWRITE_" + os.urandom(512).hex())
