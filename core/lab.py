import json
import threading
from pathlib import Path

from config import (
    BACKUP_FOLDER,
    DATABASE_PATH,
    DEMO_FILES_FOLDER,
    EVIDENCE_FOLDER,
    PROTECTED_FOLDER,
    SCHEMA_PATH,
)
from core.backup_manager import BackupManager
from core.detector import DetectionEngine
from core.incident_logger import IncidentLogger
from core.monitor import ProtectedFolderMonitor
from core.process_tracker import ProcessTracker
from core.recovery import RecoveryManager
from core.simulator import SafeRansomwareSimulator
from core.utils import utc_now_text


class RansomEyeLab:
    """
    The central coordinator of the lab. Connects all components together:
    monitor -> detector -> scorer -> incident logger -> recovery manager.
    """

    def __init__(self) -> None:
        self.logger          = IncidentLogger(DATABASE_PATH, SCHEMA_PATH)
        self.process_tracker = ProcessTracker()
        self.backup_manager  = BackupManager(PROTECTED_FOLDER, BACKUP_FOLDER)
        self.recovery_manager = RecoveryManager(
            PROTECTED_FOLDER,
            EVIDENCE_FOLDER,
            self.backup_manager,
            self.logger,
        )
        self.detector  = DetectionEngine()
        self.simulator = SafeRansomwareSimulator(PROTECTED_FOLDER, DEMO_FILES_FOLDER, self.process_tracker)
        self.monitor   = ProtectedFolderMonitor(PROTECTED_FOLDER, self.handle_event, self.process_tracker)

        # Lock protects status/last_recovery from being read mid-update by Flask threads.
        self._lock = threading.Lock()
        self.status        = "WATCHING"
        self.status_detail = "Ready to monitor the protected folder."
        self.last_recovery = None
        self._backup_manifest_count = 0

    def initialize(self) -> None:
        self.simulator.seed_demo_files()
        result = self.backup_manager.refresh_backups()
        self._backup_manifest_count = result["file_count"]
        self.start_monitoring()

    # ------------------------------------------------------------------ #
    # Monitor control                                                      #
    # ------------------------------------------------------------------ #

    def start_monitoring(self) -> str:
        self.monitor.start()
        self.status        = "WATCHING"
        self.status_detail = "Real-time monitoring is active."
        return self.status_detail

    def stop_monitoring(self) -> str:
        self.monitor.stop()
        self.status        = "PAUSED"
        self.status_detail = "Monitoring paused by operator."
        return self.status_detail

    # ------------------------------------------------------------------ #
    # Event handling (called from the watchdog background thread)         #
    # ------------------------------------------------------------------ #

    def handle_event(self, event: dict) -> None:
        """
        Entry point for every file change detected by the monitor.
        Reads like a plain-English summary of what happens on each event:
          1. Analyze the event against recent history.
          2. Update the dashboard status.
          3. If risk is HIGH and cooldown allows it, run full incident response.
          4. Save the event to the database.
        """
        try:
            assessment   = self.detector.analyze_event(event)
            incident_id  = None
            action_taken = "Logged"

            self._update_status(assessment)

            if assessment["trigger_incident"]:
                incident_id, action_taken = self._respond_to_incident(assessment, event)

            self._save_event(event, assessment, incident_id, action_taken)

        except Exception as error:
            with self._lock:
                self.status        = "ALERT"
                self.status_detail = f"Monitor handler error: {error}"
            self.logger.log_recovery_action(None, "event_handler_error", "ERROR", str(error))

    def _update_status(self, assessment: dict) -> None:
        """Update the dashboard status label based on the current risk level."""
        with self._lock:
            if assessment["severity"] == "HIGH":
                self.status        = "ALERT"
                self.status_detail = "; ".join(assessment["reasons"])
            elif assessment["severity"] == "MEDIUM":
                self.status        = "ALERT"
                self.status_detail = "Medium-confidence suspicious behavior detected."
            else:
                if self.status != "RECOVERY":
                    self.status        = "WATCHING"
                    self.status_detail = "Monitoring normal file activity."

    def _respond_to_incident(self, assessment: dict, event: dict) -> tuple[int, str]:
        """
        Full incident response, executed when the risk score crosses HIGH threshold.
        Steps:
          1. Save the incident record to the database.
          2. Stop the simulator so it does not keep damaging files.
          3. Preserve evidence (copy affected files before restoring).
          4. Restore all files from the clean backup.
          5. Close the incident record with the outcome.
          6. Reset the detector so fresh monitoring begins.
        """
        # Step 1: save incident to database
        incident_id = self.logger.create_incident({
            "created_at":    utc_now_text(),
            "severity":      assessment["severity"],
            "risk_score":    assessment["score"],
            "title":         "High-risk ransomware-like activity detected",
            "reasons":       assessment["reasons"],
            "affected_files": assessment["recent_files"],
            "report": {
                "summary": assessment["summary"],
                "event":   {k: v for k, v in event.items() if k != "dt"},
            },
        })

        # Step 2: signal the simulator to stop touching files
        with self._lock:
            self.status = "RECOVERY"
        self.simulator.request_stop()

        # Steps 3 & 4: preserve evidence then restore clean files
        self.monitor.suspend_callbacks()
        try:
            recovery = self.recovery_manager.execute_recovery(incident_id, assessment["recent_files"])
        finally:
            self.monitor.resume_callbacks()

        # Step 5: close the incident record
        action_taken = "Suspicious demo activity stopped, evidence preserved, and clean backup restored"
        self.logger.update_incident(
            incident_id,
            status="CLOSED",
            action_taken=action_taken,
            evidence_path=recovery["evidence_path"],
            recovery_status=recovery["recovery_status"],
        )

        # Step 6: reset the detector and return to normal watching
        with self._lock:
            self.last_recovery = recovery
            self.detector.recent_events.clear()
            self.detector.last_assessment = {
                "score":    0,
                "severity": "LOW",
                "reasons":  ["High-risk activity was contained and files were restored from backup."],
                "recent_files": [],
            }
            self.status        = "WATCHING"
            self.status_detail = "Recovered from the latest high-risk incident."

        return incident_id, action_taken

    def _save_event(self, event: dict, assessment: dict, incident_id, action_taken: str) -> None:
        """Attach risk metadata to the event dict and save it to the database."""
        event["risk_score"]   = assessment["score"]
        event["severity"]     = assessment["severity"]
        event["alert_reason"] = "; ".join(assessment["reasons"])
        event["action_taken"] = action_taken
        event["incident_id"]  = incident_id
        self.logger.log_event(event)

    # ------------------------------------------------------------------ #
    # Dashboard data                                                       #
    # ------------------------------------------------------------------ #

    def dashboard_summary(self) -> dict:
        stats = self.logger.stats()
        with self._lock:
            summary        = self.detector.last_assessment
            status         = self.status
            status_detail  = self.status_detail
            last_recovery  = self.last_recovery

        last_alert = None
        if stats["last_alert"]:
            last_alert = {
                "created_at": stats["last_alert"]["created_at"],
                "title":      stats["last_alert"]["title"],
                "severity":   stats["last_alert"]["severity"],
            }

        return {
            "status":               status,
            "status_detail":        status_detail,
            "protected_folder":     str(PROTECTED_FOLDER),
            "backup_folder":        str(BACKUP_FOLDER),
            "total_events":         stats["total_events"],
            "suspicious_events":    stats["suspicious_events"],
            "total_incidents":      stats["total_incidents"],
            "open_incidents":       stats["open_incidents"],
            "last_alert":           last_alert,
            "current_risk_score":   summary["score"],
            "current_severity":     summary["severity"],
            "explanations":         summary["reasons"],
            "recent_files":         summary["recent_files"],
            "event_type_counts":    stats["event_type_counts"],
            "monitor_running":      self.monitor.running,
            "simulator_active":     self.simulator.active,
            "simulator_last_message": self.simulator.last_message,
            "last_recovery":        last_recovery,
            "process_snapshot":     self.process_tracker.process_snapshot(),
            "backup_manifest_count": self._backup_manifest_count,
        }

    def recent_events(self, limit: int = 100):
        return self.logger.recent_events(limit)

    def incidents(self, limit: int = 50):
        return self.logger.list_incidents(limit)

    def recovery_history(self, limit: int = 25):
        return self.logger.recovery_history(limit)

    def backup_status(self) -> dict:
        manifest = self.backup_manager.manifest()
        return {
            "backup_root":   str(BACKUP_FOLDER),
            "protected_root": str(PROTECTED_FOLDER),
            "manifest":      manifest,
            "file_count":    len(manifest),
        }

    # ------------------------------------------------------------------ #
    # Operator actions                                                     #
    # ------------------------------------------------------------------ #

    def manual_restore(self) -> dict:
        self.status = "RECOVERY"
        self.monitor.suspend_callbacks()
        try:
            result = self.backup_manager.restore_all()
        finally:
            self.monitor.resume_callbacks()
        self.logger.log_recovery_action(
            None, "manual_restore", "SUCCESS",
            f"Operator restored {result['restored_count']} file(s) manually.",
        )
        self.detector.recent_events.clear()
        self.detector.last_assessment = {
            "score": 0, "severity": "LOW",
            "reasons": ["Manual restore completed and the alert window was reset."],
            "recent_files": [],
        }
        self.status        = "WATCHING"
        self.status_detail = "Manual restore completed."
        return result

    def refresh_backups(self) -> dict:
        # Block refresh during an attack so the clean backup is not overwritten.
        with self._lock:
            current_status = self.status
        if current_status in ("ALERT", "RECOVERY"):
            raise ValueError(
                "Backup refresh blocked: the system is currently in ALERT or RECOVERY. "
                "Wait until the status returns to WATCHING so you don't overwrite the clean backup."
            )
        result = self.backup_manager.refresh_backups()
        self._backup_manifest_count = result["file_count"]
        self.logger.log_recovery_action(
            None, "refresh_backups", "SUCCESS",
            f"Refreshed clean backup set with {result['file_count']} file(s).",
        )
        return result

    def seed_demo_files(self) -> dict:
        self.monitor.suspend_callbacks()
        try:
            result        = self.simulator.seed_demo_files()
            backup_result = self.backup_manager.refresh_backups()
            self._backup_manifest_count = backup_result["file_count"]
        finally:
            self.monitor.resume_callbacks()
        return result

    def run_simulator(self, scenario: str) -> dict:
        return self.simulator.run_async(scenario)

    def clear_logs(self) -> None:
        self.logger.clear_all()
        self.detector.last_assessment = {
            "score": 0, "severity": "LOW",
            "reasons": ["Logs cleared. Monitoring remains active."],
            "recent_files": [],
        }

    def incident_report(self, incident_id: int) -> dict | None:
        row = self.logger.get_incident(incident_id)
        if row is None:
            return None
        return {
            "id":              row["id"],
            "created_at":      row["created_at"],
            "severity":        row["severity"],
            "risk_score":      row["risk_score"],
            "title":           row["title"],
            "reasons":         row["reasons"].splitlines(),
            "status":          row["status"],
            "action_taken":    row["action_taken"],
            "evidence_path":   row["evidence_path"],
            "recovery_status": row["recovery_status"],
            "affected_files":  json.loads(row["affected_files_json"]),
            "report":          json.loads(row["report_json"]),
        }

    def shutdown(self) -> None:
        self.monitor.stop()