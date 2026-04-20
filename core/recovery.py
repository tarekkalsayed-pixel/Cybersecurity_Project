import shutil
from pathlib import Path

from core.utils import dump_json, ensure_within, utc_now_text


class RecoveryManager:
    def __init__(self, protected_folder: Path, evidence_folder: Path, backup_manager, logger):
        self.protected_folder = protected_folder
        self.evidence_folder = evidence_folder
        self.backup_manager = backup_manager
        self.logger = logger
        self.evidence_folder.mkdir(parents=True, exist_ok=True)

    def preserve_evidence(self, incident_id: int, affected_files: list[str]) -> Path:
        target_dir = self.evidence_folder / f"incident_{incident_id}"
        target_dir.mkdir(parents=True, exist_ok=True)

        copied_files = []
        for relative_name in affected_files:
            source_path = ensure_within(self.protected_folder, self.protected_folder / relative_name)
            if source_path.exists() and source_path.is_file():
                evidence_file = target_dir / relative_name
                evidence_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, evidence_file)
                copied_files.append(relative_name)

        summary_path = target_dir / "evidence_summary.json"
        summary_path.write_text(
            dump_json(
                {
                    "incident_id": incident_id,
                    "preserved_at": utc_now_text(),
                    "copied_files": copied_files,
                }
            ),
            encoding="utf-8",
        )
        return target_dir

    def execute_recovery(self, incident_id: int, affected_files: list[str]) -> dict:
        evidence_dir = self.preserve_evidence(incident_id, affected_files)
        restore_result = self.backup_manager.restore_all()
        self.logger.log_recovery_action(
            incident_id,
            "restore_all",
            "SUCCESS",
            f"Restored {restore_result['restored_count']} file(s) from clean backup.",
        )
        return {
            "evidence_path": str(evidence_dir),
            "restore_result": restore_result,
            "recovery_status": "Recovered from clean backup",
        }
