import shutil
from pathlib import Path

from core.entropy import sha256_file
from core.utils import ensure_within, relative_display_path


class BackupManager:
    def __init__(self, protected_folder: Path, backup_folder: Path) -> None:
        self.protected_folder = protected_folder
        self.backup_folder = backup_folder
        self.protected_folder.mkdir(parents=True, exist_ok=True)
        self.backup_folder.mkdir(parents=True, exist_ok=True)

    def _protected_files(self) -> list[Path]:
        return sorted(path for path in self.protected_folder.rglob("*") if path.is_file())

    def refresh_backups(self) -> dict:
        if self.backup_folder.exists():
            for item in self.backup_folder.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()

        file_count = 0
        for source_file in self._protected_files():
            relative_path = source_file.relative_to(self.protected_folder)
            target_file = self.backup_folder / relative_path
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target_file)
            file_count += 1

        return {
            "file_count": file_count,
            "backup_root": str(self.backup_folder),
        }

    def restore_all(self) -> dict:
        restored_files = []
        expected_files = set()

        for backup_file in sorted(self.backup_folder.rglob("*")):
            if not backup_file.is_file():
                continue

            relative_path = backup_file.relative_to(self.backup_folder)
            expected_files.add(relative_path)
            target_file = ensure_within(self.protected_folder, self.protected_folder / relative_path)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_file, target_file)
            restored_files.append(relative_display_path(self.protected_folder, target_file))

        for protected_file in self._protected_files():
            relative_path = protected_file.relative_to(self.protected_folder)
            if relative_path not in expected_files:
                protected_file.unlink(missing_ok=True)

        return {
            "restored_count": len(restored_files),
            "restored_files": restored_files,
        }

    def manifest(self) -> list[dict]:
        manifest_rows = []
        for file_path in sorted(self.backup_folder.rglob("*")):
            if file_path.is_file():
                manifest_rows.append(
                    {
                        "relative_path": str(file_path.relative_to(self.backup_folder)),
                        "sha256": sha256_file(file_path),
                        "size": file_path.stat().st_size,
                    }
                )
        return manifest_rows
