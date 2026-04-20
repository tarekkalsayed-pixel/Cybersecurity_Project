from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_DIR = BASE_DIR / "database"
DATABASE_PATH = DATABASE_DIR / "events.db"
SCHEMA_PATH = DATABASE_DIR / "schema.sql"

PROTECTED_FOLDER = BASE_DIR / "protected_folder"
BACKUP_FOLDER = BASE_DIR / "backup_folder"
DEMO_FILES_FOLDER = BASE_DIR / "demo_files"
EVIDENCE_FOLDER = BASE_DIR / "evidence"

MONITOR_WINDOW_SECONDS = 15
DELETE_RECREATE_WINDOW_SECONDS = 4
INCIDENT_COOLDOWN_SECONDS = 20
MAX_RECENT_EVENTS = 300
MAX_RECENT_FILES = 12

SUSPICIOUS_EXTENSIONS = {".locked", ".enc", ".cry", ".crypted", ".encrypted"}
SUSPICIOUS_KEYWORDS = {"locked", "decrypt", "readme", "restore", "recover", "payment"}
ENTROPY_SPIKE_THRESHOLD = 1.2
HIGH_ENTROPY_THRESHOLD = 5.2

LOW_THRESHOLD = 40
MEDIUM_THRESHOLD = 70

ALLOWED_SIMULATOR_SCENARIOS = {"rename_storm", "entropy_burst", "mixed_attack"}


class FlaskConfig:
    SECRET_KEY = "ransomeye-ethical-lab"
    MAX_CONTENT_LENGTH = 4 * 1024 * 1024
