PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    old_path TEXT,
    process_name TEXT,
    pid INTEGER,
    entropy_before REAL,
    entropy_after REAL,
    hash_before TEXT,
    hash_after TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'LOW',
    alert_reason TEXT,
    action_taken TEXT,
    incident_id INTEGER,
    extra_json TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    title TEXT NOT NULL,
    reasons TEXT NOT NULL,
    affected_files_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    action_taken TEXT,
    evidence_path TEXT,
    recovery_status TEXT,
    report_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_risk_score ON events(risk_score);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
