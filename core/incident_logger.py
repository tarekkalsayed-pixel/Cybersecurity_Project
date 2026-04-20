import json
import sqlite3
import threading
from pathlib import Path

from core.utils import dump_json, utc_now_text


class IncidentLogger:
    def __init__(self, database_path: Path, schema_path: Path) -> None:
        self.database_path = database_path
        self.schema_path = schema_path
        self._lock = threading.Lock()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize_database(self) -> None:
        schema = self.schema_path.read_text(encoding="utf-8")
        with self._connect() as connection:
            connection.executescript(schema)
            connection.commit()

    def log_event(self, event: dict) -> int:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO events (
                    timestamp,
                    event_type,
                    file_path,
                    old_path,
                    process_name,
                    pid,
                    entropy_before,
                    entropy_after,
                    hash_before,
                    hash_after,
                    risk_score,
                    severity,
                    alert_reason,
                    action_taken,
                    incident_id,
                    extra_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["timestamp"],
                    event["event_type"],
                    event["file_path"],
                    event.get("old_path"),
                    event.get("process_name"),
                    event.get("pid"),
                    event.get("entropy_before"),
                    event.get("entropy_after"),
                    event.get("hash_before"),
                    event.get("hash_after"),
                    event.get("risk_score", 0),
                    event.get("severity", "LOW"),
                    event.get("alert_reason"),
                    event.get("action_taken"),
                    event.get("incident_id"),
                    json.dumps(event.get("extra", {})),
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def create_incident(self, incident: dict) -> int:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    created_at,
                    severity,
                    risk_score,
                    title,
                    reasons,
                    affected_files_json,
                    status,
                    action_taken,
                    evidence_path,
                    recovery_status,
                    report_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident["created_at"],
                    incident["severity"],
                    incident["risk_score"],
                    incident["title"],
                    "\n".join(incident["reasons"]),
                    dump_json(incident["affected_files"]),
                    incident.get("status", "OPEN"),
                    incident.get("action_taken"),
                    incident.get("evidence_path"),
                    incident.get("recovery_status"),
                    dump_json(incident["report"]),
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def update_incident(self, incident_id: int, **fields) -> None:
        if not fields:
            return
        assignments = ", ".join(f"{key} = ?" for key in fields)
        values = list(fields.values()) + [incident_id]
        with self._lock, self._connect() as connection:
            connection.execute(
                f"UPDATE incidents SET {assignments} WHERE id = ?",
                values,
            )
            connection.commit()

    def log_recovery_action(
        self, incident_id: int | None, action: str, status: str, details: str
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO recovery_log (incident_id, timestamp, action, status, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (incident_id, utc_now_text(), action, status, details),
            )
            connection.commit()

    def recent_events(self, limit: int = 100) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def list_incidents(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def get_incident(self, incident_id: int) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()

    def recovery_history(self, limit: int = 25) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM recovery_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def stats(self) -> dict:
        with self._connect() as connection:
            total_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            suspicious_events = connection.execute(
                "SELECT COUNT(*) FROM events WHERE risk_score > 40"
            ).fetchone()[0]
            total_incidents = connection.execute(
                "SELECT COUNT(*) FROM incidents"
            ).fetchone()[0]
            open_incidents = connection.execute(
                "SELECT COUNT(*) FROM incidents WHERE status != 'CLOSED'"
            ).fetchone()[0]
            last_alert = connection.execute(
                "SELECT created_at, title, severity FROM incidents ORDER BY id DESC LIMIT 1"
            ).fetchone()

            event_type_rows = connection.execute(
                "SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type"
            ).fetchall()

        return {
            "total_events": total_events,
            "suspicious_events": suspicious_events,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "last_alert": last_alert,
            "event_type_counts": {row["event_type"]: row["count"] for row in event_type_rows},
        }

    def clear_all(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM events")
            connection.execute("DELETE FROM incidents")
            connection.execute("DELETE FROM recovery_log")
            connection.commit()
