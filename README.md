# RansomEye

RansomEye is a safe university-level cybersecurity project that demonstrates ransomware early-warning, explainable alerting, forensic logging, backup recovery, and controlled simulation inside a protected demo folder.

This project is **defensive and educational only**. It does **not** contain real ransomware, destructive malware, persistence, privilege escalation, or harmful encryption logic.

## Project Overview

The lab monitors one protected folder in real time and scores suspicious behavior such as rapid bulk modifications, rename storms, suspicious extension changes, delete-and-recreate patterns, entropy spikes, and repeated activity associated with a recent process context. When the system reaches a high-risk threshold, it preserves evidence and restores clean backup copies.

## Core Features

- Real-time file monitoring with `watchdog`
- Safe ransomware-like behavior scoring from `0` to `100`
- Explainable alerts with human-readable reasons
- SQLite logging for events, incidents, and recovery actions
- Entropy and SHA-256 file profiling
- Backup snapshot creation and full restore workflow
- Safe simulator that only acts inside `protected_folder/`
- Flask dashboard pages for overview, monitor, events, incidents, recovery, simulator, and settings
- Downloadable incident reports in JSON or TXT

## Architecture

### Main components

- `app.py`
  Flask dashboard, API endpoints, and operator actions
- `config.py`
  Central configuration for paths, thresholds, and safety constants
- `core/monitor.py`
  Watches the protected folder and emits normalized file events
- `core/detector.py`
  Tracks recent behavior windows and decides when to trigger incidents
- `core/scorer.py`
  Converts suspicious behaviors into a weighted risk score
- `core/entropy.py`
  Calculates Shannon entropy and SHA-256 hashes
- `core/process_tracker.py`
  Provides a safe approximation for process correlation
- `core/incident_logger.py`
  Stores events, incidents, and recovery actions in SQLite
- `core/backup_manager.py`
  Builds clean backup snapshots and restores files
- `core/recovery.py`
  Preserves evidence and runs recovery actions
- `core/simulator.py`
  Runs safe demo scenarios only inside the protected lab folder
- `core/lab.py`
  Connects all components together

## Folder Structure

```text
RansomEye/
|-- app.py
|-- config.py
|-- requirements.txt
|-- README.md
|-- database/
|   |-- schema.sql
|   `-- events.db
|-- core/
|   |-- __init__.py
|   |-- backup_manager.py
|   |-- detector.py
|   |-- entropy.py
|   |-- incident_logger.py
|   |-- lab.py
|   |-- monitor.py
|   |-- process_tracker.py
|   |-- recovery.py
|   |-- scorer.py
|   |-- simulator.py
|   `-- utils.py
|-- templates/
|   |-- base.html
|   |-- index.html
|   |-- monitor.html
|   |-- events.html
|   |-- incidents.html
|   |-- recovery.html
|   |-- simulator.html
|   |-- settings.html
|   |-- 404.html
|   `-- 500.html
|-- static/
|   |-- style.css
|   `-- app.js
|-- protected_folder/
|-- backup_folder/
|-- demo_files/
`-- evidence/
```

## Detection Logic

The system builds a rolling behavior window and assigns points for suspicious patterns:

- `10+` modified files in a short period
- `5+` rapid renames
- suspicious extensions like `.locked`, `.enc`, `.cry`
- delete followed by recreate
- strong entropy increases after a file change
- repeated events associated with the same recent process context
- many unique files touched in one burst

Risk levels:

- `0-40` = `LOW`
- `41-70` = `MEDIUM`
- `71-100` = `HIGH`

Example explanations:

- `12 files modified within 15 seconds`
- `8 files renamed in rapid succession`
- `5 suspicious extension changes matched patterns like .locked or .enc`
- `python-simulator was linked to 10 rapid file events`

## Safe Simulator

The simulator is intentionally harmless and only works inside `protected_folder/`.

Available scenarios:

- `rename_storm`
  Renames multiple files to add `.locked`
- `entropy_burst`
  Overwrites files with randomized high-entropy content
- `mixed_attack`
  Combines rename, overwrite, and delete/recreate behavior

## Process Correlation Limitation

Reliable per-file process ownership is hard to obtain on Windows without lower-level OS instrumentation. This project uses an honest approximation:

- the safe simulator registers its own process context explicitly
- the dashboard also shows a live process snapshot with `psutil`

This is suitable for a student demo, but it is not a kernel-level EDR.

## Installation

### 1. Open the project in VS Code

Open the `RansomEye` folder in VS Code.

### 2. Activate the virtual environment

If your `.venv` already exists:

```powershell
.\.venv\Scripts\activate
```

If you need to create one:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

## How to Run

```powershell
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## How to Demo the Project

1. Start the Flask app.
2. Open the dashboard home page.
3. Go to `Simulator Control`.
4. Click `Reseed Demo Files` if needed.
5. Run `Rename Storm`, `Entropy Burst`, or `Mixed Attack`.
6. Open `Live Monitor` and `Incidents`.
7. Show that the system explains the alert and restores files from backup after a `HIGH` incident.
8. Open `Backups & Recovery` to show recovery history.

## Database

SQLite data is stored in:

- `database/events.db`

Tables:

- `events`
- `incidents`
- `recovery_log`

## Ethical / Safe Use Disclaimer

- This project is for cybersecurity awareness, defensive monitoring, and university demonstration only.
- It does not create or deploy real ransomware.
- The simulator must only be used on local demo files you control.
- Do not point the protected folder to important personal or system directories.

## Security Considerations

Several defensive security decisions were made in the implementation:

- **Thread safety** — the watchdog file monitor runs in a background thread while Flask serves requests in another. A `threading.Lock` is used in both `DetectionEngine` and `RansomEyeLab` to ensure shared state is never read mid-update.
- **SQL injection prevention** — `update_incident` only allows a fixed whitelist of column names (`status`, `action_taken`, `evidence_path`, `recovery_status`). Any unexpected column name is rejected before it reaches the SQL query.
- **Backup integrity guard** — refreshing the backup is blocked when the system is in `ALERT` or `RECOVERY` state. This prevents accidentally overwriting the clean backup with compromised files during or after a simulated attack.
- **Secret key** — the Flask `SECRET_KEY` is read from an environment variable if available, otherwise a cryptographically random key is generated at startup using `secrets.token_hex`.

## Limitations

- Process attribution is approximate, not exact per-file ownership.
- Watchdog events may vary slightly by platform and editor behavior.
- Recovery restores from the latest clean backup snapshot; it is not a versioned enterprise backup system.
- Entropy-based heuristics are useful for demos but can produce false positives in real environments.

## Presentation Tips

- Add screenshots of the Overview, Live Monitor, Incidents, and Recovery pages.
- Demonstrate one low-risk file change first, then a simulator attack.
- Explain how each rule contributes to the score.
- Highlight the ethical design and the recovery workflow.
