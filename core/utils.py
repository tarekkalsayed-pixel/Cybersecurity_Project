import json
from datetime import datetime
from pathlib import Path


def utc_now_text() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def ensure_within(base_path: Path, target_path: Path) -> Path:
    base_resolved = base_path.resolve()
    target_resolved = target_path.resolve()
    if base_resolved not in target_resolved.parents and target_resolved != base_resolved:
        raise ValueError(f"Unsafe path outside allowed folder: {target_resolved}")
    return target_resolved


def relative_display_path(base_path: Path, target_path: Path) -> str:
    try:
        return str(target_path.resolve().relative_to(base_path.resolve()))
    except ValueError:
        return str(target_path)


def safe_read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return default


def dump_json(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True)
