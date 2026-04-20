import hashlib
import math
from collections import Counter
from pathlib import Path


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None

    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_profile(path: Path) -> dict:
    if not path.exists() or not path.is_file():
        return {
            "exists": False,
            "size": 0,
            "entropy": None,
            "sha256": None,
        }

    data = path.read_bytes()
    return {
        "exists": True,
        "size": len(data),
        "entropy": calculate_entropy(data),
        "sha256": sha256_file(path),
    }
