from config import LOW_THRESHOLD, MEDIUM_THRESHOLD


def classify_score(score: int) -> str:
    if score > MEDIUM_THRESHOLD:
        return "HIGH"
    if score > LOW_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def score_behavior(summary: dict) -> dict:
    score = 0
    reasons = []

    modified_count = summary["modified_count"]
    renamed_count = summary["renamed_count"]
    suspicious_extensions = summary["suspicious_extension_count"]
    delete_recreate = summary["delete_recreate_count"]
    entropy_spikes = summary["entropy_spike_count"]
    same_process_count = summary["same_process_count"]
    unique_files = summary["unique_files"]
    window_seconds = summary["window_seconds"]

    if modified_count >= 10:
        points = 25 if modified_count >= 20 else 15
        score += points
        reasons.append(f"{modified_count} files modified within {window_seconds} seconds")

    if renamed_count >= 5:
        points = 25 if renamed_count >= 10 else 15
        score += points
        reasons.append(f"{renamed_count} files renamed in rapid succession")

    if suspicious_extensions:
        points = min(20, suspicious_extensions * 5)
        score += points
        reasons.append(
            f"{suspicious_extensions} suspicious extension change(s) matched patterns like .locked or .enc"
        )

    if delete_recreate:
        points = min(15, delete_recreate * 5)
        score += points
        reasons.append(f"{delete_recreate} delete-and-recreate pattern(s) detected")

    if entropy_spikes:
        points = min(20, entropy_spikes * 6)
        score += points
        reasons.append(f"{entropy_spikes} file(s) showed abnormal entropy spikes")

    if same_process_count >= 6:
        points = 15 if same_process_count < 12 else 20
        score += points
        process_name = summary.get("dominant_process_name") or "single process"
        reasons.append(
            f"{process_name} was linked to {same_process_count} rapid file events"
        )

    if unique_files >= 12 and score < 100:
        score += 10
        reasons.append(f"{unique_files} unique files were touched in a short burst")

    score = min(score, 100)
    severity = classify_score(score)

    if not reasons and summary["total_events"] > 0:
        reasons.append("Activity observed, but it remains below the alert threshold.")

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons,
    }
