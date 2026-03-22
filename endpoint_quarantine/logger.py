from pathlib import Path
import json
from datetime import datetime

BASE_DIR = Path(__file__).parent

QUARANTINE_LOG_FILE = BASE_DIR / "logs/quarantine_log.json"
RESTORE_LOG_FILE = BASE_DIR / "logs/restore_log.json"

# Ensure log files exist
for log_file in [QUARANTINE_LOG_FILE, RESTORE_LOG_FILE]:
    if not log_file.exists():
        log_file.write_text("[]", encoding="utf-8")


def _append_log(file, entry):
    try:
        with open(file, "r+", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []

            logs.append(entry)

            f.seek(0)
            json.dump(logs, f, indent=4)
            f.truncate()

    except Exception as e:
        print(f"Logging error: {e}")


def log_quarantine(file_name, reason, file_hash, file_size, user_account):
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": "QUARANTINED",
        "file_name": file_name,
        "reason": reason,
        "hash": file_hash,
        "size": file_size,
        "user_account": user_account
    }

    _append_log(QUARANTINE_LOG_FILE, entry)


def log_restore(file_name, restored_to):
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": "RESTORED",
        "file_name": file_name,
        "restored_to": str(restored_to)
    }

    _append_log(RESTORE_LOG_FILE, entry)