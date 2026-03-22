from quarantine_manager import quarantine_file
import json
from pathlib import Path

def process_member1_json(json_file):
    json_file = Path(json_file)

    if not json_file.exists():
        return

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    updated = False

    for entry in data:
        severity = entry.get("severity")
        artifact = entry.get("artifact", {})
        file_path = artifact.get("file_path")
        file_hash = artifact.get("hash")

        if not file_path:
            continue

        # Only quarantine HIGH severity files that haven't been processed
        if severity == "HIGH" and not entry.get("processed", False):
            success = quarantine_file(
                file_path=file_path,
                file_hash=file_hash
            )

            if success:
                entry["processed"] = True
                updated = True

    if updated:
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)