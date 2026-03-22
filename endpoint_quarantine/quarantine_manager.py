# quarantine_manager.py
from pathlib import Path
import shutil
import getpass
from datetime import datetime
import json
from permissions import restore_file_permissions, secure_quarantine_folder, is_admin
from logger import log_quarantine, log_restore
from process import terminate_process_by_file
from utils import get_file_size

# ----------------------------
# Quarantine folder path
# ----------------------------
QUARANTINE_DIR = Path("C:/ProgramData/EndpointSecurity/Quarantine")
CURRENT_QUARANTINE_FILE = Path(__file__).parent / "logs/current_quarantine.json"

# ----------------------------
# Update current_quarantine.json
# ----------------------------
def update_current_quarantine(entry, add=True):
    current = []
    if CURRENT_QUARANTINE_FILE.exists():
        try:
            with open(CURRENT_QUARANTINE_FILE, "r", encoding="utf-8") as f:
                current = json.load(f)
        except:
            current = []

    if add:
        current.append(entry)
    else:
        # Remove by exact quarantine file name
        current = [e for e in current if e.get("file_name") != entry.get("file_name")]

    with open(CURRENT_QUARANTINE_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=4)

# ----------------------------
# Get unique quarantine file path
# ----------------------------
def get_unique_quarantine_path(original_name):
    stem = Path(original_name).stem
    suffix = Path(original_name).suffix
    counter = 0
    while True:
        if counter == 0:
            dest_name = f"{original_name}.quarantine"
        else:
            dest_name = f"{stem} ({counter}){suffix}.quarantine"
        dest_path = QUARANTINE_DIR / dest_name
        if not dest_path.exists():
            return dest_path
        counter += 1

# ----------------------------
# Quarantine file
# ----------------------------
def quarantine_file(file_path, file_hash):
    file_path = Path(file_path)

    # Ensure quarantine folder exists (silent, no print)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    secure_quarantine_folder(QUARANTINE_DIR)

    if not file_path.exists():
        print("File not found")
        return False

    # Terminate process (even admin)
    terminate_process_by_file(file_path)

    # Metadata
    file_size = get_file_size(file_path)
    user_account = getpass.getuser()

    # Determine unique quarantine path
    dest_path = get_unique_quarantine_path(file_path.name)

    try:
        # Move file to quarantine folder
        shutil.move(str(file_path), str(dest_path))

        # Log quarantine
        log_quarantine(
            file_name=file_path.name,
            reason="HIGH-RISK FILE",
            file_hash=file_hash,
            file_size=file_size,
            user_account=user_account
        )

        # Update current_quarantine.json
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_name": dest_path.name,       # unique .quarantine file
            "file_path": str(dest_path),
            "original_path": str(file_path),   # exact original path
            "hash": file_hash,
            "size": file_size,
            "user_account": user_account,
            "reason": "HIGH-RISK FILE"
        }
        update_current_quarantine(entry, add=True)

        print(f"File quarantined: {dest_path}")
        return True

    except Exception as e:
        print(f"Error moving file: {e}")
        return False

# ----------------------------
# Restore file (Admin only)
# ----------------------------
def restore_file(file_name_in_quarantine):
    if not is_admin():
        print("Only administrators can restore files!")
        return False

    if not CURRENT_QUARANTINE_FILE.exists():
        print("No quarantine records found!")
        return False

    # Load current quarantine JSON
    try:
        with open(CURRENT_QUARANTINE_FILE, "r", encoding="utf-8") as f:
            current = json.load(f)
    except:
        current = []

    # Find entry by exact quarantine file name
    entry = next((e for e in current if e["file_name"] == file_name_in_quarantine), None)
    if not entry:
        print(f"Quarantined file '{file_name_in_quarantine}' record not found!")
        return False

    quarantine_path = Path(entry["file_path"])
    original_path = Path(entry["original_path"])
    original_dir = original_path.parent
    original_dir.mkdir(parents=True, exist_ok=True)

    # Restore using the exact original name from quarantine
    dest_path = original_path  # start with original path

    # Only auto-rename if **that exact name already exists** in original path
    counter = 1
    while dest_path.exists():
        dest_path = original_dir / f"{original_path.stem} ({counter}){original_path.suffix}"
        counter += 1

    try:
        shutil.move(str(quarantine_path), str(dest_path))
        restore_file_permissions(dest_path)

        log_restore(entry["file_name"], dest_path)
        update_current_quarantine({"file_name": entry["file_name"]}, add=False)

        print(f"File restored to: {dest_path}")
        return True

    except Exception as e:
        print(f"Restore failed for {entry['file_name']}: {e}")
        return False