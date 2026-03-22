from quarantine_manager import QUARANTINE_DIR
from permissions import secure_quarantine_folder
from member1_reader import process_member1_json
from pathlib import Path

if __name__ == "__main__":
    # Secure quarantine folder
    secure_quarantine_folder(QUARANTINE_DIR)

    # Process member1.json
    json_file = Path(__file__).parent / "logs/member1.json"
    process_member1_json(json_file)