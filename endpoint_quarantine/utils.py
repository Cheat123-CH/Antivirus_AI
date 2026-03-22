from pathlib import Path
import hashlib


def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_file_size(file_path):
    """
    Return file size in bytes
    """
    return Path(file_path).stat().st_size


def ensure_folder(folder_path):
    folder = Path(folder_path)
    folder.mkdir(parents=True, exist_ok=True)
    return folder