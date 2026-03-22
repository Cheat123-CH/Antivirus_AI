# permissions.py
import ctypes
import subprocess
from pathlib import Path

# ----------------------------
# Check if running as Admin
# ----------------------------
def is_admin():
    """Returns True if script is run as Administrator"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# ----------------------------
# Secure quarantine folder
# ----------------------------
def secure_quarantine_folder(folder_path):
    """
    Secure a folder:
      - Administrators & SYSTEM have full control
      - Normal Users cannot modify/delete (read-only)
    """
    folder_path = Path(folder_path)
    folder_path.mkdir(parents=True, exist_ok=True)

    try:
        # Reset permissions quietly
        subprocess.run(["icacls", str(folder_path), "/reset", "/T", "/C"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=True)
        # Remove inheritance quietly
        subprocess.run(["icacls", str(folder_path), "/inheritance:r", "/T", "/C"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=True)
        # Grant full control to Administrators and SYSTEM
        subprocess.run(["icacls", str(folder_path), "/grant", "Administrators:F", "/T", "/C"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=True)
        subprocess.run(["icacls", str(folder_path), "/grant", "SYSTEM:F", "/T", "/C"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=True)
        # Remove Users (normal users cannot modify)
        subprocess.run(["icacls", str(folder_path), "/remove", "Users", "/T", "/C"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=True)

        print(f"Folder secured (Admins & SYSTEM only, Users read-only): {folder_path}")

    except subprocess.CalledProcessError as e:
        print(f"Failed to secure folder: {e}")


# ----------------------------
# Restore file permissions
# ----------------------------
def restore_file_permissions(file_path):
    """Restore permissions for a restored file"""
    file_path = Path(file_path)

    try:
        subprocess.run(["icacls", str(file_path), "/reset", "/C"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=True)
        subprocess.run(["icacls", str(file_path), "/grant", "Administrators:F", "/C"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=True)
        subprocess.run(["icacls", str(file_path), "/grant", "SYSTEM:F", "/C"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=True)
        subprocess.run(["icacls", str(file_path), "/remove", "Users", "/C"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=True)

        print(f"Permissions restored correctly: {file_path}")

    except subprocess.CalledProcessError as e:
        print(f"Failed to restore file permissions: {e}")