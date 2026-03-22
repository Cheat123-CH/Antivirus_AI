# process.py
import psutil
from pathlib import Path

def terminate_process_by_file(file_path):
    """
    Kill any process running the specified file
    Works for both normal and admin processes (if script runs as admin)
    """

    file_path = str(Path(file_path).resolve())
    found = False

    for proc in psutil.process_iter(['pid', 'name', 'exe']):

        try:
            exe = proc.info['exe']

            if exe and str(Path(exe).resolve()) == file_path:

                print(f"Terminating process: {proc.info['name']} (PID {proc.pid})")

                # Try graceful termination
                proc.terminate()

                try:
                    proc.wait(timeout=3)

                except psutil.TimeoutExpired:
                    print("Force killing process...")
                    proc.kill()

                found = True

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not found:
        print("No running process found.")