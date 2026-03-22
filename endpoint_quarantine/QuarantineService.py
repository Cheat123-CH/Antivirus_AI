import time
import win32serviceutil
import win32service
import win32event
import servicemanager
from member1_reader import process_member1_json
from pathlib import Path

JSON_FILE = Path(__file__).resolve().parent / "logs/member1.json"

class QuarantineService(win32serviceutil.ServiceFramework):
    _svc_name_ = "EndpointQuarantineService"
    _svc_display_name_ = "Endpoint Protection Quarantine Service"
    _svc_description_ = "Automatically quarantines high-risk files detected by Member 1."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        while self.running:
            try:
                if JSON_FILE.exists():
                    process_member1_json(JSON_FILE)
            except Exception as e:
                print(f"Error processing JSON: {e}")
            time.sleep(5)

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(QuarantineService)