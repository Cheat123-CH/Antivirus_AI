import json
import os
from datetime import datetime

# Updated to match your JSON severity levels
STATUS_COLORS = {
    "HIGH": ("#FFECEC", "#D32F2F"),   # Red
    "MEDIUM": ("#FFF3E0", "#E65100"), # Orange
    "LOW": ("#E3F2FD", "#1565C0"),    # Blue
}
def get_activities():
    json_path = os.path.join(os.path.dirname(__file__), "..", "member1_alerts.json")
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
            
        activities = []
        for alert in data.get("alerts", []):
            dt = datetime.strptime(alert["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
            time_label = dt.strftime("%I:%M %p Today")
            
            # (Time, Process, Status, Critical_Flag, Path, RAW_ALERT_DICT)
            activities.append((
                time_label, 
                alert["process_name"], 
                alert["severity"], 
                alert["severity"] == "HIGH", 
                alert.get("file_path", "Unknown Path"),
                alert  # Return the whole dictionary here
            ))
        return activities
    except Exception as e:
        print(f"Error loading alerts: {e}")
        return []