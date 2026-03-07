def get_activities():
    activities = [
        ("2:34 PM Today",  "invoice_2024.exe",   "Quarantined", True),
        ("1:15 PM Today",  "report.docx",         "Suspicious",  False),
        ("11:42 AM Today", "update_patch.msi",    "Low",         False),
    ]*8
    return activities

STATUS_COLORS = {
    "Quarantined": ("#FFECEC", "#D32F2F"),  # red
    "Suspicious":  ("#FFF3E0", "#E65100"),  # orange
    "Low":         ("#E3F2FD", "#1565C0"),  # blue
}
