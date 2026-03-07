import tkinter as tk
import customtkinter as ctk
from datetime import datetime
import random
import threading
import time

ctk.set_appearance_mode("light")

# ── Palette ──────────────────────────────────────────────────────────────────
BG        = "#F7F8FC"
WHITE     = "#FFFFFF"
BORDER    = "#E4E7EF"
NAV_BG    = "#1A2340"
NAV_SEL   = "#2A3558"
NAV_TEXT  = "#A8B4CC"
NAV_ACT   = "#FFFFFF"
BLUE      = "#2563EB"
BLUE_L    = "#EFF4FF"
RED       = "#EF4444"
RED_L     = "#FEF2F2"
ORANGE    = "#F59E0B"
ORANGE_L  = "#FFFBEB"
GREEN     = "#10B981"
GREEN_L   = "#ECFDF5"
TEXT      = "#0F172A"
TEXT2     = "#64748B"
TEXT3     = "#94A3B8"

FONT_H1   = ("Georgia", 18, "bold")
FONT_H2   = ("Georgia", 13, "bold")
FONT_H3   = ("Georgia", 11, "bold")
FONT_BODY = ("Helvetica", 11)
FONT_SM   = ("Helvetica", 10)
FONT_XS   = ("Helvetica", 9)

# ── Mock Data ─────────────────────────────────────────────────────────────────
DEVICES = [
    {"name": "WS-Prod-01",    "ip": "192.168.1.10",  "os": "Windows 11",  "user": "alice",   "status": "Clean",     "contained": False, "last_seen": "Just now"},
    {"name": "Stewart-PC",    "ip": "192.168.1.11",  "os": "Windows 10",  "user": "stewart", "status": "Threat",    "contained": True,  "last_seen": "2 min ago"},
    {"name": "SharePoint01",  "ip": "192.168.1.20",  "os": "Windows Server 2022", "user": "admin", "status": "Warning", "contained": False, "last_seen": "5 min ago"},
    {"name": "ubuntu-dev",    "ip": "192.168.1.30",  "os": "Ubuntu 22.04","user": "devteam", "status": "Clean",     "contained": False, "last_seen": "1 min ago"},
    {"name": "Jayne-Laptop",  "ip": "192.168.1.12",  "os": "Windows 11",  "user": "jayne",   "status": "Clean",     "contained": False, "last_seen": "3 min ago"},
    {"name": "Tomcat-Server", "ip": "192.168.1.40",  "os": "CentOS 8",    "user": "sysadmin","status": "Warning",   "contained": False, "last_seen": "8 min ago"},
    {"name": "Cooper-MBP",    "ip": "192.168.1.13",  "os": "macOS 14",    "user": "cooper",  "status": "Clean",     "contained": False, "last_seen": "Just now"},
    {"name": "Dylan-PC",      "ip": "192.168.1.14",  "os": "Windows 10",  "user": "dylan",   "status": "Threat",    "contained": False, "last_seen": "12 min ago"},
]

ACTIVITIES = [
    ("invoice_2024.exe",   "Stewart-PC",   "Quarantined", True),
    ("report.docx",        "SharePoint01", "Suspicious",  False),
    ("update_patch.msi",   "Tomcat-Server","Low",         False),
    ("malware_dropper.exe","Dylan-PC",     "Quarantined", True),
    ("phish_link.html",    "Jayne-Laptop", "Suspicious",  False),
    ("keylogger.dll",      "Stewart-PC",   "Quarantined", True),
    ("safe_update.msi",    "ubuntu-dev",   "Low",         False),
    ("ransomware.exe",     "Dylan-PC",     "Quarantined", True),
]

STATUS_COLORS = {
    "Clean":       (GREEN_L,  GREEN),
    "Threat":      (RED_L,    RED),
    "Warning":     (ORANGE_L, ORANGE),
    "Quarantined": (RED_L,    RED),
    "Suspicious":  (ORANGE_L, ORANGE),
    "Low":         (BLUE_L,   BLUE),
}

OS_ICONS = {
    "Windows": "🖥",
    # "Ubuntu":  "🐧",
    # "CentOS":  "🐧",
    # "macOS":   "🍎",
}

def get_os_icon(os_name):
    for k, v in OS_ICONS.items():
        if k in os_name:
            return v
    return "💻"

# ── Main App ──────────────────────────────────────────────────────────────────
class SMEDashboard:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Virus-AI — SME Device Control Center")
        self.root.geometry("1280x780")
        self.root.configure(bg=BG)
        self.root.minsize(1100, 680)

        self.selected_device = None
        self.containment_vars = {}

        self._build_layout()
        self._build_sidebar()
        self._build_main()
        self._select_device(DEVICES[0])
        self._start_live_feed()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_layout(self):
        self.sidebar = tk.Frame(self.root, bg=NAV_BG, width=260)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        self.main = tk.Frame(self.root, bg=BG)
        self.main.pack(side="left", fill="both", expand=True)

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        # Logo
        logo_frame = tk.Frame(self.sidebar, bg=NAV_BG)
        logo_frame.pack(fill="x", padx=20, pady=(24, 20))

        tk.Label(logo_frame, text="🛡  Virus-AI",
                 font=("Georgia", 16, "bold"),
                 bg=NAV_BG, fg=WHITE).pack(anchor="w")
        tk.Label(logo_frame, text="SME Control Center",
                 font=FONT_XS, bg=NAV_BG, fg=NAV_TEXT).pack(anchor="w")

        # Divider
        tk.Frame(self.sidebar, bg="#2A3558", height=1).pack(fill="x", padx=15, pady=(0, 12))

        # Search
        search_frame = ctk.CTkFrame(self.sidebar, fg_color="#252F4A",
                                    corner_radius=8)
        search_frame.pack(fill="x", padx=15, pady=(0, 16))

        self.search_var = tk.StringVar()
        self.search_var.trace("w", self._filter_devices)

        ctk.CTkEntry(search_frame,
                     placeholder_text="🔍  Search devices...",
                     textvariable=self.search_var,
                     font=FONT_SM,
                     fg_color="transparent",
                     border_width=0,
                     text_color=WHITE,
                     placeholder_text_color=NAV_TEXT,
                     height=34).pack(fill="x", padx=8)

        # Stats row
        stats = tk.Frame(self.sidebar, bg=NAV_BG)
        stats.pack(fill="x", padx=15, pady=(0, 12))

        threats = sum(1 for d in DEVICES if d["status"] == "Threat")
        clean   = sum(1 for d in DEVICES if d["status"] == "Clean")

        for label, val, color in [("Devices", len(DEVICES), NAV_TEXT),
                                   ("Threats", threats, RED),
                                   ("Clean",   clean,   GREEN)]:
            f = tk.Frame(stats, bg=NAV_BG)
            f.pack(side="left", expand=True)
            tk.Label(f, text=str(val), font=("Georgia", 14, "bold"),
                     bg=NAV_BG, fg=color).pack()
            tk.Label(f, text=label, font=FONT_XS,
                     bg=NAV_BG, fg=NAV_TEXT).pack()

        tk.Frame(self.sidebar, bg="#2A3558", height=1).pack(fill="x", padx=15, pady=(0, 8))

        # Device list
        tk.Label(self.sidebar, text="ALL DEVICES",
                 font=("Helvetica", 9, "bold"),
                 bg=NAV_BG, fg=NAV_TEXT).pack(anchor="w", padx=20, pady=(4, 6))

        self.device_list_frame = ctk.CTkScrollableFrame(
            self.sidebar, fg_color=NAV_BG, scrollbar_button_color=NAV_SEL,
            scrollbar_button_hover_color=BLUE)
        self.device_list_frame.pack(fill="both", expand=True, padx=8)

        self.device_buttons = {}
        self._render_device_list(DEVICES)

    def _render_device_list(self, devices):
        for w in self.device_list_frame.winfo_children():
            w.destroy()

        for dev in devices:
            bg_c, fg_c = STATUS_COLORS.get(dev["status"], (BLUE_L, BLUE))
            is_sel = self.selected_device and self.selected_device["name"] == dev["name"]
            row_bg = NAV_SEL if is_sel else NAV_BG

            row = tk.Frame(self.device_list_frame, bg=row_bg, cursor="hand2")
            row.pack(fill="x", pady=2)

            inner = tk.Frame(row, bg=row_bg)
            inner.pack(fill="x", padx=10, pady=8)

            # Icon + name
            icon = get_os_icon(dev["os"])
            left = tk.Frame(inner, bg=row_bg)
            left.pack(side="left", fill="x", expand=True)

            name_row = tk.Frame(left, bg=row_bg)
            name_row.pack(anchor="w")
            tk.Label(name_row, text=icon + "  ", font=FONT_SM,
                     bg=row_bg, fg=WHITE).pack(side="left")
            tk.Label(name_row, text=dev["name"],
                     font=("Helvetica", 11, "bold") if is_sel else FONT_SM,
                     bg=row_bg, fg=WHITE).pack(side="left")

            tk.Label(left, text=dev["ip"], font=FONT_XS,
                     bg=row_bg, fg=NAV_TEXT).pack(anchor="w")

            # Status badge
            badge = tk.Label(inner, text=dev["status"],
                             font=("Helvetica", 8, "bold"),
                             bg=fg_c, fg=WHITE,
                             padx=6, pady=2)
            badge.pack(side="right")

            # Bind click
            for w in [row, inner, left, name_row, badge]:
                w.bind("<Button-1>", lambda e, d=dev: self._select_device(d))

            self.device_buttons[dev["name"]] = row

    def _filter_devices(self, *args):
        q = self.search_var.get().lower()
        filtered = [d for d in DEVICES if q in d["name"].lower() or q in d["ip"]]
        self._render_device_list(filtered)

    # ── Main Panel ────────────────────────────────────────────────────────────
    def _build_main(self):
        # Top bar
        topbar = tk.Frame(self.main, bg=WHITE, height=56)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        tk.Frame(topbar, bg=BORDER, width=1).pack(side="left", fill="y")

        tk.Label(topbar, text="Device Control Center",
                 font=FONT_H2, bg=WHITE, fg=TEXT).pack(side="left", padx=24)

        # Time
        self.time_label = tk.Label(topbar, text="", font=FONT_SM,
                                   bg=WHITE, fg=TEXT2)
        self.time_label.pack(side="right", padx=20)
        self._update_clock()

        tk.Frame(topbar, bg=BORDER, height=1).pack(side="bottom", fill="x")

        # Content area (two columns)
        content = tk.Frame(self.main, bg=BG)
        content.pack(fill="both", expand=True, padx=20, pady=16)

        content.columnconfigure(0, weight=5)
        content.columnconfigure(1, weight=4)
        content.rowconfigure(0, weight=1)

        # Left: device info + actions
        self.info_panel = tk.Frame(content, bg=BG)
        self.info_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        # Right: activity feed
        right = tk.Frame(content, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        self._build_activity_panel(right)

    def _build_activity_panel(self, parent):
        card = ctk.CTkFrame(parent, fg_color=WHITE, corner_radius=14,
                            border_width=1, border_color=BORDER)
        card.pack(fill="both", expand=True)

        # Header
        hdr = tk.Frame(card, bg=WHITE)
        hdr.pack(fill="x", padx=20, pady=(16, 8))

        tk.Label(hdr, text="⚡  Live Threat Feed",
                 font=FONT_H3, bg=WHITE, fg=TEXT).pack(side="left")

        self.live_dot = tk.Label(hdr, text="● LIVE",
                                 font=("Helvetica", 9, "bold"),
                                 bg=WHITE, fg=GREEN)
        self.live_dot.pack(side="right")

        tk.Frame(card, bg=BORDER, height=1).pack(fill="x", padx=16)

        self.feed_frame = ctk.CTkScrollableFrame(card, fg_color=WHITE)
        self.feed_frame.pack(fill="both", expand=True, padx=4, pady=4)

        for time_str, fname, status, danger in ACTIVITIES:
            self._add_feed_item(fname, time_str, status)

    def _add_feed_item(self, filename, device, status):
        bg_c, fg_c = STATUS_COLORS.get(status, (BLUE_L, BLUE))

        row = ctk.CTkFrame(self.feed_frame, fg_color="#FAFAFA",
                           corner_radius=8, border_width=1,
                           border_color=BORDER)
        row.pack(fill="x", pady=3, padx=8)

        inner = tk.Frame(row, bg="#FAFAFA")
        inner.pack(fill="x", padx=12, pady=8)

        # Icon circle
        icon_f = ctk.CTkFrame(inner, fg_color=bg_c,
                              corner_radius=18, width=34, height=34)
        icon_f.pack(side="left")
        icon_f.pack_propagate(False)
        ctk.CTkLabel(icon_f, text="🗂", font=("Arial", 14),
                     fg_color="transparent",
                     text_color=fg_c).pack(expand=True)

        # Text
        txt = tk.Frame(inner, bg="#FAFAFA")
        txt.pack(side="left", padx=(10, 0), fill="x", expand=True)
        tk.Label(txt, text=filename, font=("Helvetica", 10, "bold"),
                 bg="#FAFAFA", fg=TEXT).pack(anchor="w")
        tk.Label(txt, text=f"📍 {device}  •  {datetime.now().strftime('%H:%M')}",
                 font=FONT_XS, bg="#FAFAFA", fg=TEXT3).pack(anchor="w")

        # Badge
        tk.Label(inner, text=status,
                 font=("Helvetica", 8, "bold"),
                 bg=fg_c, fg=WHITE,
                 padx=7, pady=3).pack(side="right")

    # ── Device Info Panel ─────────────────────────────────────────────────────
    def _select_device(self, device):
        self.selected_device = device
        for w in self.info_panel.winfo_children():
            w.destroy()
        self._render_device_info(device)
        self._render_device_list(DEVICES)

    def _render_device_info(self, dev):
        bg_c, fg_c = STATUS_COLORS.get(dev["status"], (BLUE_L, BLUE))

        # ── Status banner ──────────────────────────────────────────────────
        banner = ctk.CTkFrame(self.info_panel, fg_color=bg_c,
                              corner_radius=12, border_width=1,
                              border_color=fg_c)
        banner.pack(fill="x", pady=(0, 12))

        b_inner = tk.Frame(banner, bg=bg_c)
        b_inner.pack(fill="x", padx=20, pady=14)

        icon = get_os_icon(dev["os"])
        tk.Label(b_inner, text=f"{icon}  {dev['name']}",
                 font=FONT_H1, bg=bg_c, fg=TEXT).pack(side="left")

        status_pill = tk.Label(b_inner,
                               text=f"  {dev['status'].upper()}  ",
                               font=("Helvetica", 11, "bold"),
                               bg=fg_c, fg=WHITE, padx=10, pady=4)
        status_pill.pack(side="right")

        tk.Label(b_inner, text=f"Last seen: {dev['last_seen']}",
                 font=FONT_XS, bg=bg_c, fg=TEXT2).pack(side="right", padx=16)

        # ── Two column: Host Info + Actions ───────────────────────────────
        row = tk.Frame(self.info_panel, bg=BG)
        row.pack(fill="x", pady=(0, 12))
        row.columnconfigure(0, weight=3)
        row.columnconfigure(1, weight=2)

        # Host Info Card
        info_card = ctk.CTkFrame(row, fg_color=WHITE, corner_radius=14,
                                 border_width=1, border_color=BORDER)
        info_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        tk.Label(info_card, text="Host Information",
                 font=FONT_H3, bg=WHITE, fg=TEXT).pack(anchor="w", padx=20, pady=(14, 8))
        tk.Frame(info_card, bg=BORDER, height=1).pack(fill="x", padx=16)

        fields = [
            ("Hostname",     dev["name"]),
            ("IP Address",   dev["ip"]),
            ("OS",           dev["os"]),
            ("Primary User", dev["user"]),
            ("Status",       dev["status"]),
            ("Last Seen",    dev["last_seen"]),
        ]

        for label, value in fields:
            r = tk.Frame(info_card, bg=WHITE)
            r.pack(fill="x", padx=20, pady=5)
            tk.Label(r, text=label + ":",
                     font=("Helvetica", 11, "bold"),
                     bg=WHITE, fg=TEXT2, width=14,
                     anchor="w").pack(side="left")
            tk.Label(r, text=value,
                     font=FONT_BODY, bg=WHITE, fg=TEXT).pack(side="left")

        tk.Frame(info_card, bg=BG, height=10).pack()

        # Actions Card
        action_card = ctk.CTkFrame(row, fg_color=WHITE, corner_radius=14,
                                   border_width=1, border_color=BORDER)
        action_card.grid(row=0, column=1, sticky="nsew")

        tk.Label(action_card, text="Actions",
                 font=FONT_H3, bg=WHITE, fg=TEXT).pack(anchor="w", padx=20, pady=(14, 8))
        tk.Frame(action_card, bg=BORDER, height=1).pack(fill="x", padx=16)

        # Containment toggle
        cont_row = tk.Frame(action_card, bg=WHITE)
        cont_row.pack(fill="x", padx=20, pady=(16, 8))

        tk.Label(cont_row, text="Containment",
                 font=("Helvetica", 11, "bold"),
                 bg=WHITE, fg=TEXT).pack(anchor="w")

        toggle_row = tk.Frame(action_card, bg=WHITE)
        toggle_row.pack(fill="x", padx=20, pady=(0, 4))

        var = tk.BooleanVar(value=dev["contained"])
        self.containment_vars[dev["name"]] = var

        toggle = ctk.CTkSwitch(
            toggle_row,
            text="",
            variable=var,
            onvalue=True, offvalue=False,
            fg_color=RED_L,
            progress_color=RED,
            button_color=WHITE,
            button_hover_color="#F0F0F0",
            command=lambda d=dev, v=var: self._toggle_containment(d, v)
        )
        toggle.pack(side="left")

        self.contain_status_label = tk.Label(
            toggle_row,
            text="Host Contained" if dev["contained"] else "Not Contained",
            font=FONT_SM,
            bg=WHITE,
            fg=RED if dev["contained"] else TEXT3
        )
        self.contain_status_label.pack(side="left", padx=8)

        tk.Frame(action_card, bg=BORDER, height=1).pack(fill="x", padx=16, pady=8)

        # Quick action buttons
        tk.Label(action_card, text="Quick Actions",
                 font=("Helvetica", 11, "bold"),
                 bg=WHITE, fg=TEXT).pack(anchor="w", padx=20, pady=(0, 8))

        actions = [
            ("🔍  Run Full Scan",    BLUE,   "#1D4ED8"),
            ("🗑  Clear Quarantine", GREEN,  "#059669"),
            ("⚠️  Flag Device",      ORANGE, "#D97706"),
        ]

        for label, color, hover in actions:
            ctk.CTkButton(
                action_card,
                text=label,
                font=FONT_SM,
                fg_color=color,
                hover_color=hover,
                text_color=WHITE,
                corner_radius=8,
                height=34,
                anchor="w",
                command=lambda l=label: self._run_action(l, dev)
            ).pack(fill="x", padx=20, pady=3)

        tk.Frame(action_card, bg=BG, height=8).pack()

        # ── Threat history ─────────────────────────────────────────────────
        hist_card = ctk.CTkFrame(self.info_panel, fg_color=WHITE,
                                 corner_radius=14, border_width=1,
                                 border_color=BORDER)
        hist_card.pack(fill="both", expand=True)

        hdr = tk.Frame(hist_card, bg=WHITE)
        hdr.pack(fill="x", padx=20, pady=(14, 8))
        tk.Label(hdr, text=f"📋  Threat History — {dev['name']}",
                 font=FONT_H3, bg=WHITE, fg=TEXT).pack(side="left")

        tk.Frame(hist_card, bg=BORDER, height=1).pack(fill="x", padx=16)

        scroll = ctk.CTkScrollableFrame(hist_card, fg_color=WHITE)
        scroll.pack(fill="both", expand=True, padx=4, pady=4)

        device_acts = [a for a in ACTIVITIES if a[1] == dev["name"]]
        if not device_acts:
            tk.Label(scroll, text="✅  No threats detected on this device.",
                     font=FONT_BODY, bg=WHITE, fg=GREEN).pack(pady=20)
        else:
            for fname, dname, status, danger in device_acts:
                bg_c2, fg_c2 = STATUS_COLORS.get(status, (BLUE_L, BLUE))
                r = ctk.CTkFrame(scroll, fg_color="#FAFAFA",
                                 corner_radius=8, border_width=1,
                                 border_color=BORDER)
                r.pack(fill="x", pady=3, padx=8)
                rr = tk.Frame(r, bg="#FAFAFA")
                rr.pack(fill="x", padx=12, pady=8)
                tk.Label(rr, text="🗂  " + fname,
                         font=("Helvetica", 10, "bold"),
                         bg="#FAFAFA", fg=TEXT).pack(side="left")
                tk.Label(rr, text=status,
                         font=("Helvetica", 8, "bold"),
                         bg=fg_c2, fg=WHITE,
                         padx=6, pady=2).pack(side="right")

    def _toggle_containment(self, dev, var):
        dev["contained"] = var.get()
        label = "Host Contained" if dev["contained"] else "Not Contained"
        color = RED if dev["contained"] else TEXT3
        self.contain_status_label.config(text=label, fg=color)

    def _run_action(self, label, dev):
        print(f"Action: {label} on {dev['name']}")

    # ── Live feed simulation ───────────────────────────────────────────────────
    def _start_live_feed(self):
        def pulse():
            colors = [GREEN, TEXT3]
            i = 0
            while True:
                try:
                    self.live_dot.config(fg=colors[i % 2])
                    i += 1
                    time.sleep(1)
                except:
                    break

        threading.Thread(target=pulse, daemon=True).start()

    def _update_clock(self):
        now = datetime.now().strftime("%a, %d %b %Y  %H:%M:%S")
        self.time_label.config(text=now)
        self.root.after(1000, self._update_clock)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = SMEDashboard()
    app.run()
