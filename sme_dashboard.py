import tkinter as tk
import customtkinter as ctk
from datetime import datetime
import random
import threading
import time

ctk.set_appearance_mode("light")


# ── Palette ──────────────────────────────────────────────────────────────────
BG        = "#F8F9FA"       # card_bg
WHITE     = "#FFFFFF"       # bg
BORDER    = "#Ffffff"       # border_red
NAV_BG    = "#1A2340"
NAV_SEL   = "#2A3558"
NAV_TEXT  = "#A8B4CC"
NAV_ACT   = "#FFFFFF"
BLUE      = "#2563EB"
BLUE_L    = "#EFF4FF"
RED       = "#FF5252"       # accent_red ✅ matched
RED_L     = "#ffffff"       # light_red  ✅ matched
ORANGE    = "#F59E0B"
ORANGE_L  = "#FFFBEB"
GREEN     = "#10B981"
GREEN_L   = "#ECFDF5"
TEXT      = "#1A1A1B"       # text_main  ✅ matched
TEXT2     = "#6E6E73"       # text_sub   ✅ matched
TEXT3     = "#94A3B8"

FONT_H1   = ("Georgia", 18, "bold")
FONT_H2   = ("Georgia", 13, "bold")
FONT_H3   = ("Georgia", 11, "bold")
FONT_BODY = ("Helvetica", 11)
FONT_SM   = ("Helvetica", 12)
FONT_XS   = ("Helvetica", 9)

# ── Mock Data ─────────────────────────────────────────────────────────────────
DEVICES = [
    {"name": "WS-Prod-01",    "ip": "192.168.1.10",  "os": "Windows 11",  "user": "alice",   "status": "Clean",     "contained": False, "last_seen": "Just now"},
    {"name": "Stewart-PC",    "ip": "192.168.1.11",  "os": "Windows 10",  "user": "stewart", "status": "Threat",    "contained": True,  "last_seen": "2 min ago"},
    {"name": "SharePoint01",  "ip": "192.168.1.20",  "os": "Windows Server 2022", "user": "admin", "status": "Warning", "contained": False, "last_seen": "5 min ago"},
    {"name": "ubuntu-dev",    "ip": "192.168.1.30",  "os": "Windows 11","user": "devteam", "status": "Clean",     "contained": False, "last_seen": "1 min ago"},
    {"name": "Jayne-Laptop",  "ip": "192.168.1.12",  "os": "Windows 11",  "user": "jayne",   "status": "Clean",     "contained": False, "last_seen": "3 min ago"},
    {"name": "Tomcat-Server", "ip": "192.168.1.40",  "os": "Windows 11",    "user": "sysadmin","status": "Warning",   "contained": False, "last_seen": "8 min ago"},
    {"name": "Cooper-MBP",    "ip": "192.168.1.13",  "os": "Windows 11",    "user": "cooper",  "status": "Clean",     "contained": False, "last_seen": "Just now"},
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

# ── Status Colors (text only, no background) ─────────────────────────────────
STATUS_COLORS = {
    "Clean":       ("#F5F5F5", GREEN),
    "Threat":      ("#F5F5F5", RED),
    "Warning":     ("#F5F5F5", ORANGE),
    "Quarantined": ("#F5F5F5", RED),
    "Suspicious":  ("#F5F5F5", ORANGE),
    "Low":         ("#F5F5F5", BLUE),
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
        search_frame = ctk.CTkFrame(self.sidebar, fg_color="#e0e0e0",
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
        self.device_buttons = {}

        for dev in devices:
            bg_c, fg_c = STATUS_COLORS.get(dev["status"], (BLUE_L, BLUE))
            is_sel = self.selected_device and self.selected_device["name"] == dev["name"]
            row_bg = NAV_SEL if is_sel else NAV_BG

            row = tk.Frame(self.device_list_frame, bg=row_bg, cursor="hand2")
            row.pack(fill="x", pady=2)

            inner = tk.Frame(row, bg=row_bg)
            inner.pack(fill="x", padx=10, pady=8)

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

            badge_frame = ctk.CTkFrame(inner, fg_color="transparent",
                                       corner_radius=6, height=22, width=70)
            badge_frame.pack_propagate(False)
            badge_frame.pack(side="right", padx=(10, 5))

            ctk.CTkLabel(badge_frame, text=dev["status"].upper(),
                         font=("Helvetica", 9, "bold"),
                         text_color=fg_c,
                         fg_color="transparent").pack(expand=True)

            # ✅ Store row reference
            self.device_buttons[dev["name"]] = {"row": row}

            for w in [row, inner, left, name_row, badge_frame]:
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

        # Main Row Container
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

        # Text Section (Filename and Device info)
        txt = tk.Frame(inner, bg="#FAFAFA")
        txt.pack(side="left", padx=(10, 0), fill="x", expand=True)
        
        tk.Label(txt, text=filename, font=("Helvetica", 10, "bold"),
                bg="#FAFAFA", fg=TEXT).pack(anchor="w")
                
        tk.Label(txt, text=f"📍 {device}  •  {datetime.now().strftime('%H:%M')}",
                font=FONT_XS, bg="#FAFAFA", fg=TEXT3).pack(anchor="w")

        # --- UPDATED BADGE SECTION ---
        # Using CTkLabel for the corner_radius
        ctk.CTkLabel(
            inner,
            text=status.upper(),
            font=("Helvetica", 9, "bold"),
            text_color=fg_c,            # ✅ colored text only
            fg_color="#F5F5F5",
            corner_radius=6,
            height=22,
            padx=8
        ).pack(side="right")
    # ── Device Info Panel ─────────────────────────────────────────────────────
    def _select_device(self, device):
        self.selected_device = device
        self._update_sidebar_highlight()
        for w in self.info_panel.winfo_children():
            w.destroy()
        self._render_device_info(device)

    def _update_sidebar_highlight(self):
        for dev_name, row in self.device_buttons.items():
            is_sel = self.selected_device and self.selected_device["name"] == dev_name
            row_bg = NAV_SEL if is_sel else NAV_BG
            self._update_bg_recursive(row, row_bg)

    def _update_bg_recursive(self, widget, bg):
        try:
            widget.configure(bg=bg)
        except:
            pass
        for child in widget.winfo_children():
            self._update_bg_recursive(child, bg)

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
                               bg=bg_c,        # ✅ matches banner bg
                               fg=fg_c,        # ✅ colored text only
                               padx=10, pady=4)
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
                 font=("Helvetica", 12, "bold"),
                 bg=WHITE, fg=TEXT).pack(anchor="w", padx=20, pady=(0, 8))


        actions = [
                    ("Deep Behavioral Analysis", "#F0F4FF", "#B1BBD8", BLUE),
                    ("Clear Quarantine",          "#F0FDF4", "#B1BBD8", GREEN),
                    ("Mark as Compromised",       "#FFFBEB", "#D97706", ORANGE),
                ]

        for label, bg_color, text_color, hover in actions:
            ctk.CTkButton(
                action_card,
                text=label,
                font=FONT_SM,
                fg_color=bg_color,      # ✅ soft pastel background
                hover_color=hover,
                text_color="#0b0000",  # ✅ colored text
                corner_radius=8,
                height=34,
                anchor="w",
                command=lambda l=label: self._run_action(l, dev)
            ).pack(fill="x", padx=20, pady=3)
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
            for fname, _, status, danger in device_acts:
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
                         bg="#FAFAFA",
                         fg=fg_c2,
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
