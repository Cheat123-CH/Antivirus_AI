"""
quarantine_page.py — Quarantine Detail Page
Opens as a new window when clicking the Quarantine card.
Features: file list, file details, restore, delete permanently.

Usage in main.py:
    from quarantine_page import open_quarantine_page
    # In your quarantine card click handler:
    open_quarantine_page(self.root, self.quarantine_files)
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import font as tkfont
from tkinter import messagebox
import datetime
import json
import os

# ── Path to member1_alerts.json ───────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
ALERTS_FILE = os.path.join(BASE_DIR, "member1_alerts.json")

# ── Severity → threat label mapping ──────────────────────────────────────────
# member1_alerts.json uses "HIGH" / "MEDIUM" / "LOW"
# quarantine page uses  "High" / "Suspicious" / "Low"
SEVERITY_MAP = {
    "HIGH":   "High",
    "MEDIUM": "Suspicious",
    "LOW":    "Low",
}

THREAT_TITLE_MAP = {
    "HIGH":   "High-Severity Threat Detected",
    "MEDIUM": "Suspicious Activity Detected",
    "LOW":    "Low-Risk File Quarantined",
}


def _format_date(iso_str: str) -> str:
    """Convert ISO timestamp → human-readable string."""
    try:
        dt = datetime.datetime.fromisoformat(
            iso_str.replace("Z", "+00:00"))
        today = datetime.datetime.now(datetime.timezone.utc).date()
        if dt.date() == today:
            return "Today, " + dt.strftime("%I:%M %p").lstrip("0")
        yesterday = today - datetime.timedelta(days=1)
        if dt.date() == yesterday:
            return "Yesterday, " + dt.strftime("%I:%M %p").lstrip("0")
        return dt.strftime("%d %b %Y, %I:%M %p")
    except Exception:
        return iso_str


def load_quarantine_files() -> list:
    """
    Load alerts from member1_alerts.json.

    Expected fields per alert (your actual JSON):
      alert_id, rule_id, process_name, severity, confidence,
      tags, description, file_path, generated_at
    """
    if not os.path.exists(ALERTS_FILE):
        return []

    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    alerts = data.get("alerts", [])
    files  = []
    alerts = [a for a in alerts if a.get("severity", "").upper() == "HIGH"]

    for i, alert in enumerate(alerts):
        sev      = alert.get("severity", "LOW").upper()
        tags     = alert.get("tags", [])
        tag_str  = "  •  ".join(tags) if tags else "—"

        # Use the description field directly from JSON
        description = alert.get("description", "No description available.")

        # Build threat_title from process name + severity
        proc = alert.get("process_name", "Unknown")
        title_map = {
            "HIGH":   f"High-Severity Threat — {proc}",
            "MEDIUM": f"Suspicious Activity — {proc}",
            "LOW":    f"Low-Risk Detection — {proc}",
        }

        files.append({
            "id":           i + 1,

            # ── List view fields ──────────────────────────────────────────
            "name":         alert.get("process_name", "unknown"),
            "path":         alert.get("file_path", "N/A"),
            "threat":       SEVERITY_MAP.get(sev, "Low"),
            "size":         alert.get("file_size", "N/A"),   # not in your JSON → shows N/A
            "date":         _format_date(alert.get("generated_at", "")),

            # ── Detail panel fields ───────────────────────────────────────
            "rule":         alert.get("rule_id", "N/A"),
            "confidence":   alert.get("confidence", "N/A"),
            "threat_title": title_map.get(sev, f"Threat — {proc}"),
            "threat_desc":  description,

            # ── Extra detail rows (shown in detail panel) ─────────────────
            "alert_id":     alert.get("alert_id", "N/A"),
            "tags_str":     tag_str,

            # ── Raw alert kept for any future use ─────────────────────────
            "_raw":         alert,
        })

    # Sort: HIGH → MEDIUM → LOW
    order = {"High": 0, "Suspicious": 1, "Low": 2}
    files.sort(key=lambda x: order.get(x["threat"], 9))
    return files

# ── Threat level colors ───────────────────────────────────────────────────────
THREAT_COLORS = {
    "High":       ("#FEF2F2", "#DC2626"),   # bg, fg
    "Suspicious": ("#FFFBEB", "#D97706"),
    "Low":        ("#F0FDF4", "#16A34A"),
}


# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
def open_quarantine_page(parent, quarantine_files=None):
    """
    Open the quarantine detail window.
    If quarantine_files is None, loads automatically from member1_alerts.json.
    """
    files = quarantine_files if quarantine_files is not None else load_quarantine_files()
    QuarantinePage(parent, files)


# ─────────────────────────────────────────────────────────────────────────────
class QuarantinePage:
    def __init__(self, parent, files: list):
        self.parent = parent
        self.files  = list(files)          # working copy
        self.selected_file = None
        self._card_widgets  = []            # list of (frame, file_dict)

        # ── Window ────────────────────────────────────────────────────────────
        self.win = tk.Toplevel(parent)
        self.win.title("Quarantine Vault")
        self.win.geometry("920x680")
        self.win.configure(bg="#FFFFFF")
        self.win.resizable(True, True)
        self.win.grab_set()                 # modal

        # Fonts
        self.f_title  = tkfont.Font(family="Arial", size=18, weight="bold")
        self.f_sub    = tkfont.Font(family="Arial", size=11)
        self.f_bold   = tkfont.Font(family="Arial", size=12, weight="bold")
        self.f_small  = tkfont.Font(family="Arial", size=10)
        self.f_mono   = tkfont.Font(family="Courier", size=10)
        self.f_label  = tkfont.Font(family="Arial", size=9)

        self._build_ui()

    # ─────────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Top bar ───────────────────────────────────────────────────────────
        topbar = tk.Frame(self.win, bg="#FFFFFF",
                          highlightbackground="#E5E7EB", highlightthickness=1)
        topbar.pack(fill="x")

        # Back button
        ctk.CTkButton(
            topbar, text="← Back",
            font=("Arial", 12),
            fg_color="#ECEDEE",        # ← background color (light gray)
            hover_color="#E5E7EB",     # ← hover background
            text_color="#374151",      # ← text color
            corner_radius=6,
            border_color="#D1D5DB",    # ← optional border
            border_width=1,
            width=80, height=34,
            command=self.win.destroy
        ).pack(side="left", padx=12, pady=10)

        # Title
        title_row = tk.Frame(topbar, bg="#FFFFFF")
        title_row.pack(side="left", padx=8, pady=8)

        # Shield icon (canvas)
        shield_canvas = tk.Canvas(title_row, width=36, height=36,
                                  bg="#FFFFFF", highlightthickness=0)
        shield_canvas.pack(side="left")
        shield_canvas.create_oval(0, 0, 36, 36, fill="#FFFFFF", outline="")
        shield_canvas.create_text(18, 18, text="🔒", font=("Arial", 16))

        title_col = tk.Frame(title_row, bg="#FFFFFF")
        title_col.pack(side="left", padx=(8, 0))
        tk.Label(title_col, text="Quarantine Vault",
                 font=self.f_title, bg="#FFFFFF",
                 fg="#F00C13").pack(anchor="w")
        tk.Label(title_col,
                 text="Isolated files safe and cannot affect your system",
                 font=self.f_small, bg="#FFFFFF",
                 fg="#C57480").pack(anchor="w")

        # ── Summary stats row ─────────────────────────────────────────────────
        stats_row = tk.Frame(self.win, bg="#F8F9FA")
        stats_row.pack(fill="x", padx=20, pady=(16, 0))
        stats_row.columnconfigure(0, weight=1)
        stats_row.columnconfigure(1, weight=1)
        stats_row.columnconfigure(2, weight=1)

        # Change the stat card calls:
        self.stat_total = self._stat_card(stats_row, "Total Quarantined",
                                        str(len(self.files)),
                                        "#374151", "#F9FAFB", col=0)

        self.stat_high  = self._stat_card(stats_row, "High Threat",
                                        str(sum(1 for f in self.files
                                                if f["threat"] == "High")),
                                        "#EF4444", "#FEF2F2", col=1)

        self._stat_card(stats_row, "Storage Used",
                        self._total_size(),
                        "#3B82F6", "#EFF6FF", col=2)

        # ── Main content area (left list + right detail) ──────────────────────
        content = tk.Frame(self.win, bg="#F8F9FA")
        content.pack(fill="both", expand=True, padx=20, pady=16)

        # ── LEFT: file list ───────────────────────────────────────────────────
        left = tk.Frame(content, bg="#F8F9FA", width=420)
        left.pack(side="left", fill="both", expand=False)
        left.pack_propagate(False)

        list_card = tk.Frame(left, bg="#FFFFFF",
                             highlightbackground="#E5E7EB", highlightthickness=1)
        list_card.pack(fill="both", expand=True)

        # List header
        list_hdr = tk.Frame(list_card, bg="#FFFFFF")
        list_hdr.pack(fill="x", padx=16, pady=(12, 8))
        tk.Label(list_hdr, text="Quarantined Files",
                 font=self.f_bold, bg="#FFFFFF",
                 fg="#111827").pack(side="left")
        self.sel_all_btn = ctk.CTkButton(
            list_hdr, text="Select all",
            font=("Arial", 10),
            fg_color="transparent", hover_color="#F3F4F6",
            text_color="#0D0D0D", corner_radius=4,
            width=70, height=24,
            command=self._select_all
        )
        self.sel_all_btn.pack(side="right")

        tk.Frame(list_card, bg="#E5E7EB", height=1).pack(fill="x")

        # Scrollable list
        list_container = tk.Frame(list_card, bg="#FFFFFF")
        list_container.pack(fill="both", expand=True)

        self.list_canvas = tk.Canvas(list_container,
                                     bg="#FFFFFF", highlightthickness=0)
        list_sb = tk.Scrollbar(list_container, orient="vertical",
                               command=self.list_canvas.yview)
        self.list_canvas.configure(yscrollcommand=list_sb.set)
        list_sb.pack(side="right", fill="y")
        self.list_canvas.pack(side="left", fill="both", expand=True)

        self.list_frame = tk.Frame(self.list_canvas, bg="#FFFFFF")
        self._list_win  = self.list_canvas.create_window(
            (0, 0), window=self.list_frame, anchor="nw")

        self.list_frame.bind("<Configure>",
            lambda e: self.list_canvas.configure(
                scrollregion=self.list_canvas.bbox("all")))
        self.list_canvas.bind("<Configure>",
            lambda e: self.list_canvas.itemconfig(
                self._list_win, width=e.width))
        self.list_canvas.bind("<Enter>",
            lambda e: self.list_canvas.bind_all(
                "<MouseWheel>", self._on_scroll))
        self.list_canvas.bind("<Leave>",
            lambda e: self.list_canvas.unbind_all("<MouseWheel>"))

        # Bulk action bar (hidden until selection)
        self.bulk_bar = tk.Frame(list_card, bg="#F3F4F6",
                                 highlightbackground="#E5E7EB",
                                 highlightthickness=1)
        # (packed later on selection)

        self._render_file_list()

        # ── RIGHT: detail panel ───────────────────────────────────────────────
        right = tk.Frame(content, bg="#F8F9FA")
        right.pack(side="left", fill="both", expand=True, padx=(16, 0))

        self.detail_outer = tk.Frame(right, bg="#F8F9FA")
        self.detail_outer.pack(fill="both", expand=True)

        self._show_detail_placeholder()

    # ─────────────────────────────────────────────────────────────────────────
    # Stat card helper
    # ─────────────────────────────────────────────────────────────────────────
    def _stat_card(self, parent, label, value, color, bg, col=0):
        card = ctk.CTkFrame(parent, fg_color=bg,
                            border_width=1,
                            border_color="#C3C3C4",
                            corner_radius=10)
        card.grid(row=0, column=col, sticky="ew", padx=(0, 12), pady=(0, 12))

        tk.Label(card, text=label,
                font=self.f_label, bg=bg,
                fg=color).pack(anchor="center", padx=16, pady=(14, 2))
        lbl = tk.Label(card, text=value,
                    font=tkfont.Font(family="Arial", size=28, weight="bold"),
                    bg=bg, fg=color)
        lbl.pack(anchor="center", padx=16, pady=(0, 14))
        return lbl

    def _total_size(self):
        # Simple sum of displayed sizes (demo)
        return f"{len(self.files) * 4.6:.1f} MB"

    # ─────────────────────────────────────────────────────────────────────────
    # File list rendering
    # ─────────────────────────────────────────────────────────────────────────
    def _render_file_list(self):
        for w in self.list_frame.winfo_children():
            w.destroy()
        self._card_widgets = []

        for i, f in enumerate(self.files):
            self._make_file_row(i, f)

        # Update stats
        self.stat_total.configure(text=str(len(self.files)))
        high_count = sum(1 for f in self.files if f["threat"] == "High")
        self.stat_high.configure(text=str(high_count))

    def _make_file_row(self, idx, f):
        threat_bg, threat_fg = THREAT_COLORS.get(f["threat"], ("#F3F4F6", "#374151"))

        row = tk.Frame(self.list_frame, bg="#FFFFFF",
                       highlightbackground="#F3F4F6", highlightthickness=1,
                       cursor="hand2")
        row.pack(fill="x", padx=8, pady=3)

        # Checkbox indicator (left colored strip)
        row._selected   = False
        row._file       = f
        row._orig_bg  = "#FFFFFF"
        row._sel_bg   = "#EFF6FF"
        row._cb_sel   = False 

        strip = tk.Frame(row, bg="#E5E7EB", width=4)
        strip.pack(side="left", fill="y")
        row._strip = strip
        # Text column
        text_col = tk.Frame(row, bg="#FFFFFF")
        text_col.pack(side="left", fill="both", expand=True, padx=(16, 0), pady=10)

        tk.Label(text_col, text=f["name"],
                 font=self.f_bold, bg="#FFFFFF",
                 fg="#111827", anchor="w").pack(anchor="w")
        tk.Label(text_col, text=f["path"],
                 font=self.f_mono, bg="#FFFFFF",
                 fg="#0F0F10", anchor="w",
                 wraplength=300).pack(anchor="w")
        tk.Label(text_col, text=f["date"],
                 font=self.f_label, bg="#FFFFFF",
                 fg="#515153").pack(anchor="w", pady=(2, 0))

        # Right: threat badge
        meta = tk.Frame(row, bg="#FFFFFF")
        meta.pack(side="right", padx=5, pady=10)


        badge = ctk.CTkFrame(meta, fg_color="#FEE2E2",
                            border_width=0,
                            corner_radius=10)
        badge.pack(anchor="e")
        ctk.CTkLabel(badge, text=f["threat"],
                    font=("Arial", 12, "bold"),
                    fg_color="transparent",
                    text_color="#E76D6D").pack(padx=12, pady=1)
        # Checkbox circle
        # cb_frame = tk.Frame(row, bg="#FFFFFF", width=22, height=22)
        # cb_frame.pack(side="right", padx=(0, 8), pady=10)
        # cb_frame.pack_propagate(False)
        # cb = tk.Canvas(cb_frame, width=20, height=20,
        #                bg="#FFFFFF", highlightthickness=0)
        # cb.pack(expand=True)
        # cb.create_oval(2, 2, 18, 18, outline="#D1D5DB", width=1.5, tags="circle")
        # row._cb     = cb
        # row._cb_sel = False

# ── Hover helpers ─────────────────────────────────────────────────────
        all_widgets = [row, strip, text_col, meta, badge]
        for child in text_col.winfo_children():
            all_widgets.append(child)

        def on_enter(e, r=row, s=strip, tc=text_col, m=meta):
            if not r._cb_sel:                          # skip if already selected
                r.configure(bg="#EFF6FF", highlightbackground="#2563EB")
                s.configure(bg="#2563EB")
                tc.configure(bg="#EFF6FF")
                m.configure(bg="#EFF6FF")
                for child in tc.winfo_children():
                    try: child.configure(bg="#EFF6FF")
                    except Exception: pass

        def on_leave(e, r=row, s=strip, tc=text_col, m=meta):
            if not r._cb_sel:                          # skip if selected
                r.configure(bg="#FFFFFF", highlightbackground="#F3F4F6")
                s.configure(bg="#E5E7EB")
                tc.configure(bg="#FFFFFF")
                m.configure(bg="#FFFFFF")
                for child in tc.winfo_children():
                    try: child.configure(bg="#FFFFFF")
                    except Exception: pass

        # ── Click binding ─────────────────────────────────────────────────────
        def on_click(e, r=row, fi=f):
            self._on_row_click(r, fi)

        for w in all_widgets:
            try:
                w.bind("<Button-1>", on_click)
                w.bind("<Enter>",    on_enter)
                w.bind("<Leave>",    on_leave)
            except Exception:
                pass

        self._card_widgets.append((row, f))

    def _on_row_click(self, row, f):
        # Toggle selection
        row._cb_sel = not row._cb_sel
        if row._cb_sel:
            row.configure(bg="#EFF6FF",
                          highlightbackground="#2563EB")
            row._strip.configure(bg="#2563EB")
            for child in row.winfo_children():
                try: child.configure(bg="#EFF6FF")
                except Exception: pass
        else:
            row.configure(bg="#FFFFFF",
                          highlightbackground="#F3F4F6")
            row._strip.configure(bg="#E5E7EB")
            for child in row.winfo_children():
                try: child.configure(bg="#FFFFFF")
                except Exception: pass

        self._update_bulk_bar()
        self._show_detail(f)
        
    def _get_selected_files(self):
        return [f for row, f in self._card_widgets if row._cb_sel]

    def _select_all(self):
        all_sel = all(row._cb_sel for row, _ in self._card_widgets)
        for row, _ in self._card_widgets:
            row._cb_sel = not all_sel
            row._cb.delete("all")
            if row._cb_sel:
                row._cb.create_oval(2, 2, 18, 18,
                                    fill="#2563EB", outline="")
                row._cb.create_text(10, 10, text="✓",
                                    font=("Arial", 9, "bold"),
                                    fill="white")
                row.configure(bg="#EFF6FF",
                              highlightbackground="#2563EB")
                row._strip.configure(bg="#2563EB")
            else:
                row._cb.create_oval(2, 2, 18, 18,
                                    outline="#D1D5DB", width=1.5)
                row.configure(bg="#FFFFFF",
                              highlightbackground="#F3F4F6")
                row._strip.configure(bg="#E5E7EB")
        self._update_bulk_bar()

    def _update_bulk_bar(self):
        selected = self._get_selected_files()
        if selected:
            # Show bulk action bar
            for w in self.bulk_bar.winfo_children():
                w.destroy()

            tk.Label(self.bulk_bar,
                     text=f"{len(selected)} file{'s' if len(selected)>1 else ''} selected",
                     font=self.f_small, bg="#F3F4F6",
                     fg="#374151").pack(side="left", padx=14, pady=8)

            ctk.CTkButton(
                self.bulk_bar, text="⟳  Restore",
                font=("Arial", 11),
                fg_color="#FFFFFF", hover_color="#F3F4F6",
                text_color="#060606",
                border_color="#D1D5DB", border_width=1,
                corner_radius=6, width=100, height=30,
                command=lambda: self._bulk_restore(selected)
            ).pack(side="left", padx=(0, 6), pady=8)

            ctk.CTkButton(
                self.bulk_bar, text="🗑  Delete",
                font=("Arial", 11),
                fg_color="#FEF2F2", hover_color="#FEE2E2",
                text_color="#DC2626",
                border_color="#FECACA", border_width=1,
                corner_radius=6, width=100, height=30,
                command=lambda: self._bulk_delete(selected)
            ).pack(side="left", pady=8)

            self.bulk_bar.pack(fill="x", side="bottom")
        else:
            self.bulk_bar.pack_forget()

    def _on_scroll(self, event):
        self.list_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ─────────────────────────────────────────────────────────────────────────
    # Detail panel
    # ─────────────────────────────────────────────────────────────────────────
    def _show_detail_placeholder(self):
        for w in self.detail_outer.winfo_children():
            w.destroy()

        ph = tk.Frame(self.detail_outer, bg="#FFFFFF",
                      highlightbackground="#E5E7EB", highlightthickness=1)
        ph.pack(fill="both", expand=True)

        center = tk.Frame(ph, bg="#FFFFFF")
        center.place(relx=0.5, rely=0.45, anchor="center")

        tk.Label(center, text="🔒",
                 font=("Arial", 40), bg="#FFFFFF").pack()
        tk.Label(center, text="No file selected",
                 font=tkfont.Font(family="Arial", size=14, weight="bold"),
                 bg="#FFFFFF", fg="#374151").pack(pady=(8, 4))
        tk.Label(center,
                 text="Click a file on the left\nto view its details here.",
                 font=self.f_sub, bg="#FFFFFF",
                 fg="#9CA3AF", justify="center").pack()

    def _show_detail(self, f: dict):
        self.selected_file = f
        for w in self.detail_outer.winfo_children():
            w.destroy()

        threat_bg, threat_fg = THREAT_COLORS.get(
            f["threat"], ("#F3F4F6", "#374151"))

        # ── Card wrapper ──────────────────────────────────────────────────────
        card = tk.Frame(self.detail_outer, bg="#FFFFFF",
                        highlightbackground="#E5E7EB", highlightthickness=1)
        card.pack(fill="both", expand=True)

        # Card header
        hdr = tk.Frame(card, bg="#FFFFFF",
                       highlightbackground="#E5E7EB", highlightthickness=0)
        hdr.pack(fill="x", padx=0)
        tk.Frame(hdr, bg="#E5E7EB", height=1).pack(fill="x", side="bottom")

        hdr_inner = tk.Frame(hdr, bg="#FFFFFF")
        hdr_inner.pack(fill="x", padx=16, pady=(14, 12))

        tk.Label(hdr_inner, text="File Details",
                 font=self.f_bold, bg="#FFFFFF",
                 fg="#111827").pack(side="left")

        # Threat badge in header
        badge = tk.Frame(hdr_inner, bg=threat_bg,
                         highlightbackground=threat_fg,
                         highlightthickness=1)
        badge.pack(side="right")
        tk.Label(badge, text=f["threat"],
                 font=self.f_label, bg=threat_bg,
                 fg=threat_fg).pack(padx=10, pady=4)

        # Scrollable detail body
        detail_container = tk.Frame(card, bg="#FFFFFF")
        detail_container.pack(fill="both", expand=True)

        detail_canvas = tk.Canvas(detail_container,
                                  bg="#FFFFFF", highlightthickness=0)
        detail_sb = tk.Scrollbar(detail_container, orient="vertical",
                                 command=detail_canvas.yview)
        detail_canvas.configure(yscrollcommand=detail_sb.set)
        detail_sb.pack(side="right", fill="y")
        detail_canvas.pack(side="left", fill="both", expand=True)

        body = tk.Frame(detail_canvas, bg="#FFFFFF")
        body_win = detail_canvas.create_window(
            (0, 0), window=body, anchor="nw")

        body.bind("<Configure>",
            lambda e: detail_canvas.configure(
                scrollregion=detail_canvas.bbox("all")))
        detail_canvas.bind("<Configure>",
            lambda e: detail_canvas.itemconfig(body_win, width=e.width))
        detail_canvas.bind("<Enter>",
            lambda e: detail_canvas.bind_all(
                "<MouseWheel>",
                lambda ev: detail_canvas.yview_scroll(
                    int(-1*(ev.delta/120)), "units")))
        detail_canvas.bind("<Leave>",
            lambda e: detail_canvas.unbind_all("<MouseWheel>"))

        pad = 20

        # ── Threat alert box ──────────────────────────────────────────────────
        alert = tk.Frame(body, bg=threat_bg,
                         highlightbackground=threat_fg,
                         highlightthickness=1)
        alert.pack(fill="x", padx=pad, pady=(16, 0))

        tk.Label(alert, text=f"⚠  {f['threat_title']}",
                 font=tkfont.Font(family="Arial", size=12, weight="bold"),
                 bg=threat_bg, fg=threat_fg).pack(
                     anchor="w", padx=14, pady=(12, 4))
        desc_lbl = tk.Label(alert, text=f["threat_desc"],
                            font=self.f_small, bg=threat_bg,
                            fg="#374151", wraplength=340,
                            justify="left")
        desc_lbl.pack(anchor="w", padx=14, pady=(0, 12))
        alert.bind("<Configure>",
            lambda e, l=desc_lbl: l.configure(
                wraplength=max(200, e.width - 30)))

        # ── Info fields grid ──────────────────────────────────────────────────
        tk.Frame(body, bg="#E5E7EB", height=1).pack(
            fill="x", padx=pad, pady=(16, 0))

        fields_frame = tk.Frame(body, bg="#FFFFFF")
        fields_frame.pack(fill="x", padx=pad, pady=(12, 0))

        def field_row(parent, label, value, mono=False):
            row = tk.Frame(parent, bg="#FFFFFF")
            row.pack(fill="x", pady=4)
            tk.Label(row, text=label,
                     font=self.f_label, bg="#FFFFFF",
                     fg="#0D0D0D", width=14, anchor="w").pack(side="left")
            font = self.f_mono if mono else self.f_small
            tk.Label(row, text=value,
                     font=font, bg="#FFFFFF",
                     fg="#111827", anchor="w",
                     wraplength=260).pack(side="left", fill="x")

        field_row(fields_frame, "ALERT ID",       f.get("alert_id", "N/A"), mono=True)
        field_row(fields_frame, "PROCESS",        f["name"])
        field_row(fields_frame, "FILE / PATH",    f["path"], mono=True)
        field_row(fields_frame, "QUARANTINED",    f["date"])
        field_row(fields_frame, "DETECTION RULE", f["rule"], mono=True)
        field_row(fields_frame, "CONFIDENCE",     f["confidence"])
        field_row(fields_frame, "TAGS",           f.get("tags_str", "—"))

        # ── Divider ───────────────────────────────────────────────────────────
        tk.Frame(body, bg="#E5E7EB", height=1).pack(
            fill="x", padx=pad, pady=(16, 0))

        # ── Action buttons ────────────────────────────────────────────────────
        btn_row = tk.Frame(body, bg="#FFFFFF")
        btn_row.pack(fill="x", padx=pad, pady=16)

        ctk.CTkButton(
            btn_row,
            text="⟳   Restore File",
            font=("Arial", 12, "bold"),
            fg_color="#FFFFFF",
            hover_color="#F3F4F6",
            text_color="#090A0A",
            border_color="#D1D5DB",
            border_width=1,
            corner_radius=8,
            height=42,
            command=lambda: self._restore_file(f)
        ).pack(fill="x", pady=(0, 8))

        ctk.CTkButton(
            btn_row,
            text="🗑   Delete Permanently",
            font=("Arial", 12, "bold"),
            fg_color="#FEF2F2",
            hover_color="#FEE2E2",
            text_color="#DC2626",
            border_color="#FECACA",
            border_width=1,
            corner_radius=8,
            height=42,
            command=lambda: self._delete_file(f)
        ).pack(fill="x")

        # ── Warning note ──────────────────────────────────────────────────────
        note = tk.Frame(body, bg="#FFFBEB",
                        highlightbackground="#FDE68A",
                        highlightthickness=1)
        note.pack(fill="x", padx=pad, pady=(25))
        tk.Label(note,
                text="⚠  Restoring a file removes it from quarantine and may expose your system to risk. Only restore if you are certain the file is safe.",
                font=self.f_label, bg="#FFFBEB",
                fg="#92400E", wraplength=0,
                justify="left", anchor="w").pack(anchor="w", padx=12, pady=10, fill="x")

    # ─────────────────────────────────────────────────────────────────────────
    # Actions
    # ─────────────────────────────────────────────────────────────────────────
    def _restore_file(self, f: dict):
        confirmed = messagebox.askyesno(
            "Restore File",
            f"Restore '{f['name']}' to its original location?\n\n"
            f"{f['path']}\n\n"
            "⚠  This file was quarantined as a threat. Only restore if safe.",
            parent=self.win,
            icon="warning"
        )
        if confirmed:
            self._remove_file(f)
            self._toast(f"'{f['name']}' restored to original location.")

    def _delete_file(self, f: dict):
        confirmed = messagebox.askyesno(
            "Delete Permanently",
            f"Permanently delete '{f['name']}'?\n\nThis cannot be undone.",
            parent=self.win,
            icon="warning"
        )
        if confirmed:
            self._remove_file(f)
            self._toast(f"'{f['name']}' permanently deleted.")

    def _bulk_restore(self, files: list):
        names = "\n".join(f["name"] for f in files)
        confirmed = messagebox.askyesno(
            "Restore Files",
            f"Restore {len(files)} file(s) to original locations?\n\n{names}",
            parent=self.win,
            icon="warning"
        )
        if confirmed:
            for f in files:
                self._remove_file(f, re_render=False)
            self._render_file_list()
            self._show_detail_placeholder()
            self._toast(f"{len(files)} file(s) restored.")

    def _bulk_delete(self, files: list):
        confirmed = messagebox.askyesno(
            "Delete Permanently",
            f"Permanently delete {len(files)} file(s)? This cannot be undone.",
            parent=self.win,
            icon="warning"
        )
        if confirmed:
            for f in files:
                self._remove_file(f, re_render=False)
            self._render_file_list()
            self._show_detail_placeholder()
            self._toast(f"{len(files)} file(s) permanently deleted.")

    def _remove_file(self, f: dict, re_render: bool = True):
        if f in self.files:
            self.files.remove(f)
        if re_render:
            self._render_file_list()
            self._show_detail_placeholder()
            self.bulk_bar.pack_forget()

    def _toast(self, message: str):
        """Show a small status popup that auto-closes."""
        toast = tk.Toplevel(self.win)
        toast.overrideredirect(True)
        toast.configure(bg="#1F2937")

        tk.Label(toast, text=f"  ✓  {message}  ",
                 font=self.f_small, bg="#1F2937",
                 fg="#FFFFFF", pady=8).pack()

        # Center at bottom of window
        self.win.update_idletasks()
        wx = self.win.winfo_x() + self.win.winfo_width() // 2
        wy = self.win.winfo_y() + self.win.winfo_height() - 60
        toast.geometry(f"+{wx - 150}+{wy}")
        toast.after(2200, toast.destroy)


# ─────────────────────────────────────────────────────────────────────────────
# Standalone test
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Main App — Test")
    root.geometry("320x200")
    root.configure(bg="#FDFDFD")

    _files = load_quarantine_files()
    _count = len(_files)

    ctk.CTkButton(
        root,
        text=f"🔒  Open Quarantine ({_count})",
        font=("Arial", 13, "bold"),
        fg_color="#FEF2F2",
        hover_color="#FEE2E2",
        text_color="#DC2626",
        border_color="#FECACA",
        border_width=1,
        corner_radius=10,
        height=50,
        command=lambda: open_quarantine_page(root)
    ).pack(expand=True)

    root.mainloop()