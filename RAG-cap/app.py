"""
AI-Sec Endpoint Protection — Desktop Dashboard
Member 4 UI: Left = Recent Activity  |  Right = AI Plain-Language Explanation
RAG: LangChain + Chroma + Gemini
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import datetime
import json
import os

# ── Import RAG at module level ────────────────────────────────────────────────
try:
    from rag_chain import retriever, llm
    RAG_AVAILABLE = True
except Exception as _e:
    RAG_AVAILABLE = False
    _RAG_ERR_MSG  = str(_e)

# ── Import prompt_template.py ─────────────────────────────────────────────────
try:
    from prompt_template import build_nontechnical_prompt
except Exception:
    def build_nontechnical_prompt(alert, retrieved_context):
        threat   = alert.get("threat_name", "Unknown")
        activity = alert.get("malicious_activity", "Unknown")
        sev      = alert.get("severity", "Unknown")
        fname    = alert.get("file_name", "Unknown")
        status   = alert.get("status", "Quarantined")
        reason   = alert.get("reason", "")
        return f"""
You are explaining a security alert to a HOME USER who has never worked in IT.
Imagine a worried grandmother or a 10-year-old child reading this.
AI-Sec has ALREADY blocked the threat. The computer is safe.

━━━ INTERNAL DATA (never copy these words directly into your response) ━━━
File name   : {fname}
Threat type : {threat}
Severity    : {sev}
Activity    : {activity}
Reason      : {reason}
Status      : {status}

━━━ SANS SECURITY STEPS (use ONLY for section 4) ━━━
{retrieved_context}

━━━ MANDATORY WORD REPLACEMENTS ━━━
credentials/credential → passwords
LSASS/memory dump → the place that stores passwords
PowerShell/script → a hidden program
execute/execution → start or run
malicious → harmful or dangerous
quarantined → locked away safely
detected → found or caught
obfuscated/encoded → disguised
payload → harmful program
endpoint → your computer
persistence → stay hidden
malware → harmful program
dump/dumping → secretly copy
extract → steal
keylogger → a spy program watching your typing
ransomware → a program that locks your files
encrypt/encryption → lock up so you cannot open them
miner/mining → a program secretly using your computer
isolate → disconnect
lateral movement → spread to other devices
MITRE/SANS/WMI/API/C2/IOC/TTPs → never mention these

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WRITE EXACTLY THESE 4 SECTIONS.
Each section MUST be specific to THIS alert: {threat} — {activity}
DO NOT give a generic answer. Every section must describe THIS specific threat.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. 🔍 WHAT HAPPENED?
   Source: INTERNAL DATA only. Do NOT use SANS steps here.
   Write 2 plain sentences about THIS specific threat and what it did.
   Use the threat name and activity above — but rewrite in plain words.
   No technical words allowed.

   ✅ GOOD EXAMPLE for "attempted to dump LSASS memory to extract user credentials":
      A harmful program secretly tried to copy all the passwords
      saved on this computer so it could steal them.
      It was watching everything quietly, hoping you would not notice.

   ✅ GOOD EXAMPLE for "mass file encryption with .wcry extension":
      A dangerous program started locking all your personal files —
      photos, documents, everything — so you could not open them.
      It was demanding money in exchange for giving your files back.

   ✅ GOOD EXAMPLE for "keylogger recording keystrokes":
      A hidden spy program was secretly recording every key you pressed —
      including your passwords, messages, and personal details.
      It was quietly sending all of that information to a stranger.

2. ❓ WHY?
   Source: your own knowledge. Do NOT use SANS steps here.
   Write 1-2 plain sentences: what did the attacker want to gain
   from THIS specific type of threat?
   Be specific — not generic. Mention what THIS threat steals or does.


   ✅ GOOD EXAMPLE for credential dumping:
      Attackers steal passwords so they can log into your email,
      bank account, or social media to steal money or personal information.

   ✅ GOOD EXAMPLE for ransomware:
      Attackers lock your files so they can demand money —
      usually hundreds or thousands of dollars — to unlock them again.

3. 💡 ANALOGY
   Source: your own creativity.
   Write 1 real-life analogy for THIS specific type of threat.
   This MUST start on its OWN NEW LINE.
   Begin with: "It is a bit like..." OR "Think of it like..." OR "Imagine..."
   NEVER join this to the previous sentence with a comma.

   ✅ GOOD EXAMPLE for credential dumping:
      Think of it like a thief quietly going through your bag
      while you were distracted at the shops —
      hoping you would not notice until it was too late.

   ✅ GOOD EXAMPLE for ransomware:
      It is a bit like someone breaking into your house,
      putting all your belongings in locked boxes,
      and then sliding a note under the door asking for money.

4. 📋 WHAT YOU SHOULD DO
   Source: SANS SECURITY STEPS only. Translate each step into plain words.
   Do NOT invent steps from your own knowledge.
   Write 3-5 steps, each on its own line.
   Each step MUST start with: ✅ ⚠️ 🔒 🗑 📞 💡 🔄

   ✅ GOOD EXAMPLE (translated from SANS — plain words):
      ✅ Change your email and bank passwords from a different device.
      🔒 Make sure your Wi-Fi password is strong and private.
      📞 If you clicked something suspicious, call IT support now.
      🔄 Check your computer for problems using AI-Sec.

RULES: No technical words. Under 250 words total. Plain language only.
Every section must be SPECIFIC to the threat above, not generic.
"""

# ─────────────────────────────────────────────────────────────────────────────
#  PATH TO ALERTS FILE
# ─────────────────────────────────────────────────────────────────────────────
ALERTS_FILE = "D:\\RAG-cao\\member1_alerts.json"

# ─────────────────────────────────────────────────────────────────────────────
#  COLOUR PALETTE
# ─────────────────────────────────────────────────────────────────────────────
C = {
    "bg":      "#080C14",
    "sidebar": "#0B1120",
    "card":    "#0F1923",
    "card2":   "#111D2C",
    "border":  "#1A2940",
    "border2": "#1E3250",
    "accent":  "#00C2FF",
    "accent2": "#0A7CCC",
    "green":   "#00E676",
    "yellow":  "#FFD740",
    "red":     "#FF4444",
    "text":    "#D0E8FF",
    "text2":   "#6B8EAD",
    "text3":   "#3A5A7A",
    "white":   "#FFFFFF",
}
FONT_UI = "Segoe UI"

SEV_COLOR = {"High": C["red"], "Medium": C["yellow"], "Low": C["green"]}
SEV_ICON  = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE-LEVEL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_alerts(raw):
    normalised = []
    for a in raw:
        a.setdefault("file_name",
            a.get("file", a.get("alert_id", "Unknown")))
        a.setdefault("threat_name",
            a.get("mitre_technique", "Unknown Threat"))
        if "detection_layer" not in a:
            sev = a.get("severity", "Medium")
            a["detection_layer"] = {
                "High":   "ML Model (Layer 3)",
                "Medium": "Rule-Based (Layer 2)",
                "Low":    "VirusTotal (Layer 1)",
            }.get(sev, "Rule-Based (Layer 2)")
        a.setdefault("severity",  "Medium")
        a.setdefault("status",    "Quarantined")
        a.setdefault("time",      "—")
        a.setdefault("file_path", a.get("path", "—"))
        normalised.append(a)
    return normalised


def _all_children(widget):
    children = widget.winfo_children()
    for child in children:
        children += child.winfo_children()
    return children


def _recolor_recursive(widget, old, new):
    try:
        if widget.cget("bg") == old:
            widget.configure(bg=new)
    except tk.TclError:
        pass
    for child in widget.winfo_children():
        _recolor_recursive(child, old, new)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN APP
# ─────────────────────────────────────────────────────────────────────────────
class AiSecApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("AI-Sec Endpoint Protection")
        self.geometry("1300x800")
        self.minsize(1100, 680)
        self.configure(bg=C["bg"])
        self.resizable(True, True)

        self.alerts = []
        try:
            with open(ALERTS_FILE) as f:
                data = json.load(f)
            raw = data.get("alerts", data) if isinstance(data, dict) else data
            self.alerts = _normalise_alerts(raw)
            print(f"[INFO] Loaded {len(self.alerts)} alerts from {ALERTS_FILE}")
        except Exception as e:
            print(f"[WARNING] Could not auto-load alerts: {e}")

        self.selected_alert = None
        self.ai_busy        = False

        self._style_ttk()
        self._build_ui()

    # ── TTK styling ───────────────────────────────────────────────────────────
    def _style_ttk(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Treeview",
            background=C["card"], fieldbackground=C["card"],
            foreground=C["text"], rowheight=38,
            font=(FONT_UI, 10), borderwidth=0, relief="flat")
        s.configure("Treeview.Heading",
            background=C["card2"], foreground=C["accent"],
            font=(FONT_UI, 9, "bold"), relief="flat", borderwidth=0)
        s.map("Treeview",
            background=[("selected", C["accent2"])],
            foreground=[("selected", C["white"])])
        s.configure("Vertical.TScrollbar",
            background=C["card2"], troughcolor=C["bg"],
            arrowcolor=C["text2"], borderwidth=0, relief="flat")
        s.configure("TProgressbar",
            troughcolor=C["border"], background=C["accent"],
            borderwidth=0, relief="flat")

    # ── Root layout ───────────────────────────────────────────────────────────
    def _build_ui(self):
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self._build_sidebar()

        self.content = tk.Frame(self, bg=C["bg"])
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(1, weight=1)

        self._build_topbar()
        self._build_main_panel()

    # ══════════════════════════════════════════════════════════════════════════
    #  SIDEBAR
    # ══════════════════════════════════════════════════════════════════════════
    def _build_sidebar(self):
        sb = tk.Frame(self, bg=C["sidebar"], width=220)
        sb.grid(row=0, column=0, sticky="ns")
        sb.pack_propagate(False)
        sb.grid_propagate(False)

        lf = tk.Frame(sb, bg=C["sidebar"])
        lf.pack(fill="x", pady=(24, 8), padx=18)
        tk.Label(lf, text="🛡", font=("Segoe UI", 22),
                 bg=C["sidebar"], fg=C["accent"]).pack(side="left")
        lf2 = tk.Frame(lf, bg=C["sidebar"])
        lf2.pack(side="left", padx=8)
        tk.Label(lf2, text="AI-SEC",
                 font=(FONT_UI, 13, "bold"), bg=C["sidebar"],
                 fg=C["white"]).pack(anchor="w")
        tk.Label(lf2, text="Endpoint Protection",
                 font=(FONT_UI, 7), bg=C["sidebar"],
                 fg=C["text2"]).pack(anchor="w")

        tk.Frame(sb, bg=C["border"], height=1).pack(fill="x", padx=18, pady=10)

        pill = tk.Frame(sb, bg=C["border2"])
        pill.pack(fill="x", padx=14, pady=(0, 20))
        inn = tk.Frame(pill, bg=C["border2"])
        inn.pack(padx=12, pady=8)
        dot = tk.Canvas(inn, width=10, height=10,
                        bg=C["border2"], highlightthickness=0)
        dot.create_oval(1, 1, 9, 9, fill=C["green"], outline="")
        dot.pack(side="left")
        tk.Label(inn, text="  Protection Active",
                 font=(FONT_UI, 9, "bold"), bg=C["border2"],
                 fg=C["green"]).pack(side="left")


        tk.Label(sb, text="TODAY'S SUMMARY",
                 font=(FONT_UI, 7, "bold"), bg=C["sidebar"],
                 fg=C["text3"]).pack(anchor="w", padx=18, pady=(0, 6))

        high_count = len([a for a in self.alerts if a.get("severity") == "High"])
        quar_count = len([a for a in self.alerts if a.get("status") == "Quarantined"])
        for label, val in [
            ("🔍 Files Scanned",   "1,284"),
            ("🦠 Threats Blocked", str(high_count)),
            ("🔒 Quarantined",     str(quar_count)),
        ]:
            row = tk.Frame(sb, bg=C["sidebar"])
            row.pack(fill="x", padx=18, pady=3)
            tk.Label(row, text=label, font=(FONT_UI, 9),
                     bg=C["sidebar"], fg=C["text2"]).pack(side="left")
            tk.Label(row, text=val, font=(FONT_UI, 9, "bold"),
                     bg=C["sidebar"], fg=C["text"]).pack(side="right")

        tk.Frame(sb, bg=C["border"], height=1).pack(fill="x", padx=18, pady=14)

        tk.Button(sb, text="📂  Load Alerts JSON",
                  command=self._load_json,
                  bg=C["accent2"], fg=C["white"],
                  font=(FONT_UI, 9, "bold"),
                  relief="flat", bd=0, padx=10, pady=8,
                  cursor="hand2", activebackground=C["accent"]
                  ).pack(fill="x", padx=14, pady=(0, 8))

        tk.Frame(sb, bg=C["border"], height=1).pack(fill="x", padx=18, pady=(6, 10))
        tk.Label(sb, text="DETECTION LAYERS",
                 font=(FONT_UI, 7, "bold"), bg=C["sidebar"],
                 fg=C["text3"]).pack(anchor="w", padx=18, pady=(0, 6))
        for badge, name, color in [
            ("● Layer 1", "VirusTotal", C["accent"]),
            ("● Layer 2", "Rule-Based", C["yellow"]),
            ("● Layer 3", "ML Model",   C["green"]),
        ]:
            row = tk.Frame(sb, bg=C["sidebar"])
            row.pack(fill="x", padx=18, pady=2)
            tk.Label(row, text=badge, font=(FONT_UI, 8, "bold"),
                     bg=C["sidebar"], fg=color).pack(side="left")
            tk.Label(row, text=f"  {name}", font=(FONT_UI, 8),
                     bg=C["sidebar"], fg=C["text2"]).pack(side="left")

        tk.Frame(sb, bg=C["border"], height=1).pack(
            fill="x", padx=18, pady=10, side="bottom")
        tk.Label(sb, text="v1.0.0  ·  Cambodia Edition",
                 font=(FONT_UI, 7), bg=C["sidebar"],
                 fg=C["text3"]).pack(side="bottom", pady=8)

    # ══════════════════════════════════════════════════════════════════════════
    #  TOP BAR
    # ══════════════════════════════════════════════════════════════════════════
    def _build_topbar(self):
        tb = tk.Frame(self.content, bg=C["sidebar"], height=58)
        tb.grid(row=0, column=0, sticky="ew")
        tb.grid_propagate(False)
        tb.columnconfigure(0, weight=1)
        tk.Label(tb, text="AI-Sec  ·  Incident Response Dashboard",
                 font=(FONT_UI, 12, "bold"), bg=C["sidebar"],
                 fg=C["text"]).grid(row=0, column=0, padx=20, sticky="w", pady=18)
        rhs = tk.Frame(tb, bg=C["sidebar"])
        rhs.grid(row=0, column=1, padx=16, sticky="e")
        now = datetime.datetime.now().strftime("%d %b %Y  %H:%M")
        tk.Label(rhs, text=f"🕐 {now}", font=(FONT_UI, 9),
                 bg=C["sidebar"], fg=C["text2"]).pack(side="left", padx=12)
        tk.Label(rhs, text="👤 Admin", font=(FONT_UI, 9),
                 bg=C["sidebar"], fg=C["text2"]).pack(side="left", padx=8)
        tk.Frame(self.content, bg=C["border"], height=1).grid(
            row=0, column=0, sticky="ews", pady=(57, 0))


    # ══════════════════════════════════════════════════════════════════════════
    #  MAIN PANEL
    # ══════════════════════════════════════════════════════════════════════════
    def _build_main_panel(self):
        outer = tk.Frame(self.content, bg=C["bg"])
        outer.grid(row=1, column=0, sticky="nsew")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=0)
        outer.columnconfigure(1, weight=1)
        self._build_left_panel(outer)
        self._build_right_panel(outer)

    # ── LEFT panel ────────────────────────────────────────────────────────────
    def _build_left_panel(self, parent):
        left = tk.Frame(parent, bg=C["bg"], width=400)
        left.grid(row=0, column=0, sticky="nsew", padx=(16, 6), pady=16)
        left.grid_propagate(False)
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        hdr = tk.Frame(left, bg=C["bg"])
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        tk.Label(hdr, text="🚨  Recent Activity",
                 font=(FONT_UI, 12, "bold"), bg=C["bg"],
                 fg=C["text"]).pack(side="left")
        self.count_lbl = tk.Label(hdr,
                 text=f"  {len(self.alerts)} alerts",
                 font=(FONT_UI, 9), bg=C["bg"], fg=C["text2"])
        self.count_lbl.pack(side="left", pady=3)

        list_canvas = tk.Canvas(left, bg=C["bg"], highlightthickness=0)
        list_canvas.grid(row=1, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(left, orient="vertical", command=list_canvas.yview)
        vsb.grid(row=1, column=1, sticky="ns")
        list_canvas.configure(yscrollcommand=vsb.set)

        self.card_frame = tk.Frame(list_canvas, bg=C["bg"])
        self.card_frame.columnconfigure(0, weight=1)
        list_canvas.create_window((0, 0), window=self.card_frame, anchor="nw")
        self.card_frame.bind("<Configure>",
            lambda e: list_canvas.configure(
                scrollregion=list_canvas.bbox("all")))
        list_canvas.bind("<MouseWheel>",
            lambda e: list_canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        self._render_activity_cards()

    def _render_activity_cards(self):
        for w in self.card_frame.winfo_children():
            w.destroy()
        for i, alert in enumerate(self.alerts):
            self._make_activity_card(self.card_frame, alert, i)

    def _make_activity_card(self, parent, alert, idx):
        sev   = alert.get("severity", "Low")
        color = SEV_COLOR.get(sev, C["text2"])
        icon  = SEV_ICON.get(sev, "⚪️")

        card = tk.Frame(parent, bg=C["card"], cursor="hand2")
        card.grid(row=idx, column=0, sticky="ew", pady=(0, 6), padx=2)
        card.columnconfigure(0, weight=1)

        tk.Frame(card, bg=color, width=4).pack(side="left", fill="y")

        body = tk.Frame(card, bg=C["card"])
        body.pack(fill="both", expand=True, padx=12, pady=10)
        body.columnconfigure(0, weight=1)

        r1 = tk.Frame(body, bg=C["card"])
        r1.pack(fill="x")
        tk.Label(r1, text=f"  {alert['file_name']}",
                 font=(FONT_UI, 10, "bold"), bg=C["card"],
                 fg=C["white"]).pack(side="left")
        tk.Label(r1, text=f" {icon} {sev} ",
                 font=(FONT_UI, 8, "bold"),
                 bg=color, fg=C["bg"],
                 padx=4, pady=1).pack(side="right")

        tk.Label(body, text=f"  🦠  {alert['threat_name']}",
                 font=(FONT_UI, 9), bg=C["card"],
                 fg=color).pack(anchor="w", pady=(2, 0))

        r3 = tk.Frame(body, bg=C["card"])
        r3.pack(fill="x", pady=(3, 0))
        tk.Label(r3, text=f"  🔍  {alert['detection_layer']}",
                 font=(FONT_UI, 8), bg=C["card"],
                 fg=C["text2"]).pack(side="left")
        tk.Label(r3, text=alert.get("time", "—"),
                 font=(FONT_UI, 8), bg=C["card"],
                 fg=C["text3"]).pack(side="right")


        r4 = tk.Frame(body, bg=C["card"])
        r4.pack(fill="x", pady=(4, 0))
        st_color = {
            "Quarantined": C["yellow"],
            "Deleted":     C["red"],
            "Released":    C["green"],
        }.get(alert.get("status", ""), C["text2"])
        tk.Label(r4, text=f"  Status: {alert.get('status', 'Quarantined')}",
                 font=(FONT_UI, 8, "bold"), bg=C["card"],
                 fg=st_color).pack(side="left")
        tk.Label(r4, text="Click for AI explanation →",
                 font=(FONT_UI, 8), bg=C["card"],
                 fg=C["text3"]).pack(side="right")

        def on_enter(e, c=card):
            c.configure(bg=C["card2"])
            for w in c.winfo_children():
                _recolor_recursive(w, C["card"], C["card2"])

        def on_leave(e, c=card):
            c.configure(bg=C["card"])
            for w in c.winfo_children():
                _recolor_recursive(w, C["card2"], C["card"])

        def on_click(e, a=alert):
            self._select_alert(a)

        for widget in _all_children(card):
            widget.bind("<Enter>",    on_enter)
            widget.bind("<Leave>",    on_leave)
            widget.bind("<Button-1>", on_click)
        card.bind("<Enter>",    on_enter)
        card.bind("<Leave>",    on_leave)
        card.bind("<Button-1>", on_click)

    # ── RIGHT panel ───────────────────────────────────────────────────────────
    def _build_right_panel(self, parent):
        right = tk.Frame(parent, bg=C["bg"])
        right.grid(row=0, column=1, sticky="nsew", padx=(0, 16), pady=16)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        hdr = tk.Frame(right, bg=C["bg"])
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        tk.Label(hdr, text="🤖  AI Explanation",
                 font=(FONT_UI, 12, "bold"), bg=C["bg"],
                 fg=C["text"]).pack(side="left")
        tk.Label(hdr, text="  Plain-language · Gemini + SANS RAG",
                 font=(FONT_UI, 9), bg=C["bg"],
                 fg=C["text2"]).pack(side="left", pady=3)

        self.info_bar = tk.Frame(right, bg=C["card2"])
        self.info_bar.grid(row=0, column=0, sticky="ew", pady=(34, 0))
        self.info_file_lbl = tk.Label(self.info_bar,
            text="← Select an alert on the left to get an explanation",
            font=(FONT_UI, 10, "bold"), bg=C["card2"],
            fg=C["text2"], anchor="w")
        self.info_file_lbl.pack(side="left", padx=16, pady=10,
                                fill="x", expand=True)
        self.info_sev_lbl = tk.Label(self.info_bar, text="",
            font=(FONT_UI, 9, "bold"), bg=C["card2"], fg=C["text2"])
        self.info_sev_lbl.pack(side="right", padx=16)

        exp_canvas = tk.Canvas(right, bg=C["bg"], highlightthickness=0)
        exp_canvas.grid(row=1, column=0, sticky="nsew", pady=(6, 4))
        vsb = ttk.Scrollbar(right, orient="vertical", command=exp_canvas.yview)
        vsb.grid(row=1, column=1, sticky="ns", pady=(6, 4))
        exp_canvas.configure(yscrollcommand=vsb.set)
        exp_canvas.bind("<MouseWheel>",
            lambda e: exp_canvas.yview_scroll(-1 * (e.delta // 120), "units"))
        self._exp_canvas = exp_canvas

        self.exp_sections_frame = tk.Frame(exp_canvas, bg=C["bg"])
        self.exp_sections_frame.columnconfigure(0, weight=1)
        self._exp_canvas_win = exp_canvas.create_window(
            (0, 0), window=self.exp_sections_frame, anchor="nw")
        self.exp_sections_frame.bind("<Configure>",
            lambda e: exp_canvas.configure(
                scrollregion=exp_canvas.bbox("all")))
        exp_canvas.bind("<Configure>",
            lambda e: exp_canvas.itemconfig(
                self._exp_canvas_win, width=e.width))


        bot = tk.Frame(right, bg=C["bg"])
        bot.grid(row=2, column=0, columnspan=2, sticky="ew")
        bot.columnconfigure(0, weight=1)
        self.progress_lbl = tk.Label(bot, text="",
            font=(FONT_UI, 9), bg=C["bg"], fg=C["text2"])
        self.progress_lbl.grid(row=0, column=0, sticky="w", pady=4)
        self.explain_btn = tk.Button(bot,
            text="🤖  Generate AI Explanation",
            command=self._run_ai_explain,
            bg=C["accent2"], fg=C["white"],
            font=(FONT_UI, 10, "bold"),
            relief="flat", bd=0, padx=20, pady=10,
            cursor="hand2", state="disabled",
            activebackground=C["accent"])
        self.explain_btn.grid(row=0, column=1, padx=(8, 0), pady=4)

        self._show_placeholder()

    # ── Section helpers ───────────────────────────────────────────────────────
    def _clear_sections(self):
        for w in self.exp_sections_frame.winfo_children():
            w.destroy()

    def _make_section_box(self, parent, row, header_text, header_color,
                          border_color, content_lines, line_color):
        box = tk.Frame(parent, bg=C["card"], bd=0)
        box.grid(row=row, column=0, sticky="ew", padx=4, pady=(0, 10))
        box.columnconfigure(0, weight=1)

        tk.Frame(box, bg=border_color, height=3).grid(
            row=0, column=0, sticky="ew")

        hdr = tk.Frame(box, bg=C["card2"])
        hdr.grid(row=1, column=0, sticky="ew")
        tk.Label(hdr, text=header_text,
                 font=(FONT_UI, 10, "bold"),
                 bg=C["card2"], fg=header_color,
                 anchor="w").pack(side="left", padx=14, pady=8)

        body = tk.Frame(box, bg=C["card"])
        body.grid(row=2, column=0, sticky="ew")
        body.columnconfigure(0, weight=1)

        for i, line in enumerate(content_lines):
            line = line.strip()
            if not line:
                continue
            is_action = any(line.startswith(e) for e in
                ("✅", "⚠️", "🔒", "🗑", "📞", "💡", "🔄",
                 "🛑", "⛔️", "📱", "💾", "⚠️", "👀"))
            fg = line_color if is_action else C["text"]
            tk.Label(body, text=line,
                     font=(FONT_UI, 10),
                     bg=C["card"], fg=fg,
                     anchor="w", wraplength=480, justify="left"
                     ).grid(row=i, column=0, sticky="ew",
                            padx=14, pady=(6 if i == 0 else 3))

        tk.Frame(box, bg=C["card"], height=10).grid(
            row=3, column=0, sticky="ew")
        return box

    def _show_placeholder(self):
        self._clear_sections()
        ph = tk.Frame(self.exp_sections_frame, bg=C["bg"])
        ph.grid(row=0, column=0, sticky="nsew", pady=60)
        ph.columnconfigure(0, weight=1)
        tk.Label(ph, text="🛡", font=("Segoe UI", 36),
                 bg=C["bg"], fg=C["text3"]).pack()
        tk.Label(ph, text="Select any alert on the left",
                 font=(FONT_UI, 11), bg=C["bg"], fg=C["text2"]).pack(pady=(10, 2))
        tk.Label(ph, text="to get a plain-language AI explanation",
                 font=(FONT_UI, 10), bg=C["bg"], fg=C["text3"]).pack()
        tk.Label(ph, text="Powered by Gemini AI  ·  SANS RAG",
                 font=(FONT_UI, 8), bg=C["bg"], fg=C["text3"]).pack(pady=(14, 0))

    # ── Alert selection — shows detection summary immediately ─────────────────
    def _select_alert(self, alert):
        self.selected_alert = alert
        sev   = alert.get("severity", "Low")
        color = SEV_COLOR.get(sev, C["text2"])
        icon  = SEV_ICON.get(sev, "⚪️")

        self.info_file_lbl.configure(
            text=f"  {alert.get('file_name', '?')}   ·   "
                 f"{alert.get('threat_name', '?')}",
            fg=C["text"])
        self.info_sev_lbl.configure(
            text=f"{icon} {sev}  |  {alert.get('status','Quarantined')}",
            fg=color)
        self.explain_btn.configure(state="normal")


        self._clear_sections()
        self._make_section_box(
            self.exp_sections_frame, row=0,
            header_text="📋  Detection Summary",
            header_color=C["accent"],
            border_color=C["accent"],
            content_lines=[
                f"Alert ID    :  {alert.get('alert_id','—')}",
                f"File        :  {alert.get('file_name','—')}",
                f"Threat      :  {alert.get('threat_name','—')}",
                f"Severity    :  {icon} {sev}",
                f"Detected by :  {alert.get('detection_layer','—')}",
                f"Activity    :  {alert.get('malicious_activity','—')}",
                f"Status      :  {alert.get('status','—')}",
                f"Time        :  {alert.get('time','—')}",
            ],
            line_color=C["text2"])

        tk.Label(self.exp_sections_frame,
            text="Press  🤖 Generate AI Explanation  to get a plain-language analysis",
            font=(FONT_UI, 9), bg=C["bg"], fg=C["text3"]
            ).grid(row=1, column=0, pady=(0, 8), padx=8)

    # ── AI Explanation ────────────────────────────────────────────────────────
    def _run_ai_explain(self):
        if not self.selected_alert or self.ai_busy:
            return
        self.ai_busy = True
        self.explain_btn.configure(state="disabled", text="⏳  Generating…")
        self.progress_lbl.configure(
            text="🔄  Retrieving SANS guidance + calling Gemini…")

        self._clear_sections()
        loading = tk.Frame(self.exp_sections_frame, bg=C["bg"])
        loading.grid(row=0, column=0, pady=50)
        loading.columnconfigure(0, weight=1)
        tk.Label(loading, text="🤖  Analyzing threat…",
                 font=(FONT_UI, 11, "bold"), bg=C["bg"],
                 fg=C["accent"]).pack()
        tk.Label(loading, text="Querying SANS knowledge base via RAG…",
                 font=(FONT_UI, 9), bg=C["bg"], fg=C["text2"]).pack(pady=(6, 2))
        tk.Label(loading, text="Generating plain-language explanation…",
                 font=(FONT_UI, 9), bg=C["bg"], fg=C["text3"]).pack()

        # Pass a COPY of the alert so the thread has its own reference
        threading.Thread(
            target=self._ai_worker,
            args=(dict(self.selected_alert),),
            daemon=True
        ).start()

    def _ai_worker(self, alert):
        """
        Runs in background thread.
        - Sections 1, 2, 3: Gemini paraphrases from alert-specific data.
        - Section 4: Gemini translates SANS RAG steps only.

        Each alert produces a unique answer because:
        1. The full alert dict (threat_name, malicious_activity, reason)
           is injected into the prompt — Gemini must describe THAT specific threat.
        2. The RAG query uses all alert fields to find the most relevant SANS chunk.
        """
        try:
            if RAG_AVAILABLE:
                # Build specific RAG query from THIS alert's fields
                query = " ".join(filter(None, [
                    alert.get("mitre_technique", ""),
                    alert.get("malicious_activity", ""),
                    alert.get("threat_name", ""),
                    alert.get("reason", ""),
                ]))

                docs    = retriever.invoke(query)
                context = "\n\n".join([
                    f"[SANS Step {i+1}]\n{d.page_content}"
                    for i, d in enumerate(docs)
                ])

                # Debug output so you can verify SANS chunks per alert
                print(f"\n{'='*60}")
                print(f"[ALERT]  {alert.get('alert_id')} — {alert.get('threat_name')}")
                print(f"[QUERY]  {query}")
                print(f"[RAG]    Retrieved {len(docs)} chunk(s):")
                for i, d in enumerate(docs):
                    print(f"  Chunk {i+1}: {d.page_content[:100]}...")
                print(f"{'='*60}")


                # Build prompt with THIS alert's data — guarantees unique answer
                prompt   = build_nontechnical_prompt(alert, context)
                response = llm.invoke(prompt)
                result   = response.content

            else:
                result = self._offline_explanation(alert)

            self.after(0, self._render_explanation, alert, result)

        except Exception as e:
            err = str(e)
            if "429" in err or "RESOURCE_EXHAUSTED" in err or "quota" in err.lower():
                result = self._offline_explanation(alert)
                self.after(0, self._render_explanation, alert, result)
                self.after(0, lambda: self.progress_lbl.configure(
                    text="⚠️  Gemini quota reached — showing offline explanation"))
            else:
                self.after(0, self._render_error, err)

    # ── Parse Gemini output into 4 sections ───────────────────────────────────
    def _parse_sections(self, text):
        sections = {
            "what_happened": [],
            "why":           [],
            "analogy":       [],
            "what_to_do":    [],
        }
        current = None

        for line in text.strip().splitlines():
            stripped = line.strip()
            low      = stripped.lower()

            is_s1 = (low.startswith("1.") or "🔍" in stripped or
                     low.startswith("what happened"))
            is_s2 = (low.startswith("2.") or "❓" in stripped or
                     (low.startswith("why") and len(stripped) < 20))
            is_s3 = (low.startswith("3.") or "💡" in stripped or
                     (low.startswith("analogy") and len(stripped) < 20))
            is_s4 = (low.startswith("4.") or "📋" in stripped or
                     low.startswith("what you should") or
                     low.startswith("what to do") or
                     low.startswith("recommended"))

            if is_s1:
                current = "what_happened"; continue
            elif is_s2:
                current = "why"; continue
            elif is_s3:
                current = "analogy"; continue
            elif is_s4:
                current = "what_to_do"; continue

            if current and stripped:
                sections[current].append(stripped)

        if not any(sections.values()):
            sections["what_happened"] = [
                l.strip() for l in text.strip().splitlines() if l.strip()
            ]
        return sections

    # ── Render 4 section boxes ────────────────────────────────────────────────
    def _render_explanation(self, alert, text):
        self._clear_sections()
        sections = self._parse_sections(text)

        # Section 1 — What Happened? (Gemini paraphrase of alert data)
        self._make_section_box(
            self.exp_sections_frame, row=0,
            header_text="🔍  WHAT HAPPENED?",
            header_color=C["accent2"], border_color=C["accent2"],
            content_lines=sections["what_happened"] or ["No information available."],
            line_color=C["text"])

        # Section 2 — Why? (Gemini explains attacker's goal)
        self._make_section_box(
            self.exp_sections_frame, row=1,
            header_text="❓  WHY?",
            header_color=C["accent"], border_color=C["accent"],
            content_lines=sections["why"] or ["No information available."],
            line_color=C["text"])

        # Section 3 — Analogy (Gemini real-life comparison)
        self._make_section_box(
            self.exp_sections_frame, row=2,
            header_text="💡  ANALOGY",
            header_color=C["yellow"], border_color=C["yellow"],
            content_lines=sections["analogy"] or ["No analogy available."],
            line_color=C["text"])


        # Section 4 — Recommendations (SANS RAG steps only)
        self._make_section_box(
            self.exp_sections_frame, row=3,
            header_text="📋  WHAT YOU SHOULD DO  (based on security guidance)",
            header_color=C["green"], border_color=C["green"],
            content_lines=sections["what_to_do"] or ["No actions available."],
            line_color=C["green"])

        # Footer
        tk.Label(self.exp_sections_frame,
            text="🤖 Gemini AI  ·  SANS RAG Knowledge Base  ·  plain-language for home users",
            font=(FONT_UI, 8), bg=C["bg"], fg=C["text3"]
            ).grid(row=4, column=0, pady=(0, 10), padx=8)

        self._exp_canvas.yview_moveto(0)
        self.progress_lbl.configure(text="✅  Explanation ready")
        self.explain_btn.configure(state="normal", text="🔄  Regenerate")
        self.ai_busy = False

        # Auto-save to ai_explanations.json
        self._save_explanation(alert, sections)

    def _save_explanation(self, alert, sections):
        """
        Saves the AI explanation for this alert to ai_explanations.json.
        Each alert is saved as one entry. If the alert was already saved
        before (same alert_id), it is overwritten with the latest result.
        """
        OUTPUT_FILE = "ai_explanations.json"

        # Build the entry to save
        entry = {
            "alert_id":        alert.get("alert_id", "Unknown"),
            "file_name":       alert.get("file_name", "Unknown"),
            "threat_name":     alert.get("threat_name", "Unknown"),
            "severity":        alert.get("severity",  "Unknown"),
            "detection_layer": alert.get("detection_layer", "Unknown"),
            "status":          alert.get("status", "Quarantined"),
            "time":            alert.get("time", ""),
            "ai_explanation": {
                "what_happened": " ".join(sections.get("what_happened", [])),
                "why":           " ".join(sections.get("why",           [])),
                "analogy":       " ".join(sections.get("analogy",       [])),
                "what_to_do":    sections.get("what_to_do", []),
            },
            "saved_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Load existing file if it exists
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                existing = []
        except (FileNotFoundError, json.JSONDecodeError):
            existing = []

        # Overwrite entry if same alert_id already saved, else append
        alert_id = entry["alert_id"]
        replaced = False
        for i, e in enumerate(existing):
            if e.get("alert_id") == alert_id:
                existing[i] = entry
                replaced = True
                break
        if not replaced:
            existing.append(entry)

        # Write back
        try:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2, ensure_ascii=False)
            print(f"[SAVED] {alert_id} → {OUTPUT_FILE}  ({len(existing)} total)")
        except Exception as e:
            print(f"[SAVE ERROR] {e}")

    def _render_error(self, err):
        self._clear_sections()
        self._make_section_box(
            self.exp_sections_frame, row=0,
            header_text="✖️  Error",
            header_color=C["red"], border_color=C["red"],
            content_lines=[
                f"  {err}", "",
                "  Make sure:",
                "  •  Your .env file contains GEMINI_API_KEY",
                "  •  The vector_db/ folder exists (run build_vector_db.py)",
                "  •  You have internet access for Gemini API",
            ],
            line_color=C["text2"])
        self.progress_lbl.configure(text="✖️  Error — see details above")
        self.explain_btn.configure(state="normal", text="🤖  Retry")
        self.ai_busy = False


    def _offline_explanation(self, alert):
        sev          = alert.get("severity", "Low")
        activity     = alert.get("malicious_activity", "suspicious activity")
        activity_low = activity.lower()

        # ── Section 1: unique description per activity type ───────────────────
        if any(w in activity_low for w in ["lsass", "credential dump", "dump", "extract user"]):
            what = (
                "A dangerous program secretly tried to copy all the passwords "
                "saved on this computer so it could steal them. "
                "It was running quietly in the background, gathering your login "
                "details without you ever knowing it was there."
            )
        elif any(w in activity_low for w in ["keylog", "keystroke", "recording key", "input capture"]):
            what = (
                "A hidden spy program was secretly watching and recording "
                "every single key you pressed on your keyboard. "
                "It was capturing your passwords, messages, and personal details "
                "and quietly sending them to a stranger."
            )
        elif any(w in activity_low for w in ["encrypt", "wcry", "ransom", "shadow copy"]):
            what = (
                "A very dangerous program started locking all your personal files — "
                "your photos, documents, and videos — so you could no longer open them. "
                "It was also trying to erase your backup copies so you would have "
                "no way to get your files back without paying money."
            )
        elif any(w in activity_low for w in ["wmi", "remote command", "persistence", "startup"]):
            what = (
                "A harmful program secretly made itself at home on your computer "
                "so it could keep running even after you restart it. "
                "It was letting attackers send hidden instructions to your computer "
                "from somewhere else on the internet."
            )
        elif any(w in activity_low for w in ["powershell", "encoded", "obfuscat", "script"]):
            what = (
                "A disguised program ran hidden instructions on your computer "
                "without you knowing, trying to take control of it from the inside. "
                "It was working in secret to let an attacker access your files and data."
            )
        elif any(w in activity_low for w in ["miner", "mining", "cpu", "monero", "cryptocurrency"]):
            what = (
                "A program secretly started using your computer's power "
                "to make money for attackers without your permission. "
                "This slows your computer down and uses up your electricity "
                "while the attackers profit."
            )
        elif any(w in activity_low for w in ["browser", "extension", "tracking", "browsing"]):
            what = (
                "A sneaky program quietly changed your internet browser settings "
                "without asking you and started tracking every website you visit. "
                "It was collecting information about what you read and buy online "
                "to send you unwanted advertisements."
            )
        elif any(w in activity_low for w in ["trojan", "invoice", "pdf", "disguised", "payload"]):
            what = (
                "A harmful program disguised itself as a normal file to trick you into running it. "
                "Once it got in, it tried to contact attackers on the internet "
                "and open a door for them to get inside your computer."
            )
        elif any(w in activity_low for w in ["macro", "auto-run", "document"]):
            what = (
                "A harmful program was hidden inside a document and set to run "
                "automatically the moment you opened it. "
                "It was waiting silently to carry out the attacker's instructions "
                "as soon as you clicked the file."
            )
        else:
            what = (

                "A harmful program was secretly active on your computer. "
                f"It was trying to: {activity_low}. "
                "It was working in the background without your knowledge."
            )

        # ── Section 2: why — specific per threat type ─────────────────────────
        if any(w in activity_low for w in ["lsass", "credential", "dump", "keylog", "keystroke"]):
            why = ("Attackers steal passwords so they can log into your email, "
                   "bank account, or social media to steal money or take over your accounts.")
        elif any(w in activity_low for w in ["encrypt", "wcry", "ransom"]):
            why = ("Attackers lock your files so they can demand money — "
                   "sometimes hundreds or thousands of dollars — to unlock them again.")
        elif any(w in activity_low for w in ["miner", "mining", "cpu"]):
            why = ("Attackers secretly use your computer's power to make money for themselves, "
                   "slowing your computer down while you pay the electricity bill.")
        elif any(w in activity_low for w in ["wmi", "powershell", "remote", "persistence"]):
            why = ("Attackers want permanent access to your computer so they can "
                   "steal files, spy on you, or use your computer to attack others.")
        elif any(w in activity_low for w in ["browser", "extension", "tracking"]):
            why = ("Attackers collect your browsing habits and sell that information "
                   "to advertising companies — your personal data is valuable to them.")
        else:
            why = ("Attackers use this type of program to steal information, "
                   "take control of your computer, or make money at your expense.")

        # ── Section 3: analogy — specific per threat type ─────────────────────
        if any(w in activity_low for w in ["lsass", "credential", "dump"]):
            analogy = ("Think of it like a thief quietly going through your bag "
                       "while you were distracted at the shops — "
                       "writing down all your card details and passwords, "
                       "hoping you would not notice until it was too late.")
        elif any(w in activity_low for w in ["keylog", "keystroke"]):
            analogy = ("Imagine someone standing silently behind you, "
                       "writing down every single key you press — "
                       "every password, every message — "
                       "without you ever knowing they were there.")
        elif any(w in activity_low for w in ["encrypt", "wcry", "ransom"]):
            analogy = ("It is a bit like someone breaking into your home, "
                       "putting all your belongings into locked boxes, "
                       "and sliding a note under the door asking for money to return them.")
        elif any(w in activity_low for w in ["miner", "mining", "cpu"]):
            analogy = ("Think of it like someone secretly borrowing your car every night "
                       "to run their own errands — wearing out your engine while you sleep, "
                       "without ever asking your permission.")
        elif any(w in activity_low for w in ["wmi", "powershell", "remote", "persistence"]):
            analogy = ("It is a bit like a burglar who does not steal anything on the first visit — "
                       "they just make a copy of your house key so they can come back "
                       "whenever they want, without you ever knowing.")
        elif any(w in activity_low for w in ["browser", "extension", "tracking"]):
            analogy = ("Imagine a stranger secretly following you around every shop you visit, "
                       "writing down everything you look at and buy — "
                       "then selling that list to companies who want to advertise to you.")
        elif any(w in activity_low for w in ["trojan", "invoice", "disguised", "payload"]):
            analogy = ("Think of it like a con artist dressed as a delivery person "

                       "knocking on your door — they look completely normal and trustworthy, "
                       "but once you let them in they cause serious harm.")
        else:
            analogy = ("It is a bit like a stranger sneaking into your home through a back window — "
                       "our security system spotted them and locked the door "
                       "before they could do any damage.")

        # ── Section 4: SANS steps via RAG ────────────────────────────────────
        todo = []
        try:
            if RAG_AVAILABLE:
                query = " ".join(filter(None, [
                    alert.get("mitre_technique", ""),
                    alert.get("malicious_activity", ""),
                    alert.get("reason", ""),
                ]))
                docs = retriever.invoke(query)
                sans_steps = []
                for doc in docs:
                    for line in doc.page_content.splitlines():
                        line = line.strip()
                        if line and not line.endswith("Response"):
                            sans_steps.append(line)
                emoji_map = [
                    ("isolate",  "⚠️ Disconnect your computer from WiFi or unplug the network cable."),
                    ("scan",     "🔄 Check your computer for problems using AI-Sec."),
                    ("password", "🔒 Change your important passwords from a different device."),
                    ("monitor",  "👀 Keep an eye on your computer for anything unusual."),
                    ("backup",   "💾 Restore any affected files from your most recent backup."),
                    ("contact",  "📞 Contact your IT support if you think you opened this file."),
                    ("remove",   "🗑 Let AI-Sec permanently delete the locked file."),
                    ("reset",    "🔒 Change your passwords from a different device just to be safe."),
                    ("check",    "💡 Look for any new apps you do not recognise and remove them."),
                    ("block",    "⚠️ Avoid downloading software from unofficial websites."),
                ]
                matched = []
                for step in sans_steps:
                    for keyword, plain in emoji_map:
                        if keyword in step.lower() and plain not in matched:
                            matched.append(plain)
                            break
                todo = matched[:5] if matched else []
        except Exception:
            pass

        if not todo:
            todo = {
                "High": [
                    "✅ Do NOT try to open or recover the blocked file.",
                    "🔒 Change your important passwords from a different device.",
                    "🔄 Check your computer for problems using AI-Sec.",
                    "📞 Contact your IT support if you think you opened this file.",
                    "🗑 Let AI-Sec permanently delete this file when prompted.",
                ],
                "Medium": [
                    "✅ The file has been isolated — no urgent action needed.",
                    "⚠️ Avoid downloading software from unofficial websites.",
                    "🔄 Check your computer to make sure nothing else was affected.",
                    "🔒 Look at your browser for any extensions you did not install.",
                ],
                "Low": [
                    "✅ The file is safely isolated — no immediate action needed.",
                    "💡 If you recognise this file, ask IT support to review it.",
                    "⚠️ Be cautious opening files from unknown sources.",
                ],
            }.get(sev, ["✅ The threat has been locked away safely by AI-Sec."])

        return "\n".join(
            ["1. 🔍 WHAT HAPPENED?", what,  "",
             "2. ❓ WHY?",           why,   "",
             "3. 💡 ANALOGY",        analogy, "",
             "4. 📋 WHAT YOU SHOULD DO"] + todo
        )


    # ── Manual JSON load ──────────────────────────────────────────────────────
    def _load_json(self):
        path = filedialog.askopenfilename(
            title="Open member1_alerts.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path) as f:
                data = json.load(f)
            raw = data.get("alerts", data) if isinstance(data, dict) else data
            self.alerts = _normalise_alerts(raw)

            self.count_lbl.configure(text=f"  {len(self.alerts)} alerts")
            self.selected_alert = None
            self._render_activity_cards()
            self._show_placeholder()
            self.info_file_lbl.configure(
                text="← Select an alert on the left to get an explanation",
                fg=C["text2"])
            self.info_sev_lbl.configure(text="")
            self.explain_btn.configure(state="disabled",
                                       text="🤖  Generate AI Explanation")
            messagebox.showinfo("Loaded",
                f"✅  Loaded {len(self.alerts)} alerts from:\n"
                f"{os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error loading file", str(e))


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = AiSecApp()
    app.mainloop()
