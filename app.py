"""
app.py — Sentinel AI Security Explanation Module
Member 4: AI Explanation Module | Sentinel AI Security Suite

A production-grade desktop application that:
  - Reads security alerts from member1_alerts.json (Member 1's output)
  - Sends each alert to Gemini AI with MITRE + NIST + SANS context
  - Displays plain-English explanations for non-technical users
  - Saves structured output to ai_explanations.json (for Member 5 dashboard)
  - Auto-detects new alerts via file watching (watchdog)
  - Caches AI results to disk to avoid redundant API calls
  - Uses a dark, professional UI via customtkinter
"""

import os
import json
import re
import threading
import datetime
import logging
import time
import hashlib
from pathlib import Path

# ── Third-party ──────────────────────────────────────────────────────────────
try:
    import customtkinter as ctk
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter", "-q"])
    import customtkinter as ctk

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "watchdog", "-q"])
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        WATCHDOG_AVAILABLE = True
    except ImportError:
        WATCHDOG_AVAILABLE = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # .env loading is optional

try:
    from google.genai import Client as GeminiClient
    GEMINI_AVAILABLE = True
except ImportError:
    try:
        import subprocess, sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "google-genai", "-q"])
        from google.genai import Client as GeminiClient
        GEMINI_AVAILABLE = True
    except Exception:
        GEMINI_AVAILABLE = False

from prompt import build_prompt

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_DIR          = os.path.dirname(os.path.abspath(__file__))
ALERTS_FILE       = os.path.join(BASE_DIR, "member1_alerts.json")
EXPLANATIONS_FILE = os.path.join(BASE_DIR, "ai_explanations.json")
CACHE_FILE        = os.path.join(BASE_DIR, "ai_cache.json")
GEMINI_MODEL      = "gemini-2.0-flash"       # fast + capable

SEVERITY_COLORS = {
    "HIGH":   "#FF4C4C",
    "MEDIUM": "#FF9A3C",
    "LOW":    "#4CAF50",
}
SEVERITY_BG = {
    "HIGH":   "#3a1a1a",
    "MEDIUM": "#3a2a1a",
    "LOW":    "#1a2e1a",
}

# ── Appearance ────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ─────────────────────────────────────────────────────────────────────────────
# Data helpers
# ─────────────────────────────────────────────────────────────────────────────
def load_alerts() -> list[dict]:
    """Load alerts from Member 1's output file."""
    if not os.path.exists(ALERTS_FILE):
        logger.warning("Alerts file not found: %s", ALERTS_FILE)
        return []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        alerts = data.get("alerts", [])
        # Sort by severity: HIGH first
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        alerts.sort(key=lambda a: order.get(a.get("severity", "LOW"), 99))
        return alerts
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load alerts: %s", e)
        return []


def load_disk_cache() -> dict:
    """Load the persistent AI response cache from disk."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_disk_cache(cache: dict) -> None:
    """Persist the AI response cache to disk."""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except OSError as e:
        logger.error("Failed to save cache: %s", e)


def alert_fingerprint(alert: dict) -> str:
    """Create a stable hash of alert content for cache key lookup."""
    key_fields = {
        "alert_id":    alert.get("alert_id"),
        "rule_id":     alert.get("rule_id"),
        "process_name":alert.get("process_name"),
        "severity":    alert.get("severity"),
        "tags":        sorted(alert.get("tags", [])),
    }
    raw = json.dumps(key_fields, sort_keys=True)
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def save_explanation_for_dashboard(alert: dict, explanation_data: dict) -> None:
    """
    Write AI explanation to ai_explanations.json for Member 5 (Dashboard).
    Thread-safe: uses a lock file approach via atomic write.
    """
    try:
        # Load existing file
        if os.path.exists(EXPLANATIONS_FILE):
            with open(EXPLANATIONS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = {"explanations": [], "last_updated": ""}

        entry = {
            "alert_id":      alert.get("alert_id"),
            "process_name":  alert.get("process_name"),
            "severity":      alert.get("severity"),
            "confidence":    alert.get("confidence"),
            "tags":          alert.get("tags", []),
            "generated_at":  alert.get("generated_at"),
            "ai_explanation": {
                "what_happened":       explanation_data.get("what_happened", ""),
                "why_concern":         explanation_data.get("why_concern", ""),
                "recommended_actions": explanation_data.get("recommended_actions", []),
            },
            "explained_at":  datetime.datetime.utcnow().isoformat() + "Z",
            "schema_version": "2.0",
        }

        # Deduplicate by alert_id
        data["explanations"] = [
            e for e in data["explanations"]
            if e.get("alert_id") != entry["alert_id"]
        ]
        data["explanations"].append(entry)

        # Sort: HIGH → MEDIUM → LOW
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        data["explanations"].sort(
            key=lambda x: order.get(x.get("severity", "LOW"), 99)
        )
        data["last_updated"] = datetime.datetime.utcnow().isoformat() + "Z"

        # Atomic write via temp file
        tmp = EXPLANATIONS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, EXPLANATIONS_FILE)

        logger.info("Saved explanation for %s → %s", entry["alert_id"], EXPLANATIONS_FILE)

    except (OSError, json.JSONDecodeError) as e:
        logger.error("Failed to save explanation: %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# Gemini AI Engine
# ─────────────────────────────────────────────────────────────────────────────
class AIEngine:
    """Manages Gemini API calls with retry logic and response validation."""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self._client: GeminiClient | None = None

    def _get_client(self) -> GeminiClient:
        if self._client is None:
            if not self.api_key:
                raise ValueError(
                    "GEMINI_API_KEY is not set.\n\n"
                    "Please create a .env file with:\n"
                    "GEMINI_API_KEY=your_key_here\n\n"
                    "Get a free key at: https://aistudio.google.com/app/apikey"
                )
            if not GEMINI_AVAILABLE:
                raise ImportError("google-genai package is not installed.")
            self._client = GeminiClient(api_key=self.api_key)
        return self._client

    def analyze(self, alert: dict, retries: int = 2) -> dict:
        """
        Send alert to Gemini and return a parsed explanation dict.
        Returns a dict with keys: what_happened, why_concern, recommended_actions.
        Raises on unrecoverable errors.
        """
        prompt = build_prompt(alert)
        client = self._get_client()

        last_error = None
        for attempt in range(retries + 1):
            try:
                chat     = client.chats.create(model=GEMINI_MODEL)
                response = chat.send_message(prompt)
                raw_text = response.text.strip()

                # Strip markdown code fences if present
                raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text, flags=re.MULTILINE)
                raw_text = re.sub(r"```\s*$", "", raw_text, flags=re.MULTILINE).strip()

                # Parse JSON
                data = json.loads(raw_text)

                # Validate required fields
                required = {"what_happened", "why_concern", "recommended_actions"}
                missing  = required - set(data.keys())
                if missing:
                    # Attempt field name migration (old schema used "why_happened")
                    if "why_happened" in data and "why_concern" not in data:
                        data["why_concern"] = data.pop("why_happened")
                    missing = required - set(data.keys())
                    if missing:
                        raise ValueError(f"Response missing fields: {missing}")

                if not isinstance(data["recommended_actions"], list):
                    raise ValueError("recommended_actions must be a list")

                return data

            except json.JSONDecodeError as e:
                last_error = f"Gemini returned invalid JSON: {e}\n\nRaw response:\n{raw_text[:500]}"
                logger.warning("Attempt %d: JSON parse failed — %s", attempt + 1, e)
                if attempt < retries:
                    time.sleep(2 ** attempt)  # exponential backoff

            except Exception as e:
                last_error = str(e)
                logger.warning("Attempt %d: API error — %s", attempt + 1, e)
                if attempt < retries:
                    time.sleep(2 ** attempt)

        raise RuntimeError(last_error or "Unknown error during AI analysis")


# ─────────────────────────────────────────────────────────────────────────────
# File Watcher (auto-detect new alerts)
# ─────────────────────────────────────────────────────────────────────────────
class AlertFileWatcher(FileSystemEventHandler):
    """Watches member1_alerts.json for changes and notifies the app."""

    def __init__(self, callback):
        super().__init__()
        self._callback  = callback
        self._last_hash = ""

    def on_modified(self, event):
        if os.path.basename(event.src_path) == ALERTS_FILE:
            self._debounced_reload()

    def on_created(self, event):
        if os.path.basename(event.src_path) == ALERTS_FILE:
            self._debounced_reload()

    def _debounced_reload(self):
        """Only fire callback if file content actually changed."""
        try:
            with open(ALERTS_FILE, "rb") as f:
                content_hash = hashlib.md5(f.read()).hexdigest()
            if content_hash != self._last_hash:
                self._last_hash = content_hash
                self._callback()
        except OSError:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────────────
class SentinelApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Sentinel AI — Security Explanation Module  (Member 4)")
        self.geometry("1280x760")
        self.minsize(900, 600)

        # State
        self.alerts:     list[dict] = []
        self.disk_cache: dict       = load_disk_cache()   # alert_fingerprint → explanation dict
        self.mem_cache:  dict       = {}                   # alert_fingerprint → formatted string (session)
        self.ai_engine               = AIEngine()
        self._selected_index: int | None = None
        self._observer = None

        self._build_ui()
        self._reload_alerts()
        self._start_watcher()

        # Pre-analyze all alerts in background
        threading.Thread(target=self._prefetch_all, daemon=True).start()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_sidebar()
        self._build_main_panel()
        self._build_statusbar()

    def _build_header(self):
        header = ctk.CTkFrame(self, height=60, corner_radius=0,
                              fg_color="#0d1117", border_width=0)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        # Shield icon + title
        ctk.CTkLabel(
            header, text="🛡️  Sentinel AI",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color="#58a6ff",
        ).grid(row=0, column=0, padx=20, pady=15, sticky="w")

        ctk.CTkLabel(
            header,
            text="Security Awareness & Explanation Module",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#8b949e",
        ).grid(row=0, column=1, padx=0, pady=15, sticky="w")

        # Reload button
        self.reload_btn = ctk.CTkButton(
            header, text="⟳  Reload Alerts", width=140, height=32,
            font=ctk.CTkFont(size=12),
            fg_color="#21262d", hover_color="#30363d",
            border_color="#30363d", border_width=1,
            command=self._on_reload_click,
        )
        self.reload_btn.grid(row=0, column=2, padx=20, pady=12, sticky="e")

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=300, corner_radius=0,
                               fg_color="#161b22", border_width=0)
        sidebar.grid(row=1, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(2, weight=1)
        sidebar.grid_propagate(False)

        # Filter bar
        filter_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        filter_frame.grid(row=0, column=0, sticky="ew", padx=12, pady=(14, 4))
        filter_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            filter_frame, text="ALERTS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#8b949e",
        ).grid(row=0, column=0, sticky="w")

        self.alert_count_label = ctk.CTkLabel(
            filter_frame, text="0 alerts",
            font=ctk.CTkFont(size=11),
            text_color="#58a6ff",
        )
        self.alert_count_label.grid(row=0, column=1, sticky="e")

        # Severity filter
        self.filter_var = ctk.StringVar(value="ALL")
        filter_seg = ctk.CTkSegmentedButton(
            sidebar,
            values=["ALL", "HIGH", "MED", "LOW"],
            variable=self.filter_var,
            font=ctk.CTkFont(size=11),
            fg_color="#21262d",
            selected_color="#1f6feb",
            unselected_color="#21262d",
            command=self._on_filter_change,
        )
        filter_seg.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))

        # Alert list (scrollable)
        self.alert_list_frame = ctk.CTkScrollableFrame(
            sidebar, fg_color="transparent",
            scrollbar_fg_color="#21262d",
            scrollbar_button_color="#30363d",
        )
        self.alert_list_frame.grid(row=2, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self.alert_list_frame.grid_columnconfigure(0, weight=1)

        sidebar.grid_columnconfigure(0, weight=1)

    def _build_main_panel(self):
        main = ctk.CTkFrame(self, corner_radius=0, fg_color="#0d1117", border_width=0)
        main.grid(row=1, column=1, sticky="nsew", padx=(1, 0))
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Top bar: alert title + copy button
        top_bar = ctk.CTkFrame(main, height=50, fg_color="#161b22", corner_radius=0)
        top_bar.grid(row=0, column=0, sticky="ew")
        top_bar.grid_columnconfigure(0, weight=1)

        self.panel_title = ctk.CTkLabel(
            top_bar,
            text="Select an alert from the sidebar to see its explanation",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#e6edf3",
            anchor="w",
        )
        self.panel_title.grid(row=0, column=0, padx=20, pady=12, sticky="w")

        self.copy_btn = ctk.CTkButton(
            top_bar, text="📋 Copy", width=90, height=30,
            font=ctk.CTkFont(size=12),
            fg_color="#21262d", hover_color="#30363d",
            border_color="#30363d", border_width=1,
            state="disabled",
            command=self._copy_to_clipboard,
        )
        self.copy_btn.grid(row=0, column=1, padx=12, pady=10, sticky="e")

        self.reanalyze_btn = ctk.CTkButton(
            top_bar, text="🔄 Re-analyze", width=110, height=30,
            font=ctk.CTkFont(size=12),
            fg_color="#21262d", hover_color="#30363d",
            border_color="#30363d", border_width=1,
            state="disabled",
            command=self._on_reanalyze,
        )
        self.reanalyze_btn.grid(row=0, column=2, padx=(0, 12), pady=10, sticky="e")

        # Explanation text area
        self.text_box = ctk.CTkTextbox(
            main,
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color="#0d1117",
            text_color="#e6edf3",
            border_width=0,
            wrap="word",
            activate_scrollbars=True,
        )
        self.text_box.grid(row=1, column=0, sticky="nsew", padx=2, pady=2)

        # Configure text tags for rich formatting
        # NOTE: customtkinter CTkTextbox does not support 'font' in tag_config
        # (raises AttributeError due to scaling incompatibility). Color only.
        self.text_box.tag_config("heading",    foreground="#58a6ff")
        self.text_box.tag_config("high",       foreground="#FF4C4C")
        self.text_box.tag_config("medium",     foreground="#FF9A3C")
        self.text_box.tag_config("low",        foreground="#4CAF50")
        self.text_box.tag_config("label",      foreground="#8b949e")
        self.text_box.tag_config("body",       foreground="#c9d1d9")
        self.text_box.tag_config("step",       foreground="#e6edf3")
        self.text_box.tag_config("sans_phase", foreground="#f0883e")
        self.text_box.tag_config("meta",       foreground="#484f58")
        self.text_box.tag_config("divider",    foreground="#21262d")
        self.text_box.tag_config("mitre_id",   foreground="#79c0ff")
        self.text_box.tag_config("nist_id",    foreground="#56d364")
        self.text_box.tag_config("error",      foreground="#f85149")

    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, height=28, corner_radius=0,
                           fg_color="#161b22", border_width=0)
        bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)

        self.status_var = ctk.StringVar(value="Ready  —  Select an alert to begin")
        ctk.CTkLabel(
            bar,
            textvariable=self.status_var,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#8b949e",
            anchor="w",
        ).grid(row=0, column=0, padx=16, pady=4, sticky="w")

        self.ai_status_label = ctk.CTkLabel(
            bar, text="🤖 AI Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#3fb950",
        )
        self.ai_status_label.grid(row=0, column=1, padx=16, pady=4, sticky="e")

    # ── Alert List Rendering ─────────────────────────────────────────────────

    def _reload_alerts(self):
        self.alerts = load_alerts()
        self._render_alert_list()
        count = len(self.alerts)
        self.alert_count_label.configure(text=f"{count} alert{'s' if count != 1 else ''}")

    def _render_alert_list(self):
        # Clear existing widgets
        for widget in self.alert_list_frame.winfo_children():
            widget.destroy()

        filter_val = self.filter_var.get()
        shown = 0

        for i, alert in enumerate(self.alerts):
            sev = alert.get("severity", "LOW")

            # Apply filter
            if filter_val != "ALL":
                map_ = {"HIGH": "HIGH", "MED": "MEDIUM", "LOW": "LOW"}
                if sev != map_.get(filter_val, filter_val):
                    continue

            self._create_alert_card(i, alert)
            shown += 1

        if shown == 0:
            ctk.CTkLabel(
                self.alert_list_frame,
                text="No alerts to display",
                font=ctk.CTkFont(size=12),
                text_color="#8b949e",
            ).grid(row=0, column=0, pady=20)

    def _create_alert_card(self, index: int, alert: dict):
        sev     = alert.get("severity", "LOW")
        color   = SEVERITY_COLORS.get(sev, "#aaaaaa")
        bg_color = SEVERITY_BG.get(sev, "#1c2128")

        card = ctk.CTkFrame(
            self.alert_list_frame,
            fg_color=bg_color,
            border_color=color,
            border_width=1,
            corner_radius=8,
        )
        card.grid(row=index, column=0, sticky="ew", padx=4, pady=3)
        card.grid_columnconfigure(0, weight=1)

        # Severity badge + process name
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 2))
        top.grid_columnconfigure(1, weight=1)

        sev_badge = ctk.CTkLabel(
            top,
            text=f" {sev} ",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=color,
            fg_color="#0d1117",
            corner_radius=4,
        )
        sev_badge.grid(row=0, column=0, sticky="w")

        proc_label = ctk.CTkLabel(
            top,
            text=alert.get("process_name", "Unknown"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#e6edf3",
            anchor="w",
        )
        proc_label.grid(row=0, column=1, padx=(8, 0), sticky="w")

        # Alert ID + timestamp
        aid = alert.get("alert_id", "")
        gen = alert.get("generated_at", "")[:16].replace("T", "  ") if alert.get("generated_at") else ""
        meta_label = ctk.CTkLabel(
            card,
            text=f"{aid}   {gen}",
            font=ctk.CTkFont(size=10),
            text_color="#8b949e",
            anchor="w",
        )
        meta_label.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 8))

        # Make entire card clickable
        def make_handler(idx):
            return lambda e: self._on_alert_select(idx)

        for widget in [card, top, sev_badge, proc_label, meta_label]:
            widget.bind("<Button-1>", make_handler(index))
            widget.configure(cursor="hand2")

    # ── Alert Selection & Analysis ───────────────────────────────────────────

    def _on_alert_select(self, index: int):
        if index >= len(self.alerts):
            return
        self._selected_index = index
        alert = self.alerts[index]
        aid   = alert.get("alert_id", "")
        sev   = alert.get("severity", "LOW")
        proc  = alert.get("process_name", "")

        self.panel_title.configure(text=f"[{sev}]  {proc}  —  {aid}")
        self.copy_btn.configure(state="normal")
        self.reanalyze_btn.configure(state="normal")

        fp = alert_fingerprint(alert)

        # Check memory cache first (fastest)
        if fp in self.mem_cache:
            self._display_explanation(self.mem_cache[fp], alert)
            self._set_status(f"✅  Loaded from cache  —  {aid}")
            return

        # Check disk cache
        if fp in self.disk_cache:
            explanation = self.disk_cache[fp]
            formatted   = self._format_explanation(explanation, alert)
            self.mem_cache[fp] = formatted
            self._display_explanation(formatted, alert)
            self._set_status(f"✅  Loaded from disk cache  —  {aid}")
            return

        # No cache — run analysis
        self._run_analysis_async(alert)

    def _run_analysis_async(self, alert: dict):
        self._set_text_loading(alert)
        self._set_status(f"⏳  Analyzing with Gemini AI…  —  {alert.get('alert_id')}")
        self.ai_status_label.configure(text="🤖 AI Working…", text_color="#f0883e")

        threading.Thread(
            target=self._analysis_worker,
            args=(alert,),
            daemon=True,
        ).start()

    def _analysis_worker(self, alert: dict):
        aid = alert.get("alert_id", "")
        try:
            data      = self.ai_engine.analyze(alert)
            formatted = self._format_explanation(data, alert)
            fp        = alert_fingerprint(alert)

            # Cache in memory and disk
            self.mem_cache[fp]  = formatted
            self.disk_cache[fp] = data
            save_disk_cache(self.disk_cache)

            # Save for Member 5 dashboard
            save_explanation_for_dashboard(alert, data)

            # Update UI on main thread
            self.after(0, lambda: self._display_explanation(formatted, alert))
            self.after(0, lambda: self._set_status(f"✅  Analysis complete  —  {aid}  |  Saved to {EXPLANATIONS_FILE}"))
            self.after(0, lambda: self.ai_status_label.configure(text="🤖 AI Ready", text_color="#3fb950"))

        except Exception as e:
            err_msg = str(e)
            logger.error("Analysis failed for %s: %s", aid, err_msg)
            self.after(0, lambda: self._display_error(err_msg))
            self.after(0, lambda: self._set_status(f"❌  Analysis failed  —  {aid}"))
            self.after(0, lambda: self.ai_status_label.configure(text="🤖 AI Error", text_color="#f85149"))

    # ── Display Helpers ──────────────────────────────────────────────────────

    def _set_text_loading(self, alert: dict):
        self.text_box.configure(state="normal")
        self.text_box.delete("1.0", "end")
        aid  = alert.get("alert_id", "")
        proc = alert.get("process_name", "")
        sev  = alert.get("severity", "LOW")

        self.text_box.insert("end", f"\n  ⏳  Analyzing alert with Gemini AI…\n\n", "heading")
        self.text_box.insert("end", f"  Alert:    {aid}\n", "label")
        self.text_box.insert("end", f"  Process:  {proc}\n", "body")
        self.text_box.insert("end", f"  Severity: ", "label")
        tag = sev.lower()
        self.text_box.insert("end", f"{sev}\n\n", tag)
        self.text_box.insert("end", "  Please wait — this usually takes 3-8 seconds...\n", "meta")
        self.text_box.configure(state="disabled")

    def _format_explanation(self, data: dict, alert: dict) -> str:
        """Return formatted string. We use a special tagged format stored as JSON."""
        return json.dumps({"data": data, "alert": alert})

    def _display_explanation(self, formatted_str: str, alert: dict):
        """Render the tagged explanation in the text box with colored markup."""
        self.text_box.configure(state="normal")
        self.text_box.delete("1.0", "end")

        try:
            parsed = json.loads(formatted_str)
            data   = parsed["data"]
            alert  = parsed.get("alert", alert)
        except (json.JSONDecodeError, KeyError):
            # Fallback for legacy plain-text format
            self.text_box.insert("end", formatted_str, "body")
            self.text_box.configure(state="disabled")
            return

        sev   = alert.get("severity", "LOW")
        aid   = alert.get("alert_id", "")
        proc  = alert.get("process_name", "")
        sev_tag = sev.lower()
        divider = "─" * 64 + "\n"

        # ── Header ──
        self.text_box.insert("end", f"\n  SECURITY ALERT EXPLANATION\n", "heading")
        self.text_box.insert("end", f"  {divider}", "divider")
        self.text_box.insert("end", f"  Alert ID:   ", "label")
        self.text_box.insert("end", f"{aid}\n", "body")
        self.text_box.insert("end", f"  Process:    ", "label")
        self.text_box.insert("end", f"{proc}\n", "body")
        self.text_box.insert("end", f"  Severity:   ", "label")
        self.text_box.insert("end", f"{sev}\n", sev_tag)

        conf = alert.get("confidence")
        if conf:
            self.text_box.insert("end", f"  Confidence: ", "label")
            self.text_box.insert("end", f"{conf}\n", "body")

        tags = alert.get("tags", [])
        if tags:
            self.text_box.insert("end", f"  Tags:       ", "label")
            self.text_box.insert("end", f"{', '.join(tags)}\n", "body")

        self.text_box.insert("end", f"\n  {divider}", "divider")

        # ── What Happened ──
        self.text_box.insert("end", "\n  🔍  WHAT HAPPENED\n\n", "heading")
        what = data.get("what_happened", "")
        self._insert_highlighted_paragraph(what)

        self.text_box.insert("end", f"\n  {divider}", "divider")

        # ── Why It's a Concern ──
        self.text_box.insert("end", "\n  ⚠️   WHY THIS IS A CONCERN\n\n", "heading")
        why = data.get("why_concern", data.get("why_happened", ""))
        self._insert_highlighted_paragraph(why)

        self.text_box.insert("end", f"\n  {divider}", "divider")

        # ── Recommended Actions ──
        self.text_box.insert("end", "\n  ✅  WHAT YOU SHOULD DO\n\n", "heading")
        actions = data.get("recommended_actions", [])
        for i, step in enumerate(actions, 1):
            # Detect and highlight [SANS: Phase] markers
            sans_match = re.search(r"\[SANS:\s*([^\]]+)\]", step)
            step_text  = re.sub(r"\[SANS:[^\]]+\]", "", step).strip()

            self.text_box.insert("end", f"  {i}.  ", "label")
            self.text_box.insert("end", f"{step_text}", "step")
            if sans_match:
                self.text_box.insert("end", f"  [SANS: {sans_match.group(1).strip()}]", "sans_phase")
            self.text_box.insert("end", "\n\n")

        self.text_box.insert("end", f"  {divider}", "divider")

        # ── Footer ──
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d  %H:%M:%S")
        self.text_box.insert("end", f"\n  Analyzed at: {now} UTC\n", "meta")
        self.text_box.insert("end", f"  This module is read-only. No files were modified.\n", "meta")
        self.text_box.insert("end", f"  Output saved to: {EXPLANATIONS_FILE}\n\n", "meta")

        self.text_box.configure(state="disabled")

    def _insert_highlighted_paragraph(self, text: str):
        """Insert a paragraph, highlighting MITRE IDs (T####) and NIST IDs (XX-#)."""
        parts = re.split(r"(\bT\d{4}\b|\b[A-Z]{2}-\d+\b)", text)
        for part in parts:
            if re.match(r"\bT\d{4}\b", part):
                self.text_box.insert("end", f"  {part}", "mitre_id")
            elif re.match(r"\b[A-Z]{2}-\d+\b", part):
                self.text_box.insert("end", part, "nist_id")
            else:
                # Word-wrap at 70 chars for readability
                for line in part.split("\n"):
                    self.text_box.insert("end", f"  {line.strip()}\n" if line.strip() else "\n", "body")

    def _display_error(self, message: str):
        self.text_box.configure(state="normal")
        self.text_box.delete("1.0", "end")
        self.text_box.insert("end", "\n  ❌  ANALYSIS FAILED\n\n", "error")
        self.text_box.insert("end", f"  {message}\n\n", "body")
        self.text_box.insert("end", "  Possible causes:\n", "label")
        self.text_box.insert("end", "  • EXPLANATION_API_KEY not set in your .env file\n", "body")
        self.text_box.insert("end", "  • Network/internet connection issue\n", "body")
        self.text_box.insert("end", "  • Gemini API rate limit reached (try again in 60s)\n", "body")
        self.text_box.insert("end", "\n  Click '🔄 Re-analyze' to try again.\n", "meta")
        self.text_box.configure(state="disabled")

    # ── Controls ─────────────────────────────────────────────────────────────

    def _copy_to_clipboard(self):
        self.text_box.configure(state="normal")
        content = self.text_box.get("1.0", "end").strip()
        self.text_box.configure(state="disabled")
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self._set_status("📋  Explanation copied to clipboard")

    def _on_reanalyze(self):
        if self._selected_index is None:
            return
        alert = self.alerts[self._selected_index]
        fp    = alert_fingerprint(alert)

        # Clear caches for this alert
        self.mem_cache.pop(fp, None)
        self.disk_cache.pop(fp, None)
        save_disk_cache(self.disk_cache)

        self._run_analysis_async(alert)

    def _on_filter_change(self, value):
        self._render_alert_list()

    def _on_reload_click(self):
        self._reload_alerts()
        self._set_status(f"🔄  Reloaded  —  {len(self.alerts)} alerts found")

    def _set_status(self, text: str):
        self.status_var.set(text)

    # ── File Watcher ─────────────────────────────────────────────────────────

    def _start_watcher(self):
        if not WATCHDOG_AVAILABLE:
            logger.warning("watchdog not available — auto-reload disabled")
            return
        try:
            event_handler = AlertFileWatcher(callback=self._on_alerts_file_changed)
            self._observer = Observer()
            watch_dir = os.path.abspath(os.path.dirname(ALERTS_FILE) or ".")
            self._observer.schedule(event_handler, watch_dir, recursive=False)
            self._observer.start()
            logger.info("File watcher started on: %s", watch_dir)
        except Exception as e:
            logger.warning("Could not start file watcher: %s", e)

    def _on_alerts_file_changed(self):
        """Called by watchdog when member1_alerts.json changes."""
        self.after(500, self._handle_new_alerts)

    def _handle_new_alerts(self):
        old_ids = {a.get("alert_id") for a in self.alerts}
        self._reload_alerts()
        new_ids = {a.get("alert_id") for a in self.alerts}
        new_count = len(new_ids - old_ids)

        if new_count > 0:
            self._set_status(f"🔔  {new_count} new alert(s) detected — analyzing in background…")
            # Pre-analyze new alerts
            new_alerts = [a for a in self.alerts if a.get("alert_id") not in old_ids]
            threading.Thread(
                target=lambda: [self._analysis_worker(a) for a in new_alerts],
                daemon=True,
            ).start()

    def _prefetch_all(self):
        """Pre-analyze all alerts on startup (skips those already cached)."""
        for alert in self.alerts:
            fp = alert_fingerprint(alert)
            if fp not in self.mem_cache and fp not in self.disk_cache:
                try:
                    data      = self.ai_engine.analyze(alert)
                    formatted = self._format_explanation(data, alert)
                    self.mem_cache[fp]  = formatted
                    self.disk_cache[fp] = data
                    save_disk_cache(self.disk_cache)
                    save_explanation_for_dashboard(alert, data)
                    aid = alert.get("alert_id", "")
                    self.after(0, lambda a=aid: self._set_status(f"✅  Pre-analyzed: {a}"))
                except Exception as e:
                    logger.warning("Prefetch failed for %s: %s", alert.get("alert_id"), e)

        self.after(0, lambda: self._set_status(
            f"✅  All {len(self.alerts)} alerts analyzed and ready"
        ))
        self.after(0, lambda: self.ai_status_label.configure(
            text="🤖 AI Ready", text_color="#3fb950"
        ))

    def on_close(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Validate API key before launching UI
    api_key = os.getenv("EXPLANATION_API_KEY", "").strip()
    if not api_key:
        print("=" * 55)
        print("  ⚠️   EXPLANATION_API_KEY not found")
        print("=" * 55)
        print("  Create a .env file in this folder with:")
        print("  EXPLANATION_API_KEY=your_key_here")
        print()
        print("  Get a free key at:")
        print("  https://aistudio.google.com/app/apikey")
        print("=" * 55)
        print()
        print("  Starting app anyway — AI features will show errors")
        print("  until a valid key is provided.")
        print()

    app = SentinelApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    try:
        app.mainloop()
    except KeyboardInterrupt:
        app.on_close()