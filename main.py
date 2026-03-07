import tkinter as tk
import customtkinter as ctk
from PIL import Image
from tkinter import font as tkfont
from chatbot import open_chatbot
from alert_popup import show_security_popup
from dataset.scan_file import get_activities, STATUS_COLORS

class ModernAISec:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-Sec Assistant Pro")
        self.root.geometry("1100x850")
        self.root.configure(bg="#FDFDFD")

        self.colors = {
            "bg": "#FFFFFF",
            "accent_red": "#FF5252",
            "light_red": "#FDD7D7",
            "border_red": "#FFDADA",
            "text_main": "#1A1A1B",
            "text_sub": "#6E6E73",
            "card_bg": "#F8F9FA",
        }
    # show Dashbord when click buttom
    # In this case the TK window 
    # def show_dashboard(self):
    #     # self.root.deiconify()  # make sure window is visible
    #     # self.root.lift()       # bring to front
    #     # self.root.focus_force() 
    #     pass

        self.quarantine_count = 1  # initial quarantine count

        self.setup_styles()
        self.render_ui()

        # Example: simulate a new quarantine after 4 seconds
        self.root.after(4000, lambda: self.update_quarantine("virus_payload.exe"))

    # ================= STYLES =================
    def setup_styles(self):
        self.h1 = tkfont.Font(family="Arial", size=24, weight="bold")
        self.h2 = tkfont.Font(family="Arial", size=16, weight="bold")
        self.p = tkfont.Font(family="Arial", size=11)
        self.code_font = tkfont.Font(family="Courier", size=10)

    # ================= MAIN UI =================
    def render_ui(self):
        # NAVBAR
        navbar = tk.Frame(self.root, bg=self.colors["bg"])
        navbar.pack(fill="x", padx=40, pady=20)
        tk.Label(navbar,
                 text="🛡️ AI-Sec Assistant",
                 font=self.h2,
                 bg=self.colors["bg"]).pack(side="left")

        # HERO
        hero_border = tk.Frame(self.root,
                               bg=self.colors["border_red"],
                               padx=1,
                               pady=1)
        hero_border.pack(fill="x", padx=40, pady=(0, 20))

        hero = tk.Frame(hero_border, bg="#FFF5F5", height=155)
        hero.pack(fill="x")
        hero.pack_propagate(False)
        tk.Label(hero,
                 text="🔒 QUARANTINED",
                 font=self.h1,
                 bg="#FFF5F5",
                 fg=self.colors["accent_red"]).pack(pady=40)

        # MAIN GRID
        grid = tk.Frame(self.root, bg="#FDFDFD")
        grid.pack(fill="both", expand=True, padx=40)

        # ================= LEFT SECTION =================
        left_pane = tk.Frame(grid, bg="#FDFDFD", width=400, height=00)
        left_pane.pack(side="left", fill="y", padx=(0, 20))
        left_pane.pack_propagate(False)

        tk.Label(left_pane,
                 text="🕒 Recent Activity",
                 font=self.h2,
                 bg="#FDFDFD").pack(anchor="w", pady=(0, 10))

        left_container = tk.Frame(left_pane, bg="#FFFFFF")
        left_container.pack(fill="both", expand=True)

        self.left_canvas = tk.Canvas(left_container,
                                     bg="#FFFFFF",
                                     highlightthickness=0)
        left_scrollbar = tk.Scrollbar(left_container,
                                      orient="vertical",
                                      command=self.left_canvas.yview)
        self.left_canvas.configure(yscrollcommand=left_scrollbar.set)

        left_scrollbar.pack(side="right", fill="y")
        self.left_canvas.pack(side="left", fill="both", expand=True)

        self.left_scroll_frame = tk.Frame(self.left_canvas, bg="#FFFFFF")
        self.left_canvas_window = self.left_canvas.create_window(
            (0, 0),
            window=self.left_scroll_frame,
            anchor="nw"
        )

        self.left_scroll_frame.bind(
            "<Configure>",
            lambda e: self.left_canvas.configure(
                scrollregion=self.left_canvas.bbox("all")
            )
        )

        self.left_canvas.bind(
            "<Configure>",
            lambda e: self.left_canvas.itemconfig(
                self.left_canvas_window,
                width=e.width
            )
        )

        self.left_canvas.bind("<Enter>", lambda e: self._bind_scroll(self.left_canvas))
        self.left_canvas.bind("<Leave>", lambda e: self._unbind_scroll())

        activities = get_activities()  # now works correctly

        for time, filename, status, is_danger in activities:
            self.create_activity_item(self.left_scroll_frame,
                                    time,
                                    filename,
                                    status,
                                    is_danger)
            
        # ================= RIGHT SECTION =================
        right_pane = tk.Frame(grid, bg="#FDFDFD")
        right_pane.pack(side="left", fill="both", expand=True)

        tk.Label(right_pane,
                 text="🤖 AI Security Assistant",
                 font=self.h2,
                 bg="#FDFDFD").pack(anchor="w", pady=(0, 10))

        right_container = tk.Frame(right_pane, bg="#FDFDFD")
        right_container.pack(fill="both", expand=True)

        self.right_canvas = tk.Canvas(right_container,
                                      bg="#FDFDFD",
                                      highlightthickness=0)
        right_scrollbar = tk.Scrollbar(right_container,
                                       orient="vertical",
                                       command=self.right_canvas.yview)
        self.right_canvas.configure(yscrollcommand=right_scrollbar.set)

        right_scrollbar.pack(side="right", fill="y")
        self.right_canvas.pack(side="left", fill="both", expand=True)

        self.right_scroll_frame = tk.Frame(self.right_canvas, bg=self.colors["card_bg"])
        self.right_canvas_window = self.right_canvas.create_window(
            (0, 0),
            window=self.right_scroll_frame,
            anchor="nw"
        )

        self.right_scroll_frame.bind(
            "<Configure>",
            lambda e: self.right_canvas.configure(
                scrollregion=self.right_canvas.bbox("all")
            )
        )

        self.right_canvas.bind(
            "<Configure>",
            lambda e: self.right_canvas.itemconfig(
                self.right_canvas_window,
                width=e.width
            )
        )

        self.right_canvas.bind("<Enter>", lambda e: self._bind_scroll(self.right_canvas))
        self.right_canvas.bind("<Leave>", lambda e: self._unbind_scroll())

        ai_card = tk.Frame(self.right_scroll_frame,
                           bg=self.colors["card_bg"],
                           padx=25,
                           pady=25)
        ai_card.pack(fill="both", expand=True)

        self.create_info_block(ai_card, "What happened:",
                               "I detected a malicious invoice file and safely isolated it.")
        self.create_info_block(ai_card, "Where:",
                               "C:\\Users\\Downloads\\invoice_2024.exe",
                               is_path=True)
        self.create_info_block(ai_card, "Why it's risky:",
                               "The file matched known ransomware behavior patterns.")
        self.create_status_block(ai_card,
                                 "✔️",
                                 "What to do:",
                                 [
                                     "Continue using your computer normally",
                                     "Delete suspicious emails",
                                     "Report phishing attempts"
                                 ],
                                 "#E8F5E9",
                                 "#2E7D32")
        self.create_status_block(ai_card,
                                 "❌",
                                 "What not to do:",
                                 [
                                     "Do not run the quarantined file",
                                     "Do not disable security alerts"
                                 ],
                                 "#FFEBEE",
                                 "#C62828")

        # ================= BOTTOM SECTION =================
        self.create_bottom_section()

    def create_bottom_section(self):
        section = tk.Frame(self.root, bg=self.root.cget("bg"))   #F5F6F8
        section.pack(fill="x", padx=15, pady=10)

        section.columnconfigure(0, weight=1)
        section.columnconfigure(1, weight=19)
        self.tips = [
            "If something feels suspicious, trust your instinct and ask for help.",
            "Always verify unknown links and attachments before opening them.",
            "Use strong, unique passwords for every account.",
            "Enable two-factor authentication wherever possible.",
            "Keep your software and OS updated to patch vulnerabilities.",
            "Never share sensitive information over unencrypted channels.",
            "Back up your data regularly to a secure location.",
        ]
        self.tip_index = 0

        # ================= LEFT CARD (Quarantine) =================
        left_card = tk.Frame(section, bg="#FFFFFF")
        left_card.grid(row=0, column=0, sticky="ew", padx=(15, 15))
        left_card.configure(highlightbackground="#EAEAEA", highlightthickness=1)

        tk.Label(left_card,
                 text="🔒  Quarantine",
                 font=self.h2,
                 bg="#FFFFFF").pack(anchor="w", padx=15, pady=(8, 8))

        # ✅ Spacer pushes content to bottom
        spacer = tk.Frame(left_card, bg="#FFFFFF")
        spacer.pack(fill="both", expand=True)
        # Alert box with border-radius using CTkFrame
        alert_box = ctk.CTkFrame(
            left_card,
            fg_color="#FFECEC",
            border_color="#FFCDD2",
            border_width=1,
            corner_radius=10
        )
        alert_box.pack(fill="x", padx=10, pady=(0, 3))
        # Icon + count row
        icon_row = tk.Frame(alert_box, bg="#FFECEC")
        icon_row.pack(anchor="w", padx=12, pady=(10, 0))

        # Circle icon background
        icon_frame = ctk.CTkFrame(
            icon_row,
            fg_color="#FFD6D6",
            corner_radius=20,
            width=38,
            height=38
        )
        icon_frame.pack(side="left")
        icon_frame.pack_propagate(False)

        ctk.CTkLabel(
            icon_frame,
            text="🗂",
            font=("Arial", 16),
            fg_color="transparent",
            text_color="#D32F2F"
        ).pack(expand=True)

        # Count next to icon
        self.quarantine_label = ctk.CTkLabel(
            icon_row,
            text=str(self.quarantine_count),
            font=("Arial", 25, "bold"),
            text_color="#E71D1D",
            fg_color="transparent"
        )
        self.quarantine_label.pack(side="left", padx=(20, 5))

        ctk.CTkLabel(
            alert_box,
            text="Item Successfully Isolated",
            font=("Arial", 11),  # ✅ tuple instead of self.p
            text_color="#555",
            fg_color="transparent"
        ).pack(anchor="w", padx=50, pady=(0, 8))

        tk.Label(left_card,
                 text="Quarantined files are securely sandboxed and cannot affect your system.",
                 wraplength=350,
                 justify="left",
                 bg="#FFFFFF",
                 font=("Arial", 9),
                 fg="#6E6E73",
                ).pack(anchor="w", padx=20, pady=(0, 10))

 # ================= RIGHT CARD (Security Tip) =================
        right_card = tk.Frame(section, bg="#FFFFFF")
        right_card.grid(row=0, column=1, sticky="ew", padx=(0, 15))
        right_card.configure(highlightbackground="#EAEAEA", highlightthickness=1)

        # Title + chatbot inline
        inline_frame = tk.Frame(right_card, bg="#FFFFFF")
        inline_frame.pack(fill="x", padx=20, pady=(8, 4))

        tk.Label(
            inline_frame,
            text="💡  Security Tip",
            font=self.h2,
            bg="#FFFFFF"
        ).pack(side="left", padx=(20, 0))

        chatbot_img = ctk.CTkImage(
            light_image=Image.open("assets/chatbot.png"),
            size=(42, 42)
        )

        chatbot_btn = ctk.CTkButton(
            inline_frame,
            image=chatbot_img,
            text="Ask AI",
            fg_color="transparent",
            hover_color="#FFFFFF",
            text_color="#373131",
            cursor="hand2",
            command=lambda: open_chatbot(self.root)
        )
        chatbot_btn.pack(side="right", padx=(0, 10))

        # Tip box
        tip_box = ctk.CTkFrame(
            right_card,
            fg_color="#FFF8E1",
            border_color="#FFE082",
            border_width=1,
            corner_radius=10,
            height=70,
        )
        tip_box.pack(fill="x", padx=20, pady=(0, 8))
        tip_box.pack_propagate(False)

        self.tip_label = ctk.CTkLabel(
            tip_box,
            text=self.tips[self.tip_index],
            wraplength=600,
            justify="left",
            fg_color="transparent",
            text_color="#444",
            font=("Arial", 14)
        )
        self.tip_label.pack(anchor="w", padx=20, pady=(15, 15))

        # Navigation row
        nav_frame = tk.Frame(right_card, bg="#FFFFFF")
        nav_frame.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkButton(
            nav_frame,
            text="◀ Back",
            font=("Arial", 11),
            fg_color="#E0E0E0",
            hover_color="#DFDFDF",
            text_color="#9E9E9E",
            corner_radius=8,
            width=80,
            height=32,
            cursor="hand2",
            command=self.prev_tip
        ).pack(side="left")

        self.tip_counter = tk.Label(
            nav_frame,
            text=f"1 of {len(self.tips)}",
            bg="#FFFFFF",
            fg="#9E9E9E",
            font=("Arial", 10)
        )
        self.tip_counter.pack(side="left", expand=True)

        ctk.CTkButton(
            nav_frame,
            text="Next ▶",
            font=("Arial", 11),
            fg_color="#E0E0E0",
            hover_color="#DFDFDF",
            text_color="#9E9E9E",
            corner_radius=8,
            width=80,
            height=32,
            cursor="hand2",
            command=self.next_tip
        ).pack(side="right")

    def next_tip(self):
        self.tip_index = (self.tip_index + 1) % len(self.tips)
        self.tip_label.configure(text=self.tips[self.tip_index])
        self.tip_counter.configure(text=f"{self.tip_index + 1} of {len(self.tips)}")

    def prev_tip(self):
        self.tip_index = (self.tip_index - 1) % len(self.tips)
        self.tip_label.configure(text=self.tips[self.tip_index])
        self.tip_counter.configure(text=f"{self.tip_index + 1} of {len(self.tips)}")

    # ================= Block Recent Activity =================
    def create_activity_item(self, parent, time, title, status, is_danger):

        # ✅ Use STATUS_COLORS instead of is_danger
        badge_bg, status_color = STATUS_COLORS.get(status, ("#F5F5F5", "#555555"))

        # Rounded box container
        item = ctk.CTkFrame(
            parent,
            corner_radius=10,
            fg_color="#F9F9F9",
            border_width=1,
            border_color="#E0E0E0"
        )
        item.pack(fill="x", pady=2, padx=15)

        # Time label
        time_label = ctk.CTkLabel(
            item,
            text=time,
            font=("Arial", 10),
            text_color="#6E6E73"
        )
        time_label.pack(anchor="w", padx=15, pady=(10, 0))

        # Middle row container
        row = ctk.CTkFrame(item, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=(5, 10))

        # Title
        title_label = ctk.CTkLabel(
            row,
            text=title,
            font=("Arial", 13, "bold")
        )
        title_label.pack(side="left")

        # Badge
        badge = ctk.CTkFrame(
            item,
            corner_radius=8,
            fg_color=badge_bg   # ✅ from STATUS_COLORS
        )
        badge.place(relx=1.0, x=-15, y=10, anchor="ne")

        status_label = ctk.CTkLabel(
            badge,
            text=status.upper(),
            font=("Arial", 10, "bold"),
            text_color=status_color,  # ✅ from STATUS_COLORS
            height=15
        )
        status_label.pack(padx=8, pady=3)

    def create_info_block(self, parent, title, body, is_path=False):
        frame = tk.Frame(parent, bg=self.colors["card_bg"], pady=10)
        frame.pack(fill="x")
        tk.Label(frame, text=title,
                 font=("Arial", 10, "bold"),
                 bg=self.colors["card_bg"]).pack(anchor="w")
        if is_path:
            tk.Label(frame, text=body,
                     font=self.code_font,
                     bg="#EEEEEE",
                     padx=10, pady=8,
                     anchor="w").pack(fill="x", pady=5)
        else:
            tk.Label(frame, text=body,
                     font=self.p,
                     bg=self.colors["card_bg"],
                     wraplength=500,
                     justify="left").pack(anchor="w")

    def create_status_block(self, parent, icon, title, items, bg_color, text_color):
        block = tk.Frame(parent, bg=bg_color, padx=15, pady=15)
        block.pack(fill="x", pady=10)
        tk.Label(block, text=f"{icon}  {title}",
                 font=("Arial", 11, "bold"),
                 bg=bg_color,
                 fg=text_color).pack(anchor="w")
        for item in items:
            tk.Label(block,
                     text=f"  • {item}",
                     font=self.p,
                     bg=bg_color).pack(anchor="w")

    # ================= SCROLL =================
    def _on_mousewheel(self, event):
        self.active_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _bind_scroll(self, canvas):
        self.active_canvas = canvas
        canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_scroll(self):
        self.root.unbind_all("<MouseWheel>")

    # ================= QUARANTINE ALERT =================
    def update_quarantine(self, filename="Unknown File"):
        self.quarantine_count += 1
        self.quarantine_label.configure(text=str(self.quarantine_count))

        # Flash effect (use configure, not config)
        self.quarantine_label.configure(text_color="#FF0000")
        self.root.after(500, lambda: self.quarantine_label.configure(text_color="#D32F2F"))

        # Show popup alert
        show_security_popup(self.root, filename)


# ================= RUN =================
if __name__ == "__main__":
    root = tk.Tk()
    app = ModernAISec(root)
    root.mainloop()