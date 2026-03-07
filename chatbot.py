import tkinter as tk
import customtkinter as ctk

def open_chatbot(parent, filename="invoice_2024.exe"):
    win = tk.Toplevel(parent)
    win.title("AI Assistant")
    win.geometry("420x580")
    win.configure(bg="#FFFFFF")
    win.resizable(False, False)

    screen_w = win.winfo_screenwidth()
    screen_h = win.winfo_screenheight()
    x = screen_w - 450 - 20   # 20px from right edge
    y = screen_h - 600 - 40   # 40px from bottom (taskbar)
    win.geometry(f"450x600+{x}+{y}")  # ✅ single call — size + position fixed
    

    # ── Header ──────────────────────────────────────────────
    header = tk.Frame(win, bg="#FFFFFF")
    header.pack(fill="x", padx=20, pady=(16, 0))

    tk.Label(header, text="🤖  AI Security Assistant",
                font=("Arial", 15, "bold"), bg="#FFFFFF", fg="#1976D2").pack(side="left")

    ctk.CTkButton(header, text="✕", width=30, height=30,
                  fg_color="#F0F0F0", hover_color="#E0E0E0",
                  text_color="#333", corner_radius=8,
                  command=win.destroy).pack(side="right")

    tk.Frame(win, bg="#E0E0E0", height=1).pack(fill="x", padx=20, pady=(12, 0))

    # ── Chat area ────────────────────────────────────────────
    chat_frame = ctk.CTkScrollableFrame(win, fg_color="#FFFFFF")
    chat_frame.pack(fill="both", expand=True, padx=20, pady=(10, 0))

    def add_message(text, is_user=False):
            bubble_frame = tk.Frame(chat_frame, bg="#FFFFFF")
            bubble_frame.pack(fill="x", pady=4)

            if is_user:
                bubble = ctk.CTkFrame(bubble_frame, fg_color="#F4F6FB", corner_radius=12)
                bubble.pack(side="right", padx=(80, 0))
                ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                            text_color="#0D0101", wraplength=280,
                            justify="left").pack(padx=14, pady=8)
            else:
                bubble = ctk.CTkFrame(bubble_frame, fg_color="#FFFFF",
                                    corner_radius=12, border_width=1,
                                    border_color="#FFFFFF")
                bubble.pack(side="left", padx=(0, 80))
                ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                            text_color="#1A1A1A", wraplength=280,
                            justify="left").pack(padx=14, pady=8)

            # ✅ Auto-scroll to bottom
            win.after(50, lambda: chat_frame._parent_canvas.yview_moveto(1.0))

    # Store chat messages
    win._messages = []

    def add_message(text, is_user=False):
        bubble_frame = tk.Frame(chat_frame, bg="#FFFFFF")
        bubble_frame.pack(fill="x", pady=4)

        if is_user:
            bubble = ctk.CTkFrame(bubble_frame, fg_color="#F4F4F4",  
                                  corner_radius=12)
            bubble.pack(side="right", padx=(10, 0))
            ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                         text_color="#0A0101", wraplength=320,
                         justify="left").pack(padx=14, pady=8)
        else:
            bubble = ctk.CTkFrame(bubble_frame, fg_color="#FFFFFF",
                                  border_color="#ffffff")
            bubble.pack(side="left", padx=(0, 10))
            ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                         text_color="#1A1A1A", wraplength=320,
                         justify="left").pack(padx=14, pady=8)
    win.after(50, lambda: chat_frame._parent_canvas.yview_moveto(1.0))

    # Welcome message
    add_message(f"Hello! I can help you understand the threat detected in {filename}. What would you like to know?")

    # ── Recommended questions ────────────────────────────────
    tk.Frame(win, bg="#FFFFFF", height=1).pack(fill="x", padx=20, pady=(12, 0))

    tk.Label(win, text="Recommended Questions:",
             font=("Arial", 11, "bold"), bg="#FFFFFF",
             fg="#1A1A1A").pack(anchor="w", padx=20, pady=(12, 6))

    questions = [
        "What happened?",
        "Why is it risky?",
        "What should I do?",
    ]

    q_frame = tk.Frame(win, bg="#FFFFFF")
    q_frame.pack(fill="x", padx=20, pady=(0, 10))

    def ask_question(q):
        add_message(q, is_user=True)
        # Simulate AI response
        responses = {
            "What happened?": f"{filename} was detected as a potentially malicious file and quarantined automatically.",
            "Why is it risky?": "Executable files from unknown sources can contain malware, ransomware, or spyware.",
            "What should I do?": "Do not run this file. You can safely delete it from quarantine if you don't recognize it.",
        }
        win.after(400, lambda: add_message(responses.get(q, "I'm analyzing that for you...")))

    for q in questions:
            ctk.CTkButton(
                q_frame,
                text=q,
                font=("Arial", 11),
                fg_color="#FFFFFF",
                hover_color="#F0F4FF",
                text_color="#333333",
                corner_radius=10,
                border_width=1,
                border_color="#CCCCCC",
                height=36,
                command=lambda x=q: ask_question(x)
            ).pack(side="left", padx=(0, 10))

    # ── Input row ────────────────────────────────────────────
    tk.Frame(win, bg="#E0E0E0", height=1).pack(fill="x", padx=20, pady=(4, 0))

    input_row = tk.Frame(win, bg="#FFFFFF")
    input_row.pack(fill="x", padx=20, pady=12)

    entry = ctk.CTkEntry(
            input_row,
            placeholder_text=f"Ask about {filename}...",
            font=("Arial", 12),
            fg_color="#FFFFFF",        # white background
            border_color="#FFFFFF",    # light grey border
            text_color="#1A1A1A",      # standard dark text
            corner_radius=10,
            height=44
        )
    entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

    def send():
        msg = entry.get().strip()
        if msg:
            add_message(msg, is_user=True)
            entry.delete(0, "end")
            win.after(400, lambda: add_message("I'm looking into that for you..."))

    entry.bind("<Return>", lambda e: send())

    ctk.CTkButton(
        input_row,
        text="Send",
        font=("Arial", 12, "bold"),
        fg_color="#2196F3",
        hover_color="#1976D2",
        text_color="#FFFFFF",
        corner_radius=10,
        width=70,
        height=44,
        command=send
    ).pack(side="right")