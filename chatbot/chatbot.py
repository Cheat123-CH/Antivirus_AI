# chatbot.py
import tkinter as tk
import customtkinter as ctk
import threading
import time
from .ai_engine import get_chatbot_response

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

    # Store chat messages for history (optional)
    win.chat_history = []

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

    # ================= SCROLL FIX =================
    def _on_mousewheel(event, canvas):
        """Handle mouse wheel scrolling"""
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _bind_scroll(canvas):
        """Bind mouse wheel to canvas"""
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", 
                                                        lambda ev: _on_mousewheel(ev, canvas)))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

    # Apply scroll binding to the canvas inside CTkScrollableFrame
    _bind_scroll(chat_frame._parent_canvas)

    # Loading indicator (hidden by default)
    loading_frame = tk.Frame(chat_frame, bg="#FFFFFF")
    loading_label = tk.Label(loading_frame, text="⏳ Thinking", font=("Arial", 11), 
                            bg="#FFFFFF", fg="#666666")
    loading_label.pack(side="left", padx=5)
    
    # Store loading animation state
    win.is_loading = False
    win.loading_dots = 0

    def animate_loading():
        """Animate the loading dots"""
        dots = [".", "..", "...", ""]
        while win.is_loading:
            for dot in dots:
                if not win.is_loading:
                    break
                # FIX: Check if widget still exists before updating
                try:
                    if loading_label.winfo_exists():
                        loading_label.config(text=f"⏳ Thinking{dot}")
                    else:
                        break
                except:
                    break
                win.update()
                time.sleep(0.3)
        # FIX: Check if widget exists before forgetting
        try:
            if loading_frame.winfo_exists():
                loading_frame.pack_forget()
        except:
            pass

    def show_loading():
        """Show loading indicator"""
        win.is_loading = True
        try:
            if loading_frame.winfo_exists():
                loading_frame.pack(anchor="w", pady=4)
        except:
            pass
        # Start animation in background thread
        thread = threading.Thread(target=animate_loading)
        thread.daemon = True
        thread.start()

    def hide_loading():
        """Hide loading indicator"""
        win.is_loading = False
        # FIX: Check if widget exists before forgetting
        try:
            if loading_frame.winfo_exists():
                loading_frame.pack_forget()
        except:
            pass

    def add_message(text, is_user=False):
        """Add message to chat"""
        bubble_frame = tk.Frame(chat_frame, bg="#FFFFFF")
        bubble_frame.pack(fill="x", pady=4)

        if is_user:
            bubble = ctk.CTkFrame(bubble_frame, fg_color="#F4F4F4", corner_radius=12)
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
        
        # Auto-scroll to bottom
        try:
            win.after(50, lambda: chat_frame._parent_canvas.yview_moveto(1.0))
        except:
            pass

    # Welcome message
    add_message(f"Hello! I can help you understand the threat detected in {filename}. I'll explain everything in simple terms!")

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
        """Handle recommended question clicks"""
        # Add user message immediately
        add_message(q, is_user=True)
        
        # Disable buttons while loading
        for widget in q_frame.winfo_children():
            widget.configure(state="disabled")
        send_button.configure(state="disabled")
        entry.configure(state="disabled")
        
        # Show loading indicator
        show_loading()
        
        # Get response in background thread
        def get_response():
            try:
                response = get_chatbot_response(filename, q)
                # Schedule UI update in main thread
                win.after(0, lambda: display_response(response))
            except Exception as e:
                win.after(0, lambda: display_response(f"Sorry, I encountered an error: {str(e)}"))
        
        thread = threading.Thread(target=get_response)
        thread.daemon = True
        thread.start()

    def display_response(response):
        """Display AI response and re-enable UI"""
        # Hide loading
        hide_loading()
        
        # Check if response contains the service unavailable message
        if "AI service temporarily unavailable" in response:
            # Split the message to show warning differently if desired
            parts = response.split("\n\n", 1)
            if len(parts) == 2:
                warning, answer = parts
                # You could show warning in red/orange if you want
                add_message(warning + "\n" + answer)
            else:
                add_message(response)
        else:
            # Normal AI response
            add_message(response)
        
        # Re-enable buttons
        for widget in q_frame.winfo_children():
            widget.configure(state="normal")
        send_button.configure(state="normal")
        entry.configure(state="normal")
        entry.focus()

    for q in questions:
        btn = ctk.CTkButton(
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
        )
        btn.pack(side="left", padx=(0, 10))

    # ── Input row ────────────────────────────────────────────
    tk.Frame(win, bg="#E0E0E0", height=1).pack(fill="x", padx=20, pady=(4, 0))

    input_row = tk.Frame(win, bg="#FFFFFF")
    input_row.pack(fill="x", padx=20, pady=12)

    entry = ctk.CTkEntry(
        input_row,
        placeholder_text=f"Ask about {filename}...",
        font=("Arial", 12),
        fg_color="#FFFFFF",
        border_color="#FFFFFF",
        text_color="#1A1A1A",
        corner_radius=10,
        height=44
    )
    entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

    def send_message(event=None):
        """Handle send button click or Enter key"""
        msg = entry.get().strip()
        if not msg:
            return
        
        # Add user message
        add_message(msg, is_user=True)
        entry.delete(0, "end")
        
        # Disable UI while loading
        for widget in q_frame.winfo_children():
            widget.configure(state="disabled")
        send_button.configure(state="disabled")
        entry.configure(state="disabled")
        
        # Show loading
        show_loading()
        
        # Get response in background
        def get_response():
            try:
                response = get_chatbot_response(filename, msg)
                win.after(0, lambda: display_response(response))
            except Exception as e:
                win.after(0, lambda: display_response(f"Sorry, I encountered an error: {str(e)}"))
        
        thread = threading.Thread(target=get_response)
        thread.daemon = True
        thread.start()

    entry.bind("<Return>", send_message)

    send_button = ctk.CTkButton(
        input_row,
        text="Send",
        font=("Arial", 12, "bold"),
        fg_color="#2196F3",
        hover_color="#1976D2",
        text_color="#FFFFFF",
        corner_radius=10,
        width=70,
        height=44,
        command=send_message
    )
    send_button.pack(side="right")