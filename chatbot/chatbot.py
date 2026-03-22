# chatbot.py
import tkinter as tk
import customtkinter as ctk
import threading
import time
from datetime import datetime
from .ai_engine import get_chatbot_response

# Global variable to track the currently open chatbot window
_current_chatbot_window = None

# In-memory storage for conversations by filename
_conversation_storage = {}  # {filename: [messages]}

def open_chatbot(parent, filename="invoice_2024.exe", available_files=None):
    global _current_chatbot_window
    
    # If there's already a chatbot window open, just update its context
    if _current_chatbot_window is not None and _current_chatbot_window.winfo_exists():
        # Update existing window with new filename
        _current_chatbot_window.update_context(filename)
        # Bring it to front
        _current_chatbot_window.lift()
        _current_chatbot_window.focus_force()
        return _current_chatbot_window
    
    # Create new chatbot window
    win = tk.Toplevel(parent)
    win.title("AI Assistant")
    win.geometry("500x650")
    win.configure(bg="#FFFFFF")
    win.resizable(False, False)
    
    # Store the current filename
    win.current_filename = filename
    
    # Generate a unique ID for this window
    win.window_id = str(id(win))
    
    # Initialize storage for this file if not exists
    if filename not in _conversation_storage:
        _conversation_storage[filename] = []
    
    # Initialize window messages from file storage
    win.messages = _conversation_storage[filename]

    screen_w = win.winfo_screenwidth()
    screen_h = win.winfo_screenheight()
    x = screen_w - 500 - 20
    y = screen_h - 650 - 40
    win.geometry(f"500x650+{x}+{y}")

    # Store as global
    _current_chatbot_window = win
    
    # Handle window closing
    def on_closing():
        global _current_chatbot_window
        # Keep conversation in storage (don't delete)
        _current_chatbot_window = None
        win.destroy()
    
    win.protocol("WM_DELETE_WINDOW", on_closing)

    # ── Header ──────────────────────────────────────────────
    header = tk.Frame(win, bg="#FFFFFF")
    header.pack(fill="x", padx=20, pady=(16, 0))

    tk.Label(header, text="🤖  AI Security Assistant",
                font=("Arial", 15, "bold"), bg="#FFFFFF", fg="#1976D2").pack(side="left")

    ctk.CTkButton(header, text="✕", width=30, height=30,
                  fg_color="#F0F0F0", hover_color="#E0E0E0",
                  text_color="#333", corner_radius=8,
                  command=on_closing).pack(side="right")

    tk.Frame(win, bg="#E0E0E0", height=1).pack(fill="x", padx=20, pady=(12, 0))

    # ── Current file display ─────────────────────────────────
    file_display_frame = tk.Frame(win, bg="#FFFFFF")
    file_display_frame.pack(fill="x", padx=20, pady=(10, 5))

    tk.Label(file_display_frame, text="Current file:", 
            font=("Arial", 11, "bold"), bg="#FFFFFF", fg="#333333").pack(side="left", padx=(0, 5))

    # Create a label to show the current filename (just blue text, no box)
    win.current_file_label = tk.Label(
        file_display_frame, 
        text="None selected",
        font=("Arial", 11, "bold"),
        bg="#FFFFFF",  # Match the background
        fg="#999999",  # Gray when none selected
    )
    win.current_file_label.pack(side="left")

    # ── Chat area ────────────────────────────────────────────
    chat_frame = ctk.CTkScrollableFrame(win, fg_color="#FFFFFF")
    chat_frame.pack(fill="both", expand=True, padx=20, pady=(10, 0))

    # ================= SCROLL FIX =================
    def _on_mousewheel(event, canvas):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _bind_scroll(canvas):
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", 
                                                        lambda ev: _on_mousewheel(ev, canvas)))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

    _bind_scroll(chat_frame._parent_canvas)

    # Loading indicator
    loading_frame = tk.Frame(chat_frame, bg="#FFFFFF")
    loading_label = tk.Label(loading_frame, text="⏳ Thinking", font=("Arial", 11), 
                            bg="#FFFFFF", fg="#666666")
    loading_label.pack(side="left", padx=5)
    
    win.is_loading = False

    def animate_loading():
        dots = [".", "..", "...", ""]
        while win.is_loading:
            for dot in dots:
                if not win.is_loading:
                    break
                try:
                    if loading_label.winfo_exists():
                        loading_label.config(text=f"⏳ Thinking{dot}")
                    else:
                        break
                except:
                    break
                win.update()
                time.sleep(0.3)
        try:
            if loading_frame.winfo_exists():
                loading_frame.pack_forget()
        except:
            pass

    def show_loading():
        win.is_loading = True
        try:
            if loading_frame.winfo_exists():
                loading_frame.pack(anchor="w", pady=4)
        except:
            pass
        thread = threading.Thread(target=animate_loading)
        thread.daemon = True
        thread.start()

    def hide_loading():
        win.is_loading = False
        try:
            if loading_frame.winfo_exists():
                loading_frame.pack_forget()
        except:
            pass

    def add_message(text, is_user=False, clear_first=False):
        """Add message to chat and save to temporary storage"""
        if clear_first:
            for widget in chat_frame.winfo_children():
                if widget != loading_frame:
                    widget.destroy()
            win.messages.clear()
            # Also clear from file storage
            if win.current_filename in _conversation_storage:
                _conversation_storage[win.current_filename] = []
        
        timestamp = datetime.now().strftime("%H:%M")
        
        bubble_frame = tk.Frame(chat_frame, bg="#FFFFFF")
        bubble_frame.pack(fill="x", pady=4)

        if is_user:
            bubble = ctk.CTkFrame(bubble_frame, fg_color="#F4F4F4", corner_radius=12)
            bubble.pack(side="right", padx=(10, 0))
            ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                        text_color="#0A0101", wraplength=320,
                        justify="left").pack(padx=14, pady=8)
            time_label = tk.Label(bubble_frame, text=timestamp, 
                                 font=("Arial", 8), bg="#FFFFFF", fg="#999")
            time_label.pack(side="right", padx=(0, 5))
            
            # Save to file storage
            msg_data = {
                'type': 'user',
                'text': text,
                'timestamp': timestamp,
                'file': win.current_filename
            }
            win.messages.append(msg_data)
        else:
            bubble = ctk.CTkFrame(bubble_frame, fg_color="#FFFFFF",
                                  border_color="#E0E0E0", border_width=1)
            bubble.pack(side="left", padx=(0, 10))
            ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                        text_color="#1A1A1A", wraplength=320,
                        justify="left").pack(padx=14, pady=8)
            time_label = tk.Label(bubble_frame, text=timestamp, 
                                 font=("Arial", 8), bg="#FFFFFF", fg="#999")
            time_label.pack(side="left", padx=(5, 0))
            
            # Save to file storage
            msg_data = {
                'type': 'assistant',
                'text': text,
                'timestamp': timestamp,
                'file': win.current_filename
            }
            win.messages.append(msg_data)
        
        try:
            win.after(50, lambda: chat_frame._parent_canvas.yview_moveto(1.0))
        except:
            pass

    # Load existing messages from file storage
    win.messages = _conversation_storage.get(filename, [])
    
    for msg in win.messages:
        timestamp = msg['timestamp']
        text = msg['text']
        is_user = (msg['type'] == 'user')
        
        bubble_frame = tk.Frame(chat_frame, bg="#FFFFFF")
        bubble_frame.pack(fill="x", pady=4)

        if is_user:
            bubble = ctk.CTkFrame(bubble_frame, fg_color="#F4F4F4", corner_radius=12)
            bubble.pack(side="right", padx=(10, 0))
            ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                        text_color="#0A0101", wraplength=320,
                        justify="left").pack(padx=14, pady=8)
            time_label = tk.Label(bubble_frame, text=timestamp, 
                                 font=("Arial", 8), bg="#FFFFFF", fg="#999")
            time_label.pack(side="right", padx=(0, 5))
        else:
            bubble = ctk.CTkFrame(bubble_frame, fg_color="#FFFFFF",
                                  border_color="#E0E0E0", border_width=1)
            bubble.pack(side="left", padx=(0, 10))
            ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                        text_color="#1A1A1A", wraplength=320,
                        justify="left").pack(padx=14, pady=8)
            time_label = tk.Label(bubble_frame, text=timestamp, 
                                 font=("Arial", 8), bg="#FFFFFF", fg="#999")
            time_label.pack(side="left", padx=(5, 0))
    
    # If no messages, show welcome message that guides user to select an activity
    if not win.messages:
        welcome_message = """👋 **Welcome to AI Security Assistant!**

I'm here to help you understand any security alerts on your system. 

📋 **To get started:**
1. **Click on any activity** in the main window
2. The file name will appear here in blue
3. Then you can ask me anything about that specific file!

👉 **Please select a file from the list first** - then I'll be ready to help! 🔒"""

        add_message(welcome_message)

    # ── Create frames for question and input sections (initially hidden) ─────────────
    
    # Create question label (but don't pack it yet)
    win.question_label = tk.Label(win, text="Recommended Questions:",
                                  font=("Arial", 11, "bold"), bg="#FFFFFF",
                                  fg="#1A1A1A")
    
    # Create separator (but don't pack it yet)
    win.separator = tk.Frame(win, bg="#E0E0E0", height=1)
    
    # Create input separator (but don't pack it yet)
    win.input_separator = tk.Frame(win, bg="#E0E0E0", height=1)

    questions = [
        "What happened?",
        "Why is it risky?",
        "What should I do?",
    ]

    # Create question frame (but don't pack it yet)
    win.q_frame = tk.Frame(win, bg="#FFFFFF")

    def ask_question(q):
        add_message(q, is_user=True)
        
        for widget in win.q_frame.winfo_children():
            widget.configure(state="disabled")
        win.send_button.configure(state="disabled")
        win.entry.configure(state="disabled")
        
        show_loading()
        
        def get_response():
            try:
                response = get_chatbot_response(win.current_filename, q)
                win.after(0, lambda: display_response(response))
            except Exception as e:
                win.after(0, lambda: display_response(f"Sorry, I encountered an error: {str(e)}"))
        
        thread = threading.Thread(target=get_response)
        thread.daemon = True
        thread.start()

    def display_response(response):
        hide_loading()
        
        if "AI service temporarily unavailable" in response:
            parts = response.split("\n\n", 1)
            if len(parts) == 2:
                warning, answer = parts
                add_message(warning + "\n" + answer)
            else:
                add_message(response)
        else:
            add_message(response)
        
        for widget in win.q_frame.winfo_children():
            widget.configure(state="normal")
        win.send_button.configure(state="normal")
        win.entry.configure(state="normal")
        win.entry.focus()

    for q in questions:
        btn = ctk.CTkButton(
            win.q_frame,
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

    # ── Input row (initially hidden) ─────────────────────────
    
    win.input_row = tk.Frame(win, bg="#FFFFFF")

    win.entry = ctk.CTkEntry(
        win.input_row,
        placeholder_text="Ask about the selected file...",
        font=("Arial", 12),
        fg_color="#FFFFFF",
        border_color="#DDDDDD",
        text_color="#1A1A1A",
        corner_radius=10,
        height=44
    )
    win.entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

    def send_message(event=None):
        msg = win.entry.get().strip()
        if not msg:
            return
        
        add_message(msg, is_user=True)
        win.entry.delete(0, "end")
        
        for widget in win.q_frame.winfo_children():
            widget.configure(state="disabled")
        win.send_button.configure(state="disabled")
        win.entry.configure(state="disabled")
        
        show_loading()
        
        def get_response():
            try:
                response = get_chatbot_response(win.current_filename, msg)
                win.after(0, lambda: display_response(response))
            except Exception as e:
                win.after(0, lambda: display_response(f"Sorry, I encountered an error: {str(e)}"))
        
        thread = threading.Thread(target=get_response)
        thread.daemon = True
        thread.start()

    win.entry.bind("<Return>", send_message)

    win.send_button = ctk.CTkButton(
        win.input_row,
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
    win.send_button.pack(side="right")
    
    # Initially hide the question and input sections
    def hide_input_sections():
        """Hide the question and input sections"""
        win.question_label.pack_forget()
        win.separator.pack_forget()
        win.q_frame.pack_forget()
        win.input_separator.pack_forget()
        win.input_row.pack_forget()
    
    def show_input_sections():
        """Show the question and input sections"""
        # Show separator
        win.separator.pack(fill="x", padx=20, pady=(12, 0))
        
        # Show question label
        win.question_label.pack(anchor="w", padx=20, pady=(12, 6))
        
        # Show question frame
        win.q_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        # Show input separator
        win.input_separator.pack(fill="x", padx=20, pady=(4, 0))
        
        # Show input row
        win.input_row.pack(fill="x", padx=20, pady=12)
    
    # Hide sections initially
    hide_input_sections()
    
    # Method to update context without showing message (called from main.py)
    def update_context(new_filename):
        """Update the chatbot to discuss a new file without showing a message"""
        
        # Save current messages to storage before switching
        if win.current_filename != new_filename:
            # Update storage for current file
            if win.current_filename != "invoice_2024.exe":  # Don't save default
                _conversation_storage[win.current_filename] = win.messages.copy()
            
            # Load new file's messages
            if new_filename not in _conversation_storage:
                _conversation_storage[new_filename] = []
            
            # Clear chat (but keep loading frame)
            for widget in chat_frame.winfo_children():
                if widget != loading_frame:
                    widget.destroy()
            
            # Update current file
            win.current_filename = new_filename
            
            # Update the display label
            win.current_file_label.configure(text=new_filename, fg="#1976D2")
            
            # Load new messages
            win.messages = _conversation_storage[new_filename]
            for msg in win.messages:
                timestamp = msg['timestamp']
                text = msg['text']
                is_user = (msg['type'] == 'user')
                
                bubble_frame = tk.Frame(chat_frame, bg="#FFFFFF")
                bubble_frame.pack(fill="x", pady=4)

                if is_user:
                    bubble = ctk.CTkFrame(bubble_frame, fg_color="#F4F4F4", corner_radius=12)
                    bubble.pack(side="right", padx=(10, 0))
                    ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                                text_color="#0A0101", wraplength=320,
                                justify="left").pack(padx=14, pady=8)
                    time_label = tk.Label(bubble_frame, text=timestamp, 
                                         font=("Arial", 8), bg="#FFFFFF", fg="#999")
                    time_label.pack(side="right", padx=(0, 5))
                else:
                    bubble = ctk.CTkFrame(bubble_frame, fg_color="#FFFFFF",
                                          border_color="#E0E0E0", border_width=1)
                    bubble.pack(side="left", padx=(0, 10))
                    ctk.CTkLabel(bubble, text=text, font=("Arial", 12),
                                text_color="#1A1A1A", wraplength=320,
                                justify="left").pack(padx=14, pady=8)
                    time_label = tk.Label(bubble_frame, text=timestamp, 
                                         font=("Arial", 8), bg="#FFFFFF", fg="#999")
                    time_label.pack(side="left", padx=(5, 0))
            
            # Show the input sections now that a file is selected
            show_input_sections()
            
            # Show a confirmation that file was selected (only if no previous messages)
            if not win.messages:
                add_message(f"✅ Now discussing: **{new_filename}**. What would you like to know about this file?")
            
            # Scroll to bottom
            try:
                win.after(100, lambda: chat_frame._parent_canvas.yview_moveto(1.0))
            except:
                pass
        
        win.lift()
        win.focus_force()
    
    # Attach methods to window
    win.update_context = update_context
    win.hide_input_sections = hide_input_sections
    win.show_input_sections = show_input_sections

    return win