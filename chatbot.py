import tkinter as tk

def open_chatbot(parent):
    chatbot_window = tk.Toplevel(parent)
    chatbot_window.title("AI Assistant")
    chatbot_window.geometry("400x500")

    tk.Label(
        chatbot_window,
        text="AI Chatbot Coming Soon!",
        font=("Arial", 14)
    ).pack(expand=True)