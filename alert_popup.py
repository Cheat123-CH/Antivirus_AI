import tkinter as tk
import customtkinter as ctk

def show_security_popup(parent, filename,on_dashboard=None):
    # Create Toplevel popup
    alert = tk.Toplevel(parent)
    alert.geometry("450x320")
    alert.configure(bg="white", highlightbackground="#2485C1", highlightthickness=1)
    alert.lift()
    alert.attributes("-topmost", True)
    alert.overrideredirect(True)

    def go_to_dashboard():
        alert.destroy()          
        if on_dashboard:
            on_dashboard()   

    # Popup size
    popup_width = 450
    popup_height = 320

    # Get screen size
    screen_width = alert.winfo_screenwidth()
    screen_height = alert.winfo_screenheight()

    # Bottom-right position
    x = screen_width - popup_width - 10   # 10px from right
    y = screen_height - popup_height - 10 # 10px from bottom

    alert.geometry(f"{popup_width}x{popup_height}+{x}+{y}")

    # Header
    header_frame = tk.Frame(alert, bg="white")
    header_frame.pack(fill="x", padx=25, pady=(25, 10))

    # Info icon
    info_icon = ctk.CTkLabel(
        header_frame,
        text="i",
        fg_color="#2485C1",
        text_color="white",
        corner_radius=10,
        width=35,
        height=35,
        font=("Times New Roman", 22, "bold")
    )
    info_icon.pack(side="left", padx=(0, 15))

    tk.Label(header_frame, 
             text="See how we've kept you safe", 
             font=("Times New Roman", 14, "bold"), 
             bg="white", 
             fg="#1A1A1B").pack(side="left")

    # Close button
    close_btn = tk.Label(alert, text="✕", font=("Times New Roman", 15), bg="white", fg="#888", cursor="hand2")
    close_btn.place(x=420, y=10)
    close_btn.bind("<Button-1>", lambda e: alert.destroy())

    # Description
    desc_text = f"Threat detected: {filename} \n AI-Sec keeps you protected every day. We have isolated this file safely to prevent any system changes."
    tk.Label(alert, 
             text=desc_text, 
             font=("Times New Roman", 12), 
             fg="#363636", 
             bg="white", 
             wraplength=340, 
             justify="left").pack(anchor="w", padx=65, pady=(0, 20))

    # Security dashboard button
    report_btn = tk.Button(alert,
                           text="Go to Security Dashboard",
                           command=go_to_dashboard,   # <-- calls our function
                           bg="#2485C1",
                           fg="white",
                           font=("Times New Roman", 10, "bold"),
                           relief="flat",
                           activebackground="#1B6391",
                           activeforeground="white",
                           padx=25,
                           pady=8,
                           cursor="hand2")
    report_btn.pack(anchor="w", padx=65, pady=(0, 20))

    # Footer link
    footer_link = tk.Label(alert, 
                           text="I don't want to receive Security report notifications.", 
                           font=("Times New Roman", 10), 
                           fg="#2485C1", 
                           bg="white", 
                           cursor="hand2")
    footer_link.pack(anchor="w", padx=65, pady=(0, 10))

    # Bottom bar
    bottom_bar = tk.Frame(alert, bg="#F9F9F9", height=40)
    bottom_bar.pack(fill="x", side="bottom")
    bottom_bar.pack_propagate(False)
    tk.Label(bottom_bar, 
             text="Learn more about this message", 
             font=("Times New Roman", 10), 
             bg="#F9F9F9", 
             fg="#666").pack(side="left", padx=20)

    # Auto-destroy after 5 seconds (5000 ms)
    alert.lift()
    alert.attributes("-topmost", True)
    alert.after(50000, alert.destroy)