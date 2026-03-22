import tkinter as tk
from tkinter import ttk, messagebox
import tkinter.font as tkfont

# ── Color Palette ──────────────────────────────────────────────
BG          = "#F4F6F8"
HEADER_BG   = "#E8A800"   
PANEL_BG    = "#FFFFFF"
ACCENT      = "#0F5C75" 
ACCENT2     = "#0F5C75"
TEXT_DARK   = "#1A2A36"
TEXT_LIGHT  = "#FFFFFF"
TEXT_MID    = "#5A6A78"
BORDER      = "#D0D8E0"
CARD_HOVER  = "#EAF4F8"
BTN_BUY     = "#0F5C75"
BTN_ACT     = "#FFFFFF"
SUCCESS     = "#2ECC71"
WARNING     =  "#0F5C75"


class AntivirusApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureShield — Antivirus Protection")
        self.geometry("820x620")
        self.resizable(False, False)
        self.configure(bg=BG)
        self._center()
        self._build_ui()

    def _center(self):
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - 820) // 2
        y = (self.winfo_screenheight() - 620) // 2
        self.geometry(f"820x620+{x}+{y}")

    # ── Main layout ────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        self._build_body()

    def _build_header(self):
        hdr = tk.Frame(self, bg=WARNING, height=90)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Warning icon circle
        canvas = tk.Canvas(hdr, width=50, height=50,
                           bg=WARNING, highlightthickness=0)
        canvas.place(x=24, y=20)
        canvas.create_oval(2, 2, 48, 48, fill="#F0B800", outline="#FFD040", width=2)
        canvas.create_text(25, 25, text="!", fill=TEXT_LIGHT,
                           font=("Georgia", 22, "bold"))

        tk.Label(hdr, text="Attention Required",
                 bg=WARNING, fg=TEXT_LIGHT,
                 font=("Trebuchet MS", 18, "bold")).place(x=90, y=18)
        tk.Label(hdr, text="Your free trial expires in 8 days.",
                 bg=WARNING, fg="#FFF8E1",
                 font=("Trebuchet MS", 11)).place(x=90, y=50)

        # Logo area (right side)
        tk.Label(hdr, text="🛡  SecureShield",
                 bg=WARNING, fg=TEXT_LIGHT,
                 font=("Trebuchet MS", 13, "bold")).place(x=630, y=35)

    def _build_body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=20)

        # Left sidebar buttons
        side = tk.Frame(body, bg=BG, width=180)
        side.pack(side="left", fill="y", padx=(0, 16))
        side.pack_propagate(False)

        tk.Label(side, text="QUICK ACTIONS",
                 bg=BG, fg=TEXT_MID,
                 font=("Trebuchet MS", 9, "bold")).pack(anchor="w", pady=(4, 8))

        self._sidebar_btn(side, "🛒  Buy Subscription",
                          BTN_BUY, TEXT_LIGHT, self._open_activation)
        self._sidebar_btn(side, "🔑  Activate Product",
                          BTN_ACT, ACCENT, self._open_activation,
                          outline=True)

        tk.Frame(side, bg=BORDER, height=1).pack(fill="x", pady=14)
        tk.Label(side, text="FREE TRIAL STATUS",
                 bg=BG, fg=TEXT_MID,
                 font=("Trebuchet MS", 9, "bold")).pack(anchor="w", pady=(0, 6))

        prog_lbl = tk.Label(side, text="8 days remaining",
                            bg=BG, fg=ACCENT,
                            font=("Trebuchet MS", 10, "bold"))
        prog_lbl.pack(anchor="w")

        bar_bg = tk.Frame(side, bg=BORDER, height=8, width=160)
        bar_bg.pack(anchor="w", pady=(4, 0))
        bar_fg = tk.Frame(bar_bg, bg="#FFD040", height=8, width=40)
        bar_fg.place(x=0, y=0)

        tk.Label(side, text="25% of trial used",
                 bg=BG, fg=TEXT_MID,
                 font=("Trebuchet MS", 8)).pack(anchor="w", pady=(2, 0))

        # Main panel
        main = tk.Frame(body, bg=PANEL_BG,
                        highlightbackground=BORDER, highlightthickness=1)
        main.pack(side="left", fill="both", expand=True)

        tk.Label(main, text="Choose an Activation Option",
                 bg=PANEL_BG, fg=TEXT_DARK,
                 font=("Trebuchet MS", 14, "bold")).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(main, text="Select the option that best fits your needs.",
                 bg=PANEL_BG, fg=TEXT_MID,
                 font=("Trebuchet MS", 10)).pack(anchor="w", padx=20, pady=(0, 14))

        tk.Frame(main, bg=BORDER, height=1).pack(fill="x", padx=20)

        cards_frame = tk.Frame(main, bg=PANEL_BG)
        cards_frame.pack(fill="both", expand=True, padx=20, pady=16)

        # Row 1
        row1 = tk.Frame(cards_frame, bg=PANEL_BG)
        row1.pack(fill="x", pady=(0, 12))

        self._option_card(
            row1,
            icon="🏠",
            title="Home User",
            subtitle="Personal & Family",
            desc="Perfect for protecting personal devices.\nUp to 5 devices included.",
            color=ACCENT,
            command=lambda: self._select_plan("Home User"),
        )
        self._option_card(
            row1,
            icon="🏢",
            title="Small Business (SME)",
            subtitle="Teams & Organizations",
            desc="Centralized management for businesses.\nScalable from 5 to 250 seats.",
            color=ACCENT,
            command=lambda: self._select_plan("Small Business (SME)"),
        )

        # Row 2
        row2 = tk.Frame(cards_frame, bg=PANEL_BG)
        row2.pack(fill="x")

        self._option_card(
            row2,
            icon="👤",
            title="Use My Account",
            subtitle="ESET HOME Login",
            desc="Log in with your existing account to\nrestore or transfer a subscription.",
            color=ACCENT,
            command=lambda: self._select_plan("My Account"),
        )
        self._option_card(
            row2,
            icon="🔑",
            title="Enter Activation Key",
            subtitle="Purchased License",
            desc="Already have a key? Enter it here\nto activate your product instantly.",
            color=ACCENT,
            command=lambda: self._select_plan("Activation Key"),
        )

    # ── Reusable widgets ───────────────────────────────────────
    def _sidebar_btn(self, parent, text, bg, fg, cmd, outline=False):
        btn = tk.Label(parent, text=text, bg=bg, fg=fg,
                       font=("Trebuchet MS", 10, "bold"),
                       padx=12, pady=10, cursor="hand2",
                       relief="flat", bd=0)
        if outline:
            btn.config(highlightbackground=ACCENT,
                       highlightthickness=1,
                       highlightcolor=ACCENT)
        btn.pack(fill="x", pady=4)
        btn.bind("<Button-1>", lambda e: cmd())
        btn.bind("<Enter>", lambda e: btn.config(bg=ACCENT2 if not outline else CARD_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg))

    def _option_card(self, parent, icon, title, subtitle, desc, color, command, title_color="#0F5C75"):
        card = tk.Frame(parent, bg=PANEL_BG, cursor="hand2",
                        highlightbackground=BORDER, highlightthickness=1,
                        width=270, height=140)
        card.pack(side="left", padx=(0, 12), fill="y")
        card.pack_propagate(False)

        # Colored left stripe
        stripe = tk.Frame(card, bg=color, width=5)
        stripe.pack(side="left", fill="y")

        inner = tk.Frame(card, bg=PANEL_BG)
        inner.pack(side="left", fill="both", expand=True, padx=12, pady=10)

        top = tk.Frame(inner, bg=PANEL_BG)
        top.pack(fill="x")

        tk.Label(top, text=icon, bg=PANEL_BG, fg=color,
                 font=("Segoe UI Emoji", 18)).pack(side="left")
        right_lbl = tk.Frame(top, bg=PANEL_BG)
        right_lbl.pack(side="left", padx=8)
        tk.Label(right_lbl, text=title, bg=PANEL_BG, fg=TEXT_DARK,
                 font=("Trebuchet MS", 11, "bold"),
                 anchor="w").pack(anchor="w")
        tk.Label(right_lbl, text=subtitle, bg=PANEL_BG, fg=color,
                 font=("Trebuchet MS", 8, "bold"),
                 anchor="w").pack(anchor="w")

        tk.Label(inner, text=desc, bg=PANEL_BG, fg=TEXT_MID,
                 font=("Trebuchet MS", 9),
                 justify="left", anchor="w").pack(anchor="w", pady=(6, 6))

        select_btn = tk.Label(inner, text="Select  →",
                              bg=color, fg=TEXT_LIGHT,
                              font=("Trebuchet MS", 8, "bold"),
                              padx=10, pady=4, cursor="hand2")
        select_btn.pack(anchor="w")

        # Hover effects on entire card
        for widget in (card, inner, top, right_lbl):
            widget.bind("<Enter>", lambda e, c=card, s=select_btn, col=color:
                        self._card_hover(c, s, col, True))
            widget.bind("<Leave>", lambda e, c=card, s=select_btn, col=color:
                        self._card_hover(c, s, col, False))
            widget.bind("<Button-1>", lambda e, cmd=command: cmd())

        select_btn.bind("<Button-1>", lambda e, cmd=command: cmd())
        select_btn.bind("<Enter>", lambda e, c=card, s=select_btn, col=color:
                        self._card_hover(c, s, col, True))

    def _card_hover(self, card, btn, color, entering):
        card.config(highlightbackground=color if entering else BORDER)
        for w in card.winfo_children():
            if isinstance(w, tk.Frame):
                w.config(bg=CARD_HOVER if entering else PANEL_BG)
                for ww in w.winfo_children():
                    if isinstance(ww, (tk.Label, tk.Frame)):
                        try:
                            if ww.cget("bg") != color:
                                ww.config(bg=CARD_HOVER if entering else PANEL_BG)
                        except Exception:
                            pass

    # ── Dialogs ────────────────────────────────────────────────
    def _select_plan(self, plan):
        if plan == "My Account":
            self._login_dialog()
        elif plan == "Activation Key":
            self._key_dialog()
        else:
            self._buy_dialog(plan)

    def _buy_dialog(self, plan):
        dlg = self._make_dialog(f"Buy Subscription — {plan}", 480, 320)

        tk.Label(dlg, text=f"🛒  {plan} Plan",
                 bg=PANEL_BG, fg=TEXT_DARK,
                 font=("Trebuchet MS", 14, "bold")).pack(pady=(24, 4))
        tk.Label(dlg, text="Choose your subscription duration:",
                 bg=PANEL_BG, fg=TEXT_MID,
                 font=("Trebuchet MS", 10)).pack()

        choice = tk.StringVar(value="1 Year")
        for opt, price in [("1 Year", "$39.99"), ("2 Years", "$69.99"), ("3 Years", "$89.99")]:
            row = tk.Frame(dlg, bg=PANEL_BG)
            row.pack(fill="x", padx=40, pady=4)
            tk.Radiobutton(row, text=f"{opt}  —  {price}",
                           variable=choice, value=opt,
                           bg=PANEL_BG, fg=TEXT_DARK,
                           font=("Trebuchet MS", 10),
                           activebackground=PANEL_BG,
                           selectcolor=ACCENT).pack(side="left")

        def confirm():
            messagebox.showinfo("Redirecting",
                f"You selected: {plan} / {choice.get()}\n\nYou will now be redirected to checkout.",
                parent=dlg)
            dlg.destroy()

        tk.Button(dlg, text="Proceed to Checkout",
                  bg=BTN_BUY, fg=TEXT_LIGHT,
                  font=("Trebuchet MS", 10, "bold"),
                  relief="flat", padx=20, pady=8,
                  cursor="hand2", command=confirm).pack(pady=20)

    def _login_dialog(self):
        dlg = self._make_dialog("Sign In — My Account", 420, 300)

        tk.Label(dlg, text="👤  Sign in to Your Account",
                 bg=PANEL_BG, fg=TEXT_DARK,
                 font=("Trebuchet MS", 13, "bold")).pack(pady=(24, 12))

        for label, show in [("Email address", ""), ("Password", "*")]:
            tk.Label(dlg, text=label, bg=PANEL_BG, fg=TEXT_MID,
                     font=("Trebuchet MS", 9)).pack(anchor="w", padx=40)
            entry = tk.Entry(dlg, font=("Trebuchet MS", 10),
                             show=show, width=36,
                             relief="flat", bg="#EEF2F5", bd=0,
                             highlightthickness=1,
                             highlightbackground=BORDER,
                             highlightcolor=ACCENT)
            entry.pack(padx=40, pady=(2, 10), ipady=6)

        def login():
            messagebox.showinfo("Success", "Signed in successfully!\nYour subscription has been activated.", parent=dlg)
            dlg.destroy()

        tk.Button(dlg, text="Sign In",
                  bg=ACCENT, fg=TEXT_LIGHT,
                  font=("Trebuchet MS", 10, "bold"),
                  relief="flat", padx=20, pady=8,
                  cursor="hand2", command=login).pack(pady=4)

    def _key_dialog(self):
        dlg = self._make_dialog("Enter Activation Key", 420, 240)

        tk.Label(dlg, text="🔑  Enter Your Activation Key",
                 bg=PANEL_BG, fg=TEXT_DARK,
                 font=("Trebuchet MS", 13, "bold")).pack(pady=(24, 8))
        tk.Label(dlg, text="Format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
                 bg=PANEL_BG, fg=TEXT_MID,
                 font=("Trebuchet MS", 9)).pack()

        key_var = tk.StringVar()
        entry = tk.Entry(dlg, textvariable=key_var,
                         font=("Courier New", 12, "bold"),
                         width=32, relief="flat", bg="#EEF2F5", bd=0,
                         highlightthickness=1,
                         highlightbackground=BORDER,
                         highlightcolor=ACCENT,
                         justify="center")
        entry.pack(padx=40, pady=12, ipady=8)

        def activate():
            key = key_var.get().strip()
            if len(key) < 5:
                messagebox.showerror("Invalid Key", "Please enter a valid activation key.", parent=dlg)
                return
            messagebox.showinfo("Activated!", f"Product activated successfully!\nKey: {key}", parent=dlg)
            dlg.destroy()

        tk.Button(dlg, text="Activate Now",
                  bg="#C62828", fg=TEXT_LIGHT,
                  font=("Trebuchet MS", 10, "bold"),
                  relief="flat", padx=20, pady=8,
                  cursor="hand2", command=activate).pack()

    def _open_activation(self):
        self._buy_dialog("Home User")

    # ── Helper ─────────────────────────────────────────────────
    def _make_dialog(self, title, w, h):
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.geometry(f"{w}x{h}")
        dlg.resizable(False, False)
        dlg.configure(bg=PANEL_BG)
        dlg.grab_set()
        x = self.winfo_x() + (820 - w) // 2
        y = self.winfo_y() + (620 - h) // 2
        dlg.geometry(f"{w}x{h}+{x}+{y}")
        return dlg


if __name__ == "__main__":
    app = AntivirusApp()
    app.mainloop()