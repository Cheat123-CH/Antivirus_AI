# quarantine_ui.py
import tkinter as tk
from tkinter import ttk, messagebox
import json
import ctypes

from quarantine_manager import restore_file, CURRENT_QUARANTINE_FILE

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def load_quarantined_files():
    files = []

    if not CURRENT_QUARANTINE_FILE.exists():
        return files

    try:
        with open(CURRENT_QUARANTINE_FILE, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except:
        entries = []

    for entry in entries:

        # Show full file path instead of just file name
        display_name = entry.get("original_path")
        real_name = entry.get("file_name")  # still keep internal

        files.append({
            "timestamp": entry.get("timestamp"),
            "display_name": display_name,
            "real_name": real_name,
            "size": entry.get("size"),
            "hash": entry.get("hash"),
            "user_account": entry.get("user_account")
        })

    return files

def refresh_tree(tree):

    for row in tree.get_children():
        tree.delete(row)

    files = load_quarantined_files()

    for file in files:

        tree.insert(
            "",
            tk.END,
            values=(
                file["timestamp"],
                file["display_name"],
                file["size"],
                file["hash"],
                file["user_account"]
            ),
            tags=(file["real_name"],)
        )

def restore_selected_file(tree):

    selected = tree.selection()

    if not selected:
        messagebox.showwarning("Warning", "Please select a file first.")
        return

    item = tree.item(selected)

    real_file_name = item["tags"][0]
    display_name = item["values"][1]

    confirm = messagebox.askyesno(
        "WARNING",
        f"This file is classified as HIGH-risk.\n\nRestore '{display_name}'?"
    )

    if not confirm:
        return

    success = restore_file(real_file_name)

    if success:
        messagebox.showinfo("Success", f"{display_name} restored successfully.")
        refresh_tree(tree)
    else:
        messagebox.showerror("Error", "Restore failed.")

def build_ui():

    root = tk.Tk()
    root.title("Endpoint Quarantine Manager")
    root.geometry("900x400")

    admin = is_admin()

    columns = (
        "Timestamp",
        "Object Path",  # changed label
        "Size",
        "Hash",
        "User Account"
    )

    tree = ttk.Treeview(root, columns=columns, show="headings", height=15)

    for col in columns:
        tree.heading(col, text=col)

    tree.column("Timestamp", width=150)
    tree.column("Object Path", width=300)
    tree.column("Size", width=80)
    tree.column("Hash", width=300)
    tree.column("User Account", width=120)

    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    refresh_tree(tree)

    if admin:
        restore_btn = tk.Button(
            root,
            text="Restore Selected File",
            command=lambda: restore_selected_file(tree)
        )
        restore_btn.pack(pady=5)

    lbl = tk.Label(
        root,
        text=f"{'Admin Mode' if admin else 'User Mode (Read-only)'}"
    )
    lbl.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    build_ui()