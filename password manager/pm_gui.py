#!/usr/bin/env python3

import os
import sys
import traceback
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from vault_store import create_vault, unlock_vault, VaultError, WrongPasswordError, VaultCorruptError
from pm import generate_password

VAULT_PATH = "vault.json"

DARK_BG = "#1e1e24"
PANEL_BG = "#26262e"
ACCENT = "#7c9eff"
FG = "#e6e6eb"
MUTED = "#9a9aa5"
DANGER = "#ff6b6b"
FONT = ("Segoe UI", 10)
FONT_MONO = ("Consolas", 10)


class VaultApp:
    """Owns a Tk root window and swaps its content between the lock screen
    and the main screen. Does NOT subclass tk.Tk (see module docstring)."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Local Password Manager")
        self.root.geometry("760x480")
        self.root.minsize(620, 420)
        self.root.configure(bg=DARK_BG)
        self.root.report_callback_exception = self._on_callback_error

        self.vault = None
        self.pw_var = None
        self.pw_confirm_var = None
        self.search_var = None
        self.lock_status = None
        self.tree = None

        self._build_style()
        self.show_lock_screen()

    # error safety net
    def _on_callback_error(self, exc_type, exc_value, exc_tb):
        """Catches any exception raised inside a Tkinter callback (button
        click, keypress, etc.) so a bug shows a readable message instead of
        leaving the app looking frozen on the old screen."""
        detail = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        print(detail, file=sys.stderr)
        messagebox.showerror(
            "Unexpected error",
            f"Something went wrong:\n\n{exc_value}\n\n"
            "Details were printed to the terminal.",
        )

    def run(self):
        self.root.mainloop()

    # - styling -
    def _build_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass   # fall back to whatever default theme is available
        
        style.configure("TFrame", background=DARK_BG)
        style.configure("Panel.TFrame", background=PANEL_BG)
        style.configure("TLabel", background=DARK_BG, foreground=FG, font=FONT)
        style.configure("Muted.TLabel", background=DARK_BG, foreground=MUTED, font=FONT)
        style.configure("Panel.TLabel", background=PANEL_BG, foreground=FG, font=FONT)
        style.configure("Title.TLabel", background=DARK_BG, foreground=FG, font=("Segoe UI", 16, "bold"))
        style.configure("TButton", background=ACCENT, foreground="#12131a", font=FONT, padding=6, borderwidth=0)
        style.map("TButton", background=[("active", "#93b0ff")])
        style.configure("Danger.TButton", background=DANGER, foreground="#12131a", font=FONT, padding=6)
        style.map("Danger.TButton", background=[("active", "#ff8a8a")])
        style.configure("TEntry", fieldbackground=PANEL_BG, foreground=FG, insertcolor=FG, borderwidth=1)
        style.configure(
            "Treeview",
            background=PANEL_BG, fieldbackground=PANEL_BG, foreground=FG,
            rowheight=26, font=FONT, borderwidth=0,
        )
        style.configure("Treeview.Heading", background="#33333d", foreground=FG, font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#12131a")])

    def _clear_root(self):
        for w in self.root.winfo_children():
            w.destroy()

    #  lock screen 
    def show_lock_screen(self):
        self._clear_root()
        root = self.root

        frame = ttk.Frame(root, padding=40)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="Local Password Manager", style="Title.TLabel").pack(pady=(0, 4))
        exists = os.path.exists(VAULT_PATH)
        subtitle = f"Vault: {os.path.abspath(VAULT_PATH)}" if exists else "No vault found: one will be created."
        ttk.Label(frame, text=subtitle, style="Muted.TLabel").pack(pady=(0, 20))

        self.pw_var = tk.StringVar()
        pw_entry = ttk.Entry(frame, textvariable=self.pw_var, show="•", width=32, font=FONT)
        pw_entry.pack(pady=(0, 4))

        if not exists:
            self.pw_confirm_var = tk.StringVar()
            ttk.Label(frame, text="Confirm master password:", style="Muted.TLabel").pack(pady=(10, 2))
            confirm_entry = ttk.Entry(frame, textvariable=self.pw_confirm_var, show="•", width=32, font=FONT)
            confirm_entry.pack(pady=(0, 4))
            confirm_entry.bind("<Return>", lambda e: self._do_create())
            button_label, button_action = "Create Vault", self._do_create
        else:
            pw_entry.bind("<Return>", lambda e: self._do_unlock())
            button_label, button_action = "Unlock", self._do_unlock

        ttk.Button(frame, text=button_label, command=button_action).pack(pady=(16, 0), fill="x")
        self.lock_status = ttk.Label(frame, text="", style="Muted.TLabel")
        self.lock_status.pack(pady=(10, 0))

        pw_entry.focus_set()

    def _set_lock_status(self, text):
        if self.lock_status is not None:
            self.lock_status.config(text=text, foreground=DANGER)

    def _do_create(self):
        pw = self.pw_var.get()
        confirm = self.pw_confirm_var.get() if self.pw_confirm_var is not None else ""
        if len(pw) < 8:
            self._set_lock_status("Master password must be at least 8 characters.")
            return
        if pw != confirm:
            self._set_lock_status("Passwords don't match.")
            return
        try:
            self.vault = create_vault(VAULT_PATH, pw)
        except VaultError as e:
            self._set_lock_status(str(e))
            return
        
        # Vault created and go straight in, no extra "now unlock it" step.
        self.show_main_screen()

    def _do_unlock(self):
        pw = self.pw_var.get()
        try:
            self.vault = unlock_vault(VAULT_PATH, pw)
        except WrongPasswordError:
            self._set_lock_status("Incorrect master password.")
            return
        except VaultCorruptError as e:
            self._set_lock_status(str(e))
            return
        self.show_main_screen()

    # main screen 
    def show_main_screen(self):
        self._clear_root()
        root = self.root

        top = ttk.Frame(root, padding=(16, 12))
        top.pack(fill="x")
        ttk.Label(top, text="🔓 Vault unlocked", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Lock", command=self._lock).pack(side="right")

        search_bar = ttk.Frame(root, padding=(16, 0))
        search_bar.pack(fill="x")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_table())
        ttk.Entry(search_bar, textvariable=self.search_var, font=FONT).pack(side="left", fill="x", expand=True, ipady=3)
        ttk.Label(search_bar, text="search site / username / notes", style="Muted.TLabel").pack(side="left", padx=(8, 0))

        body = ttk.Frame(root, padding=16)
        body.pack(fill="both", expand=True)

        columns = ("site", "username", "created")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", selectmode="browse")
        for col, label, width in [("site", "Site", 220), ("username", "Username", 220), ("created", "Added", 160)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda e: self._view_selected())

        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="left", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        btns = ttk.Frame(root, padding=(16, 0, 16, 16))
        btns.pack(fill="x")
        ttk.Button(btns, text="+ Add Entry", command=self._open_add_dialog).pack(side="left")
        ttk.Button(btns, text="View / Copy", command=self._view_selected).pack(side="left", padx=8)
        ttk.Button(btns, text="Delete", style="Danger.TButton", command=self._delete_selected).pack(side="left")
        ttk.Button(btns, text="Generate Password…", command=self._open_generate_dialog).pack(side="right")

        self._refresh_table()

    def _lock(self):
        self.vault = None
        self.show_lock_screen()

    #  data 
    def _refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        query = self.search_var.get().strip()
        entries = self.vault.search(query) if query else self.vault.list_all()
        for e in entries:
            self.tree.insert("", "end", iid=str(e["id"]), values=(e["site"], e["username"], e["created"]))

    def _selected_id(self):
        sel = self.tree.selection()
        return int(sel[0]) if sel else None

    def _view_selected(self):
        eid = self._selected_id()
        if eid is None:
            messagebox.showinfo("No selection", "Select an entry first.")
            return
        entry = self.vault.get_entry(eid)
        EntryView(self.root, entry)

    def _delete_selected(self):
        eid = self._selected_id()
        if eid is None:
            messagebox.showinfo("No selection", "Select an entry first.")
            return
        entry = self.vault.get_entry(eid)
        if not messagebox.askyesno("Delete entry", f"Delete '{entry['site']}' ({entry['username']})?"):
            return
        self.vault.delete_entry(eid)
        self.vault.save()
        self._refresh_table()

    def _open_add_dialog(self):
        AddEntryDialog(self.root, on_save=self._add_entry)

    def _add_entry(self, site, username, password, notes):
        self.vault.add_entry(site, username, password, notes)
        self.vault.save()
        self._refresh_table()

    def _open_generate_dialog(self):
        length = simpledialog.askinteger(
            "Generate Password", "Length:", initialvalue=20, minvalue=8, maxvalue=128, parent=self.root
        )
        if not length:
            return
        pw = generate_password(length)
        top = tk.Toplevel(self.root, bg=DARK_BG)
        top.title("Generated Password")
        top.geometry("420x120")
        ttk.Label(top, text="Generated password (not saved yet):", style="Muted.TLabel").pack(pady=(16, 6))
        entry = ttk.Entry(top, font=FONT_MONO, justify="center")
        entry.insert(0, pw)
        entry.configure(state="readonly")
        entry.pack(fill="x", padx=20)
        ttk.Button(top, text="Copy to Clipboard", command=lambda: self._copy(pw)).pack(pady=14)

    def _copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo(
            "Copied",
            "Copied to clipboard.\n(Remember: local password managers generally "
            "can't auto-clear your system clipboard — clear it yourself after pasting.)",
        )


class AddEntryDialog(tk.Toplevel):
    def __init__(self, parent, on_save):
        super().__init__(parent, bg=DARK_BG)
        self.title("Add Entry")
        self.geometry("380x360")
        self.on_save = on_save
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        pad = {"padx": 20, "pady": (10, 0)}
        ttk.Label(self, text="Site / service", style="Muted.TLabel").pack(anchor="w", **pad)
        self.site_var = tk.StringVar()
        site_entry = ttk.Entry(self, textvariable=self.site_var, font=FONT)
        site_entry.pack(fill="x", padx=20)

        ttk.Label(self, text="Username / email", style="Muted.TLabel").pack(anchor="w", **pad)
        self.user_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.user_var, font=FONT).pack(fill="x", padx=20)

        ttk.Label(self, text="Password", style="Muted.TLabel").pack(anchor="w", **pad)
        pw_row = ttk.Frame(self)
        pw_row.pack(fill="x", padx=20)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(pw_row, textvariable=self.pw_var, show="•", font=FONT)
        self.pw_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(pw_row, text="Generate", command=self._fill_generated).pack(side="left", padx=(6, 0))

        ttk.Label(self, text="Notes (optional)", style="Muted.TLabel").pack(anchor="w", **pad)
        self.notes_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.notes_var, font=FONT).pack(fill="x", padx=20)

        ttk.Button(self, text="Save Entry", command=self._save).pack(pady=24, padx=20, fill="x")
        site_entry.focus_set()

    def _fill_generated(self):
        self.pw_var.set(generate_password(20))
        self.pw_entry.configure(show="")  # reveal so the user can see what got generated

    def _save(self):
        site, user, pw = self.site_var.get().strip(), self.user_var.get().strip(), self.pw_var.get()
        if not site or not user or not pw:
            messagebox.showwarning("Missing fields", "Site, username, and password are required.", parent=self)
            return
        self.on_save(site, user, pw, self.notes_var.get().strip())
        self.destroy()


class EntryView(tk.Toplevel):
    def __init__(self, parent, entry):
        super().__init__(parent, bg=DARK_BG)
        self.title(entry["site"])
        self.geometry("380x280")
        self.resizable(False, False)
        self.transient(parent)

        rows = [
            ("Site", entry["site"]),
            ("Username", entry["username"]),
            ("Password", entry["password"]),
            ("Notes", entry.get("notes") or "—"),
            ("Added", entry["created"]),
        ]
        for label, value in rows:
            row = ttk.Frame(self)
            row.pack(fill="x", padx=20, pady=(10, 0))
            ttk.Label(row, text=label, style="Muted.TLabel", width=10).pack(side="left")
            ttk.Label(row, text=value, font=FONT_MONO).pack(side="left")

        btn_row = ttk.Frame(self)
        btn_row.pack(pady=20)
        ttk.Button(btn_row, text="Copy Username", command=lambda: self._copy(entry["username"])).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Copy Password", command=lambda: self._copy(entry["password"])).pack(side="left", padx=4)

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)


if __name__ == "__main__":
    app = VaultApp()
    app.run()