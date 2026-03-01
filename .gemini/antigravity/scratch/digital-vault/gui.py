import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from key_manager import generate_salt, derive_key, save_salt, load_salt
from vault_crypto import encrypt_file, decrypt_file



# ── Constants ──────────────────────────────────────────────────────
VAULT_EXT = ".vault"
SALT_EXT = ".salt"

# ── Dark-theme colour palette ─────────────────────────────────────
BG_DARK = "#1e1e2e"
BG_SURFACE = "#2a2a3c"
BG_INPUT = "#33334d"
FG_TEXT = "#e0e0f0"
FG_DIM = "#8888aa"
ACCENT = "#7c6ff7"
ACCENT_HOVER = "#9b8cff"
SUCCESS = "#50e898"
ERROR = "#ff5a7a"
WARNING = "#ffc857"


class DigitalVaultGUI:
    """Main application window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("🔐 Digital Vault")
        self.root.geometry("620x520")
        self.root.minsize(560, 480)
        self.root.configure(bg=BG_DARK)
        self.root.resizable(True, True)

        # ── ttk style ────────────────────────────────────────────
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure(".", background=BG_DARK, foreground=FG_TEXT,
                             fieldbackground=BG_INPUT, borderwidth=0)
        self.style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=BG_SURFACE,
                             foreground=FG_DIM, padding=[18, 8],
                             font=("Segoe UI", 11, "bold"))
        self.style.map("TNotebook.Tab",
                       background=[("selected", ACCENT)],
                       foreground=[("selected", "#ffffff")])
        self.style.configure("TFrame", background=BG_DARK)
        self.style.configure("TLabel", background=BG_DARK, foreground=FG_TEXT,
                             font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 13, "bold"),
                             foreground=ACCENT)
        self.style.configure("Status.TLabel", font=("Segoe UI", 10),
                             foreground=FG_DIM)
        self.style.configure("TButton", background=BG_SURFACE,
                             foreground=FG_TEXT, font=("Segoe UI", 10),
                             padding=[12, 6])
        self.style.map("TButton",
                       background=[("active", BG_INPUT)])
        self.style.configure("Accent.TButton", background=ACCENT,
                             foreground="#ffffff", font=("Segoe UI", 11, "bold"),
                             padding=[20, 10])
        self.style.map("Accent.TButton",
                       background=[("active", ACCENT_HOVER)])
        self.style.configure("TEntry", fieldbackground=BG_INPUT,
                             foreground=FG_TEXT, insertcolor=FG_TEXT,
                             padding=[8, 6])

        # ── Header ───────────────────────────────────────────────
        header = ttk.Frame(root, padding=(20, 16, 20, 4))
        header.pack(fill="x")
        ttk.Label(header, text="🔐  Digital Vault",
                  font=("Segoe UI", 18, "bold"),
                  foreground="#ffffff").pack(side="left")
        ttk.Label(header, text="AES-256-GCM  •  PBKDF2",
                  foreground=FG_DIM,
                  font=("Segoe UI", 9)).pack(side="right", pady=(6, 0))

        # ── Notebook (tabs) ──────────────────────────────────────
        self.notebook = ttk.Notebook(root, padding=10)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=(4, 14))

        self._build_encrypt_tab()
        self._build_decrypt_tab()

    # ── Encrypt tab ──────────────────────────────────────────────
    def _build_encrypt_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(tab, text="  🔒  Encrypt  ")

        # File selection
        ttk.Label(tab, text="Select a file to encrypt",
                  style="Header.TLabel").pack(anchor="w")
        file_frame = ttk.Frame(tab)
        file_frame.pack(fill="x", pady=(8, 16))

        self.enc_file_var = tk.StringVar()
        enc_entry = ttk.Entry(file_frame, textvariable=self.enc_file_var,
                              state="readonly")
        enc_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(file_frame, text="Browse …",
                   command=self._browse_encrypt).pack(side="right")

        # Password
        ttk.Label(tab, text="Password", foreground=FG_DIM).pack(anchor="w")
        pw_frame = ttk.Frame(tab)
        pw_frame.pack(fill="x", pady=(4, 8))
        self.enc_pw_var = tk.StringVar()
        self.enc_pw_entry = ttk.Entry(pw_frame, textvariable=self.enc_pw_var,
                                      show="•")
        self.enc_pw_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._eye_btn(pw_frame, self.enc_pw_entry)

        # Confirm password
        ttk.Label(tab, text="Confirm Password", foreground=FG_DIM).pack(anchor="w")
        cpw_frame = ttk.Frame(tab)
        cpw_frame.pack(fill="x", pady=(4, 16))
        self.enc_cpw_var = tk.StringVar()
        self.enc_cpw_entry = ttk.Entry(cpw_frame, textvariable=self.enc_cpw_var,
                                       show="•")
        self.enc_cpw_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._eye_btn(cpw_frame, self.enc_cpw_entry)

        # Action button
        self.enc_btn = ttk.Button(tab, text="🔒  Encrypt File",
                                  style="Accent.TButton",
                                  command=self._do_encrypt)
        self.enc_btn.pack(pady=(4, 12))

        # Status
        self.enc_status = ttk.Label(tab, text="", style="Status.TLabel")
        self.enc_status.pack()

    # ── Decrypt tab ──────────────────────────────────────────────
    def _build_decrypt_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(tab, text="  🔓  Decrypt  ")

        # File selection
        ttk.Label(tab, text="Select a .vault file to decrypt",
                  style="Header.TLabel").pack(anchor="w")
        file_frame = ttk.Frame(tab)
        file_frame.pack(fill="x", pady=(8, 16))

        self.dec_file_var = tk.StringVar()
        dec_entry = ttk.Entry(file_frame, textvariable=self.dec_file_var,
                              state="readonly")
        dec_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(file_frame, text="Browse …",
                   command=self._browse_decrypt).pack(side="right")

        # Password
        ttk.Label(tab, text="Password", foreground=FG_DIM).pack(anchor="w")
        pw_frame = ttk.Frame(tab)
        pw_frame.pack(fill="x", pady=(4, 16))
        self.dec_pw_var = tk.StringVar()
        self.dec_pw_entry = ttk.Entry(pw_frame, textvariable=self.dec_pw_var,
                                      show="•")
        self.dec_pw_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._eye_btn(pw_frame, self.dec_pw_entry)

        # Action button
        self.dec_btn = ttk.Button(tab, text="🔓  Decrypt File",
                                  style="Accent.TButton",
                                  command=self._do_decrypt)
        self.dec_btn.pack(pady=(4, 12))

        # Status
        self.dec_status = ttk.Label(tab, text="", style="Status.TLabel")
        self.dec_status.pack()

    # ── Helpers ──────────────────────────────────────────────────
    def _eye_btn(self, parent: ttk.Frame, entry: ttk.Entry) -> None:
        """Add a show/hide password toggle button."""
        shown = tk.BooleanVar(value=False)

        def toggle():
            if shown.get():
                entry.configure(show="•")
                btn.configure(text="👁")
                shown.set(False)
            else:
                entry.configure(show="")
                btn.configure(text="🙈")
                shown.set(True)

        btn = ttk.Button(parent, text="👁", width=3, command=toggle)
        btn.pack(side="right")

    def _browse_encrypt(self) -> None:
        path = filedialog.askopenfilename(title="Choose a file to encrypt")
        if path:
            self.enc_file_var.set(path)

    def _browse_decrypt(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose a .vault file to decrypt",
            filetypes=[("Vault files", "*.vault"), ("All files", "*.*")],
        )
        if path:
            self.dec_file_var.set(path)

    def _set_status(self, label: ttk.Label, text: str,
                    color: str = FG_DIM) -> None:
        """Update a status label (thread-safe via root.after)."""
        self.root.after(0, lambda: label.configure(text=text, foreground=color))

    def _set_busy(self, busy: bool) -> None:
        """Enable / disable action buttons while working."""
        state = "disabled" if busy else "!disabled"
        self.root.after(0, lambda: self.enc_btn.state([state]))
        self.root.after(0, lambda: self.dec_btn.state([state]))

    # ── Encrypt logic ────────────────────────────────────────────
    def _do_encrypt(self) -> None:
        file_path = self.enc_file_var.get().strip()
        password = self.enc_pw_var.get()
        confirm = self.enc_cpw_var.get()

        if not file_path:
            self._set_status(self.enc_status, "✗  Please select a file.", ERROR)
            return
        if not os.path.isfile(file_path):
            self._set_status(self.enc_status, "✗  File not found.", ERROR)
            return
        if not password:
            self._set_status(self.enc_status, "✗  Password cannot be empty.", ERROR)
            return
        if password != confirm:
            self._set_status(self.enc_status, "✗  Passwords do not match.", ERROR)
            return

        vault_path = file_path + VAULT_EXT
        salt_path = file_path + SALT_EXT

        if os.path.exists(vault_path):
            self._set_status(self.enc_status,
                             "✗  Vault file already exists — delete it first.",
                             ERROR)
            return

        self._set_busy(True)
        self._set_status(self.enc_status, "⏳  Deriving key (this may take a moment)…",
                         WARNING)

        def work():
            try:
                salt = generate_salt()
                save_salt(salt, salt_path)
                key = derive_key(password, salt)
                encrypt_file(file_path, vault_path, key)

                size = os.path.getsize(vault_path)
                self._set_status(
                    self.enc_status,
                    f"✓  Encrypted!  →  {os.path.basename(vault_path)} ({size:,} bytes)",
                    SUCCESS,
                )
            except Exception as exc:
                self._set_status(self.enc_status, f"✗  {exc}", ERROR)
            finally:
                self._set_busy(False)

        threading.Thread(target=work, daemon=True).start()

    # ── Decrypt logic ────────────────────────────────────────────
    def _do_decrypt(self) -> None:
        file_path = self.dec_file_var.get().strip()
        password = self.dec_pw_var.get()

        if not file_path:
            self._set_status(self.dec_status, "✗  Please select a file.", ERROR)
            return
        if not os.path.isfile(file_path):
            self._set_status(self.dec_status, "✗  File not found.", ERROR)
            return
        if not file_path.endswith(VAULT_EXT):
            self._set_status(self.dec_status,
                             "✗  Please select a .vault file.", ERROR)
            return
        if not password:
            self._set_status(self.dec_status, "✗  Password cannot be empty.", ERROR)
            return

        base_path = file_path[: -len(VAULT_EXT)]
        salt_path = base_path + SALT_EXT
        output_path = base_path + ".decrypted"

        if not os.path.isfile(salt_path):
            self._set_status(self.dec_status,
                             "✗  Salt file not found next to the vault file.",
                             ERROR)
            return

        self._set_busy(True)
        self._set_status(self.dec_status, "⏳  Deriving key (this may take a moment)…",
                         WARNING)

        def work():
            try:
                salt = load_salt(salt_path)
                key = derive_key(password, salt)
                decrypt_file(file_path, output_path, key)

                size = os.path.getsize(output_path)
                self._set_status(
                    self.dec_status,
                    f"✓  Decrypted!  →  {os.path.basename(output_path)} ({size:,} bytes)",
                    SUCCESS,
                )
            except ValueError as exc:
                self._set_status(self.dec_status, f"✗  {exc}", ERROR)
            except Exception as exc:
                self._set_status(self.dec_status, f"✗  {exc}", ERROR)
            finally:
                self._set_busy(False)

        threading.Thread(target=work, daemon=True).start()


# ── Launch ───────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    DigitalVaultGUI(root)
    root.mainloop()
