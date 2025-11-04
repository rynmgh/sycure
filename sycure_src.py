import customtkinter as ctk
from tkinter import messagebox
import json, os, random, string, base64, hashlib
from cryptography.fernet import Fernet

MASTER_FILE = "master.key"
VAULT_FILE = "vault.dat"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Generate Fernet key from master password
def derive_key(password):
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# Random password generator
def generate_password(n=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(n))

# Helper input dialog
def prompt(text, title="Input", default=""):
    d = ctk.CTkInputDialog(text=text, title=title)
    if default and hasattr(d, "_entry"): d._entry.insert(0, default)
    return d.get_input()

# Main app
class SycureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sycure - Secure Password Manager")
        self.root.geometry("720x500")
        self.root.resizable(False, False)

        if not os.path.exists(MASTER_FILE):
            self.create_master()
        else:
            self.verify_master()

    # Master password creation
    def create_master(self):
        p = prompt("Create a master password:", "Setup")
        if not p: self.root.destroy(); return
        q = prompt("Confirm master password:", "Setup")
        if p != q:
            messagebox.showerror("Error", "Passwords don't match.")
            self.root.destroy(); return

        hashed = hashlib.sha256(p.encode()).hexdigest()
        with open(MASTER_FILE, "w") as f:
            f.write(hashed)
        messagebox.showinfo("Setup Complete", "Master password created.")
        self.load_vault(p)
        self.build_ui()

    # Master password verification 
    def verify_master(self):
        entered = prompt("Enter Master Password:", "Login")
        if not entered:
            self.root.destroy(); return
        saved = open(MASTER_FILE).read().strip()
        if hashlib.sha256(entered.encode()).hexdigest() != saved:
            messagebox.showerror("Error", "Incorrect master password!")
            self.root.destroy(); return
        self.load_vault(entered)
        self.build_ui()

    # Vault security, secured by Fernet
    def load_vault(self, master_pwd):
        self.master_pwd = master_pwd
        self.key = derive_key(master_pwd)
        self.fernet = Fernet(self.key)
        self.vault = {}

        if os.path.exists(VAULT_FILE):
            try:
                enc_data = open(VAULT_FILE, "rb").read()
                if enc_data:
                    dec = self.fernet.decrypt(enc_data).decode()
                    self.vault = json.loads(dec)
            except:
                messagebox.showerror("Error", "Failed to decrypt vault.")
                self.root.destroy(); return

    def save_vault(self):
        enc = self.fernet.encrypt(json.dumps(self.vault).encode())
        with open(VAULT_FILE, "wb") as f:
            f.write(enc)

    # gui elements
    def build_ui(self):
        for w in self.root.winfo_children(): w.destroy()

        top = ctk.CTkFrame(self.root)
        top.pack(fill="x", pady=10, padx=10)

        ctk.CTkLabel(top, text="🔐 Sycure Vault", 
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")

        self.search_var = ctk.StringVar()
        self.search_var.trace("w", lambda *a: self.refresh())
        ctk.CTkEntry(top, placeholder_text="Search...", textvariable=self.search_var, width=250).pack(side="right", padx=5)

        self.show_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(top, text="Show Passwords", variable=self.show_var, command=self.refresh).pack(side="right", padx=5)

        self.scroll = ctk.CTkScrollableFrame(self.root, width=650, height=330)
        self.scroll.pack(padx=10, pady=10, fill="both", expand=True)

        btns = ctk.CTkFrame(self.root)
        btns.pack(fill="x", pady=10, padx=10)
        ctk.CTkButton(btns, text="➕ Add", command=self.add).pack(side="left", padx=5)
        ctk.CTkButton(btns, text="🔄 Generate", command=self.generate).pack(side="left", padx=5)
        ctk.CTkButton(btns, text="💾 Save", command=self.save_vault).pack(side="right", padx=5)
        ctk.CTkButton(btns, text="🚪 Exit", command=self.exit).pack(side="right", padx=5)

        self.refresh()

    # Vault features
    def refresh(self):
        for w in self.scroll.winfo_children(): w.destroy()
        q = self.search_var.get().lower()
        if not self.vault:
            ctk.CTkLabel(self.scroll, text="No entries yet. Click 'Add' to start.", text_color="gray").pack(pady=40)
            return

        for site, cred in sorted(self.vault.items()):
            if q and q not in site.lower(): continue
            f = ctk.CTkFrame(self.scroll); f.pack(fill="x", padx=6, pady=4)
            ctk.CTkLabel(f, text=f"🌐 {site}", font=ctk.CTkFont(weight="bold")).pack(anchor="w")
            ctk.CTkLabel(f, text=f"👤 {cred['username']}", text_color="gray").pack(anchor="w")
            pwd = cred["password"] if self.show_var.get() else "••••••••"
            ctk.CTkLabel(f, text=f"🔑 {pwd}", text_color="gray").pack(anchor="w")
            bf = ctk.CTkFrame(f, fg_color="transparent"); bf.pack(anchor="e", pady=2)
            ctk.CTkButton(bf, text="📋", width=36, command=lambda s=site: self.copy(s)).pack(side="left", padx=2)
            ctk.CTkButton(bf, text="✏️", width=36, command=lambda s=site: self.edit(s)).pack(side="left", padx=2)
            ctk.CTkButton(bf, text="🗑", width=36, command=lambda s=site: self.delete(s)).pack(side="left", padx=2)

    def add(self):
        s = prompt("Website:", "Add Entry")
        if not s: return
        u = prompt("Username:", "Add Entry")
        if u is None: return
        p = prompt("Password (leave blank to generate):", "Add Entry")
        if not p: p = generate_password()
        self.vault[s] = {"username": u, "password": p}
        self.save_vault(); self.refresh(); messagebox.showinfo("Saved", f"{s} added!")

    def edit(self, site):
        c = self.vault[site]
        u = prompt("Username:", "Edit", c["username"])
        if u is None: return
        p = prompt("Password:", "Edit", c["password"])
        if p is None: return
        self.vault[site] = {"username": u, "password": p}
        self.save_vault(); self.refresh()

    def delete(self, site):
        if messagebox.askyesno("Confirm", f"Delete {site}?"):
            self.vault.pop(site, None); self.save_vault(); self.refresh()

    def copy(self, site):
        p = self.vault[site]["password"]
        self.root.clipboard_clear(); self.root.clipboard_append(p)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def generate(self):
        n = prompt("Password length (6–50):", "Generate", "12")
        try: n = int(n)
        except: messagebox.showerror("Error", "Invalid number"); return
        p = generate_password(max(6, min(50, n)))
        if messagebox.askyesno("Generated", f"{p}\n\nCopy to clipboard?"):
            self.root.clipboard_clear(); self.root.clipboard_append(p)

    def exit(self):
        self.save_vault(); messagebox.showinfo("Saved", "Vault saved securely."); self.root.destroy()

if __name__ == "__main__":
    root = ctk.CTk()
    SycureApp(root)
    root.mainloop()
