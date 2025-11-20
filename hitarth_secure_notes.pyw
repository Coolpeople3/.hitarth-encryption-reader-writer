import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode
import json

# ---------------- MAIN WINDOW ----------------
root = tk.Tk()
root.title("Hitarth Secure Notes")
root.geometry("600x400")
root.configure(bg="black")

# Frame for top buttons
top_frame = tk.Frame(root, bg="black")
top_frame.pack(fill="x")

# Frame for text area
text_frame = tk.Frame(root, bg="black")
text_frame.pack(expand=True, fill="both")

text = tk.Text(text_frame, wrap="word", bg="black", fg="white", insertbackground="white", highlightbackground="orange", highlightthickness=2)
text.pack(expand=True, fill="both")

PLACEHOLDER = "type here"
text.insert("1.0", PLACEHOLDER)
text.config(fg="gray")

# ---------------- FUNCTIONS ----------------
def switch_to_write():
    text.delete("1.0", "end")
    text.insert("1.0", PLACEHOLDER)
    text.config(fg="gray")
    save_button.config(state="normal")

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=1000000)

def encrypt_text(plain_text, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    data = {
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        'ciphertext': b64encode(ciphertext).decode('utf-8')
    }
    return json.dumps(data)

def decrypt_hitarth_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.loads(f.read())
        password = simpledialog.askstring("Password", "Enter password to decrypt:", show='*')
        if not password:
            return None
        salt = b64decode(data['salt'])
        key = derive_key(password, salt)
        nonce = b64decode(data['nonce'])
        tag = b64decode(data['tag'])
        ciphertext = b64decode(data['ciphertext'])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_text.decode('utf-8')
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decode: {e}")
        return None

def switch_to_decode():
    file_path = filedialog.askopenfilename(filetypes=[("Hitarth Files", "*.hitarth")])
    if not file_path:
        return

    decrypted_text = decrypt_hitarth_file(file_path)
    if decrypted_text is not None:
        text.delete("1.0", "end")
        text.insert("1.0", decrypted_text)
        text.config(fg="white")
        save_button.config(state="disabled")

# Placeholder handlers
def on_focus_in(event):
    if text.get("1.0", "end-1c") == PLACEHOLDER:
        text.delete("1.0", "end")
        text.config(fg="white")

def on_focus_out(event):
    if text.get("1.0", "end-1c") == "":
        text.insert("1.0", PLACEHOLDER)
        text.config(fg="gray")

text.bind("<FocusIn>", on_focus_in)
text.bind("<FocusOut>", on_focus_out)

# ---------------- SAVE ----------------
def save_file():
    content = text.get("1.0", "end").rstrip("\n")
    if content == PLACEHOLDER or content.strip() == "":
        messagebox.showinfo("Empty", "Nothing to save.")
        return

    password = simpledialog.askstring("Password", "Enter password to encrypt:", show='*')
    if not password:
        return

    encrypted_text = encrypt_text(content, password)

    path = filedialog.asksaveasfilename(defaultextension=".hitarth",
                                        filetypes=[("Hitarth Files", "*.hitarth")])
    if not path:
        return

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(encrypted_text)
        messagebox.showinfo("Saved", f"Saved to {path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ---------------- BUTTONS ----------------
button_style = {"bg":"black", "fg":"orange", "highlightbackground":"orange", "highlightthickness":2, "activebackground":"black", "activeforeground":"orange"}

save_button = tk.Button(top_frame, text="Save", command=save_file, **button_style)
save_button.pack(side="right", padx=5, pady=5)

write_btn = tk.Button(top_frame, text="Write", command=switch_to_write, **button_style)
write_btn.pack(side="right", padx=5, pady=5)

decode_btn = tk.Button(top_frame, text="Decode", command=switch_to_decode, **button_style)
decode_btn.pack(side="right", padx=5, pady=5)

root.mainloop()