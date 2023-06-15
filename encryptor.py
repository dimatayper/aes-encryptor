import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import os

KEY_SIZE = 16  # 128 bit
BLOCK_SIZE = 16  # AES block size
MODE = AES.MODE_CBC  # Mode of operation

def encrypt_text():
    try:
        key = key_entry.get().encode()
        assert len(key) == KEY_SIZE, "Key must be 16 bytes"
        text = text_entry.get('1.0', 'end').rstrip().encode()
        cipher = AES.new(key, MODE)
        ct_bytes = cipher.encrypt(pad(text, BLOCK_SIZE))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        encrypted_text.delete('1.0', 'end')
        encrypted_text.insert('end', iv + ct)
    except (AssertionError, ValueError) as e:
        messagebox.showerror("Error", str(e))

def decrypt_text():
    try:
        key = key_entry.get().encode()
        assert len(key) == KEY_SIZE, "Key must be 16 bytes"
        encrypted_text_input = encrypted_text.get('1.0', 'end').rstrip()
        iv = b64decode(encrypted_text_input[:24])
        ct = b64decode(encrypted_text_input[24:])
        cipher = AES.new(key, MODE, iv=iv)
        decrypted_text = unpad(cipher.decrypt(ct), BLOCK_SIZE).decode('utf-8')
        encrypted_text.delete('1.0', 'end')
        encrypted_text.insert('end', decrypted_text)
    except (AssertionError, ValueError) as e:
        messagebox.showerror("Error", "Invalid key or encrypted message")


def encrypt_file():
    try:
        file_path = filedialog.askopenfilename()
        key = key_entry.get().encode()
        assert len(key) == KEY_SIZE, "Key must be 16 bytes"
        with open(file_path, 'rb') as f:
            text = f.read()
        cipher = AES.new(key, MODE)
        ct_bytes = cipher.encrypt(pad(text, BLOCK_SIZE))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        with open(file_path + ".enc", 'w') as f:
            f.write(iv + ct)
    except (AssertionError, ValueError) as e:
        messagebox.showerror("Error", "Invalid key or encrypted message")

def decrypt_file():
    try:
        file_path = filedialog.askopenfilename()
        key = key_entry.get().encode()
        assert len(key) == KEY_SIZE, "Key must be 16 bytes"
        with open(file_path, 'r') as f:
            encrypted_text = f.read().rstrip()
        iv = b64decode(encrypted_text[:24])
        ct = b64decode(encrypted_text[24:])
        cipher = AES.new(key, MODE, iv=iv)
        decrypted_text = unpad(cipher.decrypt(ct), BLOCK_SIZE)
        with open(file_path.replace('.enc', ''), 'wb') as f:
            f.write(decrypted_text)
    except (AssertionError, ValueError) as e:
        messagebox.showerror("Error", "Invalid key or encrypted message")


root = tk.Tk()

key_label = tk.Label(root, text="Key")
key_label.pack()

key_entry = tk.Entry(root)
key_entry.pack()

text_label = tk.Label(root, text="Text to Encrypt/Decrypt")
text_label.pack()

text_entry = tk.Text(root)
text_entry.pack()

encrypt_button = tk.Button(root, text="Encrypt Text", command=encrypt_text)
encrypt_button.pack()

decrypt_button = tk.Button(root, text="Decrypt Text", command=decrypt_text)
decrypt_button.pack()

encrypted_text_label = tk.Label(root, text="Encrypted/Decrypted Text")
encrypted_text_label.pack()

encrypted_text = tk.Text(root)
encrypted_text.pack()

encrypt_file_button = tk.Button(root, text="Encrypt File", command=encrypt_file)
encrypt_file_button.pack()

decrypt_file_button = tk.Button(root, text="Decrypt File", command=decrypt_file)
decrypt_file_button.pack()


root.mainloop()
