#!/usr/bin/env python3
# CyberMoranda Sentry - Manual Control Edition

import os
import hashlib
import json
import time
import sys
import shutil
from datetime import datetime

# --- COLORS ---
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    G = Fore.GREEN
    R = Fore.RED
    Y = Fore.YELLOW
    C = Fore.CYAN
    W = Style.RESET_ALL
except:
    G = R = Y = C = W = ""

DATABASE_FILE = "sentry_baseline.json"
BACKUP_DIR = ".cm_vault"

def clear():
    os.system("clear")

def banner():
    clear()
    print(f"""{C}
     ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
     ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
     ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
     ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
     ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
    {Y}CYBER MORANDA SENTRY | MANUAL DEFENSE SYSTEM{W}
    """)

def calculate_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return None

def secure_backup(filepath, rel_path):
    dest_path = os.path.join(BACKUP_DIR, rel_path)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    try:
        shutil.copy2(filepath, dest_path)
        return True
    except:
        return False

def restore_file(rel_path, target_dir):
    backup_path = os.path.join(BACKUP_DIR, rel_path)
    original_path = os.path.join(target_dir, rel_path)
    
    if os.path.exists(backup_path):
        try:
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.copy2(backup_path, original_path)
            print(f"    {G}[✔] RESTORED: {rel_path} recovered from Vault.{W}")
            return True
        except Exception as e:
            print(f"    {R}[✘] FAILED: Could not restore ({e}){W}")
    else:
        print(f"    {R}[!] ERROR: No backup found in Vault.{W}")
    return False

def scan_directory(directory, backup_mode=False):
    file_hashes = {}
    print(f"{C}[*] Scanning: {directory}...{W}")
    
    if backup_mode and os.path.exists(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)
    
    file_count = 0
    for root, dirs, files in os.walk(directory):
        if "/." in root: continue
        
        for file in files:
            if file == DATABASE_FILE or file.endswith(".pyc"): continue
            
            filepath = os.path.join(root, file)
            file_hash = calculate_hash(filepath)
            
            if file_hash:
                rel_path = os.path.relpath(filepath, directory)
                file_hashes[rel_path] = file_hash
                if backup_mode: secure_backup(filepath, rel_path)
                file_count += 1
                sys.stdout.write(f"\r{Y}[Processing] {file_count} files secured...{W}")
                sys.stdout.flush()
                
    print(f"\n{G}[✔] Scan Complete. {file_count} files processed.{W}\n")
    return file_hashes

def create_baseline():
    target_dir = input(f"{C}Enter directory to protect (default: current): {W}")
    if not target_dir: target_dir = "."
    
    hashes = scan_directory(target_dir, backup_mode=True)
    
    data = {
        "timestamp": str(datetime.now()),
        "directory": os.path.abspath(target_dir),
        "files": hashes
    }
    
    with open(DATABASE_FILE, "w") as f:
        json.dump(data, f, indent=4)
        
    print(f"{G}[SUCCESS] Baseline & Secure Backup Created.{W}")
    input(f"\n{Y}[Press Enter]{W}")

def monitor_integrity():
    if not os.path.exists(DATABASE_FILE):
        print(f"{R}[!] No baseline found. Run Option 1 first.{W}"); time.sleep(2); return

    with open(DATABASE_FILE, "r") as f:
        baseline_data = json.load(f)
        
    baseline_hashes = baseline_data["files"]
    target_dir = baseline_data["directory"]
    
    print(f"{Y}[*] Comparing against Backup: {baseline_data['timestamp']}{W}")
    current_hashes = scan_directory(target_dir, backup_mode=False)
    
    modified = []
    removed = []
    added = []
    
    # Check Modified & Removed
    for filepath, original_hash in baseline_hashes.items():
        if filepath not in current_hashes:
            removed.append(filepath)
        elif current_hashes[filepath] != original_hash:
            modified.append(filepath)

    # Check Added
    for filepath in current_hashes:
        if filepath not in baseline_hashes:
            added.append(filepath)

    if not modified and not removed and not added:
        print(f"{G}[✅] SYSTEM INTEGRITY VERIFIED.{W}")
    else:
        print(f"{R}[⚠️] ALERTS DETECTED:{W}")
        for f in modified: print(f"  {Y}[MODIFIED] {f}{W}")
        for f in removed:  print(f"  {R}[DELETED]  {f}{W}")
        for f in added:    print(f"  {C}[NEW FILE]  {f} (Is this yours?){W}")
        
        # --- MANUAL RESTORE PROMPT ---
        if modified or removed:
            print(f"\n{C}[?] Do you want to RESTORE modified/deleted files from Vault?{W}")
            ask = input(f"{C}(y/n): {W}")
            
            if ask.lower() == 'y':
                print(f"\n{Y}[*] Restoring files...{W}")
                for f in modified: restore_file(f, target_dir)
                for f in removed:  restore_file(f, target_dir)
                print(f"{G}[✔] Restoration Complete.{W}")
            else:
                print(f"{R}[!] No action taken. Files remain changed.{W}")
        else:
            print(f"\n{Y}[*] Note: New files cannot be 'restored' (they didn't exist before).{W}")
            print(f"{Y}    If they are malicious, delete them manually.{W}")
        
    input(f"\n{Y}[Press Enter]{W}")

def menu():
    while True:
        banner()
        print(f"{G}[1]{W} 🛡️  Create/Update Baseline (Fingerprint + Backup)")
        print(f"{G}[2]{W} 🔍  Run Integrity Scan (Detect + Option to Restore)")
        print(f"{R}[0]{W} 🚪  Exit")
        
        choice = input(f"\nsentry@moranda:~$ ")
        if choice == '1': create_baseline()
        elif choice == '2': monitor_integrity()
        elif choice == '0': break

if __name__ == "__main__":
    try: menu()
    except: sys.exit()
