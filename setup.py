import os
import sys
import subprocess
import time
import shutil

# --- COLORS & UI ---
R = '\033[31m'  # Red
G = '\033[32m'  # Green
C = '\033[36m'  # Cyan
Y = '\033[33m'  # Yellow
W = '\033[0m'   # White

def clear_screen():
    os.system('clear')

def banner():
    clear_screen()
    print(f"""{C}
   ______      __              __  ___                           __ 
  / ____/_  __/ /_  ___  _____/  |/  /___  _________ _____  ____/ /___ _
 / /   / / / / __ \/ _ \/ ___/ /|_/ / __ \/ ___/ __ `/ __ \/ __  / __ `/
/ /___/ /_/ / /_/ /  __/ /  / /  / / /_/ / /  / /_/ / / / / /_/ / /_/ / 
\____/\__, /_.___/\___/_/  /_/  /_/\____/_/   \__,_/_/ /_/\__,_/\__,_/  
     /____/  >> DEFENSE SYSTEM INSTALLER <<
    {W}""")

def run_cmd(command, task_name):
    print(f"{Y}[~] {task_name}...{W}", end="\r")
    try:
        # Output ko hide karne ke liye (silent install)
        subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        print(f"{G}[✔] {task_name} - INSTALLED     {W}")
    except subprocess.CalledProcessError:
        print(f"{R}[✘] {task_name} - FAILED (Check Error){W}")

def check_internet():
    print(f"{C}[*] Checking Internet Connection...{W}")
    response = os.system("ping -c 1 google.com > /dev/null 2>&1")
    if response == 0:
        print(f"{G}[✔] Online{W}")
    else:
        print(f"{R}[!] Offline! Internet is required.{W}")
        sys.exit()

# --- INSTALLATION LISTS ---

# 1. System Packages (Termux/Linux)
# Folder structure ke hisaab se dependencies:
# - android_adb_guard -> android-tools (adb)
# - apk_shield -> net-tools
# - moranda_hunter -> clang, make
SYS_PACKAGES = [
    "git",
    "python",
    "clang",
    "make",
    "libxml2",
    "libxslt",
    "android-tools",  # For ADB Guard
    "net-tools",      # For Network Scan
    "openssh"
]

# 2. Python Libraries (Pip)
PIP_PACKAGES = [
    "requests",
    "beautifulsoup4",
    "colorama",
    "rich",           # For Professional Tables/UI
    "tqdm",           # For Progress Bars
    "lxml"
]

def main_install():
    check_internet()
    time.sleep(1)
    
    print(f"\n{C}--- PHASE 1: SYSTEM ENVIRONMENT ---{W}")
    run_cmd("pkg update -y && pkg upgrade -y", "Updating Termux Core")
    
    for pkg in SYS_PACKAGES:
        run_cmd(f"pkg install {pkg} -y", f"Installing System Pkg: {pkg}")

    print(f"\n{C}--- PHASE 2: PYTHON DEPENDENCIES ---{W}")
    run_cmd("pip install --upgrade pip", "Upgrading PIP")
    
    for lib in PIP_PACKAGES:
        run_cmd(f"pip install {lib}", f"Installing Python Lib: {lib}")

    print(f"\n{C}--- PHASE 3: CONFIGURATION ---{W}")
    
    # Create Shortcut Command 'moranda'
    try:
        with open("/data/data/com.termux/files/usr/bin/moranda", "w") as f:
            f.write('#!/bin/bash\ncd $HOME/CyberMoranda-Defence- && python3 moranda_os.py')
        os.system("chmod +x /data/data/com.termux/files/usr/bin/moranda")
        print(f"{G}[✔] Created shortcut command: 'moranda'{W}")
    except:
        print(f"{Y}[!] Could not create shortcut (Permission Error){W}")

    print(f"\n{G}========================================{W}")
    print(f"{G}   INSTALLATION SUCCESSFUL! 🚀{W}")
    print(f"{G}========================================{W}")
    print(f"\nNow you can launch the system by typing:")
    print(f"{C}   moranda{W}")
    print(f"   OR")
    print(f"{C}   python3 moranda_os.py{W}\n")

if __name__ == "__main__":
    banner()
    try:
        main_install()
    except KeyboardInterrupt:
        print(f"\n{R}[!] Installation Cancelled.{W}")
