import os
import sys
import subprocess
import time

# --- COLORS FOR UI ---
R = '\033[31m'  # Red
G = '\033[32m'  # Green
C = '\033[36m'  # Cyan
Y = '\033[33m'  # Yellow
W = '\033[0m'   # White

# --- CONFIGURATION ---
REPO_URL = "https://github.com/Saurabhp12/CyberMoranda-Defence-"
REPO_NAME = "CyberMoranda-Defence-"

# System Packages (Termux/Linux)
SYS_PACKAGES = [
    "git",
    "python",
    "clang",       # For compiling C dependencies
    "make",
    "libxml2",     # For scraping tools
    "libxslt",
    "rust"         # For your Sticky-Trap engine
]

# Python Libraries (Pip)
PIP_PACKAGES = [
    "requests",
    "beautifulsoup4",
    "colorama",
    "lxml",
    "concurrent-log-handler"
]

def banner():
    os.system("clear")
    print(f"""{C}
   ______      __              __  ___                            __ 
  / ____/_  __/ /_  ___  _____/  |/  /___  _________  ____  ____/ /___ _
 / /   / / / / __ \/ _ \/ ___/ /|_/ / __ \/ ___/ __ \/ __ \/ __  / __ `/
/ /___/ /_/ / /_/ /  __/ /  / /  / / /_/ / /  / /_/ / / / / /_/ / /_/ / 
\____/\__, /_.___/\___/_/  /_/  /_/\____/_/   \__,_/_/ /_/\__,_/\__,_/  
     /____/                                                             
    {W}""")
    print(f"{Y}>> AUTOMATED INSTALLER & ENVIRONMENT SETUP <<{W}\n")

def run_cmd(command, task_name):
    """Commands ko run karta hai aur status dikhata hai"""
    print(f"{Y}[~] {task_name}...{W}", end="\r")
    try:
        # Output hide karne ke liye DEVNULL use kar rahe hain, error dikhega
        subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        print(f"{G}[✔] {task_name} - INSTALLED     {W}")
        return True
    except subprocess.CalledProcessError:
        print(f"{R}[✘] {task_name} - FAILED        {W}")
        return False

def install_system():
    print(f"\n{C}[+] PHASE 1: SYSTEM DEPENDENCIES{W}")
    print("-" * 40)
    # Pehle update karein
    run_cmd("pkg update -y && pkg upgrade -y", "Updating Termux Repositories")
    
    for pkg in SYS_PACKAGES:
        run_cmd(f"pkg install {pkg} -y", f"Installing {pkg}")

def install_python_libs():
    print(f"\n{C}[+] PHASE 2: PYTHON MODULES{W}")
    print("-" * 40)
    # Pip upgrade
    run_cmd("pip install --upgrade pip", "Upgrading PIP")
    
    for lib in PIP_PACKAGES:
        run_cmd(f"pip install {lib}", f"Installing Module: {lib}")

def clone_repo():
    print(f"\n{C}[+] PHASE 3: CLONING CORE SYSTEM{W}")
    print("-" * 40)
    
    if os.path.exists(REPO_NAME):
        print(f"{Y}[!] Repository already exists. Pulling updates...{W}")
        os.chdir(REPO_NAME)
        run_cmd("git pull", "Updating CyberMoranda")
        os.chdir("..")
    else:
        run_cmd(f"git clone {REPO_URL}", f"Cloning {REPO_NAME}")

def final_check():
    print(f"\n{G}[+] SETUP COMPLETE!{W}")
    print(f"{C}----------------------------------------{W}")
    print(f"To launch the system, type:")
    print(f"{Y}cd {REPO_NAME}{W}")
    print(f"{Y}python3 moranda_hunter.py{W}")
    print(f"{C}----------------------------------------{W}")

if __name__ == "__main__":
    banner()
    time.sleep(1)
    
    try:
        install_system()
        install_python_libs()
        clone_repo()
        final_check()
    except KeyboardInterrupt:
        print(f"\n{R}[!] Setup Cancelled by User.{W}")
