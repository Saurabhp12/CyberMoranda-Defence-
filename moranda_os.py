#!/usr/bin/env python3
import os
import sys
import time
import random
import subprocess

# --- COLOR CONFIGURATION ---
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    class Colors:
        CYAN = Fore.CYAN; GREEN = Fore.GREEN; YELLOW = Fore.YELLOW
        RED = Fore.RED; BLUE = Fore.BLUE; MAGENTA = Fore.MAGENTA
        BOLD = Style.BRIGHT; RESET = Style.RESET_ALL
except ImportError:
    # Fallback colors if colorama is missing
    class Colors:
        CYAN = "\033[96m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
        RED = "\033[91m"; BLUE = "\033[94m"; MAGENTA = "\033[95m"
        BOLD = "\033[1m"; RESET = "\033[0m"

# --- SYSTEM UTILITIES ---
def clear_screen():
    os.system("clear")

def banner():
    clear_screen()
    print(Colors.CYAN + Colors.BOLD + """
    ==================================================
       CYBER MORANDA DEFENSE OS [v2.50 ULTIMATE]
               System Architect: MORANDA
    ==================================================
    """ + Colors.RESET)
    print(f"    [+] STATUS: {Colors.GREEN}ONLINE{Colors.RESET} | [+] SECURITY: {Colors.GREEN}MAXIMUM{Colors.RESET}")
    print(Colors.CYAN + "    ==================================================" + Colors.RESET)

# --- FEATURE: STEALTH MODE ---
def stealth_mode():
    clear_screen()
    print("\n\n")
    print("    Android System Update")
    print("    Downloading package: com.android.system.upd...")
    print("    [=================>         ] 64%")
    print("\n    Do not turn off your device.")
    try:
        while True:
            time.sleep(10) # Fake freeze screen
    except KeyboardInterrupt:
        return # Ctrl+C se wapas

# --- FEATURE: INTELLIGENCE HUB ---
def view_intelligence():
    clear_screen()
    print(f"\n{Colors.BLUE}{Colors.BOLD}╔══════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}║     CENTRAL INTELLIGENCE HUB (CIH)   ║{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}╚══════════════════════════════════════╝{Colors.RESET}")
    print(f"{Colors.CYAN}[*] AGGREGATING DATA FROM ALL SECTORS...{Colors.RESET}\n")
    time.sleep(1)
    
    # 1. NETWORK (ADB Guard)
    print(f"{Colors.YELLOW}--- [ NETWORK ACTIVITY (ADB Guard) ] ---{Colors.RESET}")
    log_path = "android_adb_guard/adb_guard_logs.txt"
    if os.path.exists(log_path):
        os.system(f"tail -n 3 {log_path}")
    else:
        print(f"{Colors.RED}[!] No Network Logs Found (System Quiet).{Colors.RESET}")

    # 2. SYSTEM INTEGRITY (Sentry)
    print(f"\n{Colors.YELLOW}--- [ FILE SYSTEM ALERTS (Sentry) ] ---{Colors.RESET}")
    sentry_log = "sentry/sentry_log.txt"
    if os.path.exists(sentry_log):
        os.system(f"tail -n 3 {sentry_log}")
    else:
        print(f"{Colors.GREEN}[✔] System Integrity Optimal (No Alerts).{Colors.RESET}")

    # 3. MALWARE (APK Shield)
    print(f"\n{Colors.YELLOW}--- [ LATEST MALWARE SCAN (APK Shield) ] ---{Colors.RESET}")
    if os.path.exists("apk_shield"):
        cmd = "ls -t apk_shield/report_*.txt 2>/dev/null | head -n 1"
        latest_report = os.popen(cmd).read().strip()
        if latest_report:
            print(f"{Colors.GREEN}[+] Latest Report: {os.path.basename(latest_report)}{Colors.RESET}")
            os.system(f"head -n 3 {latest_report}")
        else:
             print(f"{Colors.RED}[!] No Malware Reports Found.{Colors.RESET}")
    else:
        print(f"{Colors.RED}[!] Module Offline.{Colors.RESET}")

    # 4. RECON (Hunter)
    print(f"\n{Colors.YELLOW}--- [ TARGET RECONNAISSANCE (Hunter) ] ---{Colors.RESET}")
    if os.path.exists("moranda_hunter"):
        cmd = "ls -t moranda_hunter/report_*.md 2>/dev/null | head -n 1"
        latest_hunter = os.popen(cmd).read().strip()
        if latest_hunter:
            print(f"{Colors.GREEN}[+] Latest Intel: {os.path.basename(latest_hunter)}{Colors.RESET}")
            # Show CRITICAL findings only
            os.system(f"grep -i 'CRITICAL' {latest_hunter} | head -n 3")
        else:
            print(f"{Colors.RED}[!] No Hunter Data Found.{Colors.RESET}")
    else:
        print(f"{Colors.RED}[!] Module Offline.{Colors.RESET}")

    input(f"\n{Colors.CYAN}Press Enter to return to Command Center...{Colors.RESET}")

# --- MAIN MENU & NAVIGATION ---
def main_menu():
    while True:
        banner()
        print("\n" + Colors.BOLD + "    SELECT OPERATION MODULE:" + Colors.RESET)
        
        print(f"\n    {Colors.BLUE}[ DEFENSE MATRIX ]{Colors.RESET}")
        print(f"    [{Colors.GREEN}1{Colors.RESET}] ADB Guard (Network Monitor)")
        print(f"    [{Colors.GREEN}2{Colors.RESET}] Moranda Sentry (File Monitor)")
        print(f"    [{Colors.GREEN}3{Colors.RESET}] RFC-822 Sentry (Input Validator)")
        
        print(f"\n    {Colors.RED}[ OFFENSIVE LABS ]{Colors.RESET}")
        print(f"    [{Colors.GREEN}4{Colors.RESET}] APK Shield (Analyze Malware)")
        print(f"    [{Colors.GREEN}5{Colors.RESET}] Moranda Hunter (Active Recon)")
        
        print(f"\n    {Colors.MAGENTA}[ INTELLIGENCE ]{Colors.RESET}")
        print(f"    [{Colors.GREEN}6{Colors.RESET}] Intel Hub (View All Logs)")
        
        print(f"\n    {Colors.YELLOW}[ SYSTEM ]{Colors.RESET}")
        print(f"    [{Colors.RED}9{Colors.RESET}] Stealth Mode (Fake Update)")
        print(f"    [{Colors.RED}0{Colors.RESET}] EXIT")
        
        choice = input(f"\n    {Colors.CYAN}moranda@os:~$ {Colors.RESET}")
        
        # --- LOGIC HANDLING ---
        if choice == '1':
            path = "android_adb_guard"
            if os.path.exists(path):
                os.chdir(path)
                # Smart Check for filename
                if os.path.exists("adb_guard_v5.py"):
                    os.system("python3 adb_guard_v5.py")
                elif os.path.exists("adb_guard.py"):
                    os.system("python3 adb_guard.py")
                else:
                    print(f"{Colors.RED}[!] Script missing in {path}{Colors.RESET}")
                    time.sleep(2)
                os.chdir("..")
            else:
                print(f"{Colors.RED}[!] Module Folder '{path}' Missing!{Colors.RESET}")
                time.sleep(1)
            
        elif choice == '2':
            path = "sentry"
            if os.path.exists(path):
                os.chdir(path)
                os.system("python3 moranda_sentry.py")
                os.chdir("..")
            else:
                print(f"{Colors.RED}[!] Module Folder '{path}' Missing!{Colors.RESET}")
                time.sleep(1)
        
        elif choice == '3':
            path = "sentry"
            if os.path.exists(path):
                os.chdir(path)
                os.system("python3 email_sentry.py")
                os.chdir("..")
            else:
                print(f"{Colors.RED}[!] Module Folder '{path}' Missing!{Colors.RESET}")
                time.sleep(1)

        elif choice == '4':
            path = "apk_shield"
            if os.path.exists(path):
                os.chdir(path)
                print(f"\n{Colors.YELLOW}[*] Enter APK Filename (e.g., virus.apk):{Colors.RESET}")
                t = input(f"{Colors.CYAN}>> {Colors.RESET}")
                if t: os.system(f"python3 apk_shield.py {t}")
                os.chdir("..")
            else:
                print(f"{Colors.RED}[!] Module Folder '{path}' Missing!{Colors.RESET}")
                time.sleep(1)

        elif choice == '5':
            path = "moranda_hunter"
            if os.path.exists(path):
                os.chdir(path)
                print(f"\n{Colors.YELLOW}[*] Enter Target URL (e.g., example.com):{Colors.RESET}")
                t = input(f"{Colors.CYAN}>> {Colors.RESET}")
                if t: os.system(f"python3 moranda_hunter.py {t}")
                os.chdir("..")
            else:
                print(f"{Colors.RED}[!] Module Folder '{path}' Missing!{Colors.RESET}")
                time.sleep(1)

        elif choice == '6':
            view_intelligence()

        elif choice == '9':
            stealth_mode()

        elif choice == '0':
            print(f"\n{Colors.RED}[*] SHUTTING DOWN SYSTEMS...{Colors.RESET}")
            sys.exit()

        else:
            print(f"{Colors.RED}[!] Invalid Selection{Colors.RESET}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Force Exit.{Colors.RESET}")
