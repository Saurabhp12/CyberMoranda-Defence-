#!/usr/bin/env python3
# apk_shield.py — CyberMoranda APK Shield v7.0 (Cloud Uplink)
# The Ultimate Android Forensics & Red Team Suite
# Features: VirusTotal Scan, C2 Hunter, AI Analysis, JSON Export

import os
import re
import sys
import zipfile
import hashlib
import subprocess
import argparse
import time
import datetime
import html
import sqlite3
import shutil
import json
import urllib.request
import urllib.parse

# --- CONFIGURATION ---
# API Key ab external file se load hogi (Secure)
def load_api_key():
    key_file = "vt_key.txt"
    if os.path.exists(key_file):
        try:
            with open(key_file, "r") as f:
                return f.read().strip()
        except: pass
    return ""

VT_API_KEY = load_api_key()

# --- CYBER UI ENGINE ---
class UI:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'
    
    @staticmethod
    def banner():
        os.system('clear')
        print(f"{UI.CYAN}")
        print(r"""
   ██████╗██╗   ██╗██████╗ ███████╗██████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
        """)
        print(f"{UI.YELLOW}   CYBERMORANDA APK SHIELD v7.0 {UI.RESET}| {UI.BLUE}CLOUD UPLINK{UI.RESET}")
        print(f"   {UI.GRAY}>> Connecting to Global Threat Grid...{UI.RESET}\n")

    @staticmethod
    def print_box(title, text, color=CYAN):
        width = 60
        print(f"{color}┌─[{title}]" + "─" * (width - len(title) - 4) + "┐")
        for line in text.split('\n'):
            print(f"│ {line:<{width-3}}│")
        print(f"└" + "─" * (width - 2) + "┘" + UI.RESET)

    @staticmethod
    def progress_bar(task, duration=1.0):
        width = 40
        print(f"{UI.CYAN}[*] {task}{UI.RESET}")
        for i in range(width + 1):
            time.sleep(duration / width)
            bar = "█" * i + "-" * (width - i)
            percent = int((i / width) * 100)
            sys.stdout.write(f"\r{UI.GREEN}[{bar}] {percent}%{UI.RESET}")
            sys.stdout.flush()
        print("\n")

    @staticmethod
    def table_row(col1, col2, color=RESET):
        print(f"{color}│ {col1:<35} │ {col2:<18} │{UI.RESET}")

    @staticmethod
    def table_header(col1, col2):
        print(f"{UI.CYAN}┌─────────────────────────────────────┬────────────────────┐")
        print(f"│ {col1:<35} │ {col2:<18} │")
        print(f"├─────────────────────────────────────┼────────────────────┤{UI.RESET}")

    @staticmethod
    def table_footer():
        print(f"{UI.CYAN}└─────────────────────────────────────┴────────────────────┘{UI.RESET}")

# --- TRACKER DATABASE ---
TRACKER_SIGNATURES = {
    "Google AdMob": "com.google.android.gms.ads",
    "Facebook SDK": "com.facebook.ads",
    "Unity Ads": "com.unity3d.ads",
    "Adjust Analysis": "com.adjust.sdk",
    "AppsFlyer": "com.appsflyer",
    "Firebase Analytics": "com.google.firebase.analytics",
    "Mixpanel": "com.mixpanel",
    "OneSignal": "com.onesignal"
}

# --- DATABASE ENGINE ---
DB_FILE = "shield_memory.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  apk_name TEXT,
                  sha256 TEXT,
                  score INTEGER,
                  verdict TEXT,
                  scan_date TEXT)''')
    conn.commit()
    conn.close()

def save_scan_to_db(apk_name, sha256, score, verdict):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO history (apk_name, sha256, score, verdict, scan_date) VALUES (?, ?, ?, ?, ?)",
              (apk_name, sha256, score, verdict, date_str))
    conn.commit()
    conn.close()

def show_history():
    if not os.path.exists(DB_FILE):
        print(f"{UI.RED}[!] No history found.{UI.RESET}")
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM history ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    conn.close()
    
    UI.banner()
    print(f"{UI.YELLOW}SCAN HISTORY LOG:{UI.RESET}")
    print(f"{UI.CYAN}ID   DATE                 VERDICT         APK NAME{UI.RESET}")
    print("-" * 60)
    for row in rows:
        r_id, r_name, r_sha, r_score, r_verdict, r_date = row
        color = UI.GREEN if r_score < 20 else (UI.YELLOW if r_score < 50 else UI.RED)
        print(f"{str(r_id):<4} {r_date:<20} {color}{r_verdict:<15}{UI.RESET} {r_name}")
    print("-" * 60)

# --- CORE LOGIC ---
def calc_hashes(path):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk: break
            sha256.update(chunk)
            md5.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

def extract_strings_ordered(path):
    strings = []
    try:
        with zipfile.ZipFile(path, "r") as z:
            for name in z.namelist():
                if name.endswith((".dex", ".xml", ".arsc")):
                    try:
                        data = z.read(name)
                        current_str = []
                        for b in data:
                            if 32 <= b <= 126:
                                current_str.append(chr(b))
                            else:
                                if len(current_str) >= 4:
                                    s = "".join(current_str)
                                    strings.append(s)
                                    current_str = []
                    except: continue
    except: pass
    return strings

def analyze_certificate(path):
    cert_status = "Unknown / Unverified"
    try:
        with zipfile.ZipFile(path, "r") as z:
            for name in z.namelist():
                if name.startswith("META-INF/") and (name.endswith(".RSA") or name.endswith(".DSA")):
                    data = z.read(name)
                    try:
                        content = data.decode('utf-8', errors='ignore')
                        if "Android Debug" in content: cert_status = "DEBUG KEY (Modded)"
                        elif "Google" in content or "Android" in content: cert_status = "Verified Entity"
                        else: cert_status = "Self-Signed / Custom"
                    except: cert_status = "Binary Signed"
                    break
    except: pass
    return cert_status

def get_precise_info(apk_path):
    info = { "package": "Unknown", "label": "Unknown", "version": "Unknown", "launchable": None }
    if not shutil.which("aapt"): return info
    try:
        result = subprocess.check_output(["aapt", "dump", "badging", apk_path], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
        pkg_match = re.search(r"package: name='([^']+)'", result)
        if pkg_match: info["package"] = pkg_match.group(1)
        lbl_match = re.search(r"application-label:'([^']+)'", result)
        if lbl_match: info["label"] = lbl_match.group(1)
        ver_match = re.search(r"versionName='([^']+)'", result)
        if ver_match: info["version"] = ver_match.group(1)
        act_match = re.search(r"launchable-activity: name='([^']+)'", result)
        if act_match: info["launchable"] = act_match.group(1)
    except: pass
    return info

def scan_components(apk_path):
    components = { "boot_receiver": False, "sms_receiver": False, "admin_receiver": False, "overlay_service": False }
    if not shutil.which("aapt"): return components
    try:
        result = subprocess.check_output(["aapt", "dump", "xmltree", apk_path, "AndroidManifest.xml"], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
        if "android.intent.action.BOOT_COMPLETED" in result: components["boot_receiver"] = True
        if "android.provider.Telephony.SMS_RECEIVED" in result: components["sms_receiver"] = True
        if "android.app.action.DEVICE_ADMIN_ENABLED" in result: components["admin_receiver"] = True
        if "SYSTEM_ALERT_WINDOW" in result: components["overlay_service"] = True
    except: pass
    return components

def extract_c2_infrastructure(strings):
    c2_data = {"ips": [], "urls": []}
    ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ignore_ips = ["127.0.0.1", "0.0.0.0", "255.255.255.255"]
    for s in strings:
        ips = ip_regex.findall(s)
        for ip in ips:
            if ip not in ignore_ips and not ip.startswith("192.168.") and ip not in c2_data["ips"]:
                c2_data["ips"].append(ip)
    return c2_data

# --- v7.0: VIRUSTOTAL INTEGRATION ---
def check_virustotal(sha256_hash):
    if not VT_API_KEY:
        return None
    
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            total = sum(stats.values())
            return {"malicious": malicious, "total": total}
    except urllib.error.HTTPError as e:
        if e.code == 404: return {"malicious": 0, "total": 0, "status": "Not Found"}
        elif e.code == 401: return {"error": "Invalid API Key"}
        return None
    except:
        return None

# --- AI & REPORTING ---
def generate_ai_summary(score, components, trackers, secrets, permissions, is_malware_confirmed, c2_data, vt_stats):
    summary = "System Scan Initialized... Analysis Complete.\n\n"
    
    # 1. Global Threat Intel (VirusTotal)
    if vt_stats and vt_stats.get("malicious", 0) > 0:
        summary += f"[GLOBAL ALERT]: Confirmed malicious by {vt_stats['malicious']} security vendors on VirusTotal.\n"
        is_malware_confirmed = True # Upgrade threat level based on Cloud Intel

    if is_malware_confirmed:
        summary += "[CRITICAL]: Known malware signatures detected. This is a confirmed threat.\n"
    elif score >= 50:
        summary += "[ADWARE / HIGH RISK]: Aggressive commercial behaviors detected. Likely a free app with heavy tracking or a cracked game.\n"
    else:
        summary += "[SAFE]: Application behavior is within normal commercial limits.\n"

    summary += "\n> BEHAVIORAL INDICATORS:\n"
    if c2_data["ips"]: summary += f"- C2 INFRASTRUCTURE: Detected {len(c2_data['ips'])} raw IP addresses indicating Command & Control servers.\n"
    if components['boot_receiver']: summary += f"- PERSISTENCE: {'Malware' if is_malware_confirmed else 'App'} auto-starts at boot.\n"
    if trackers: summary += f"- ANALYTICS: {len(trackers)} tracking libraries found (AdMob/Facebook).\n"
    if secrets: summary += "- SECURITY FLAW: Developer API keys found.\n"
        
    summary += "\n> RECOMMENDATION:\n"
    if is_malware_confirmed or (vt_stats and vt_stats.get("malicious", 0) > 3):
        summary += "UNINSTALL IMMEDIATELY. Confirmed malicious activity."
    elif score > 50:
        summary += "Use with caution. Use the generated Firewall blocklist."
    else:
        summary += "Safe to use."
    return summary

def generate_firewall_rules(apk_name, urls, trackers, c2_ips):
    if not urls and not trackers and not c2_ips: return None
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"/sdcard/Download/Blocklist_{apk_name}_{timestamp}.txt"
    content = f"# CyberMoranda Blocklist\n"
    for ip in c2_ips: content += f"127.0.0.1 {ip}\n"
    domains = set()
    for u in urls:
        match = re.search(r"https?://([^/]+)", u)
        if match: domains.add(match.group(1))
    for d in domains: content += f"127.0.0.1 {d}\n"
    tracker_domains = {"Google AdMob": "googleadservices.com", "Facebook SDK": "graph.facebook.com", "Unity Ads": "unityads.unity3d.com"}
    for t in trackers:
        if t in tracker_domains: content += f"127.0.0.1 {tracker_domains[t]}\n"
    try:
        with open(filename, "w") as f: f.write(content)
        return filename
    except: return None

def generate_attack_vector(apk_name, strings, precise_pkg=None, main_activity=None):
    package_name = precise_pkg if (precise_pkg and precise_pkg != "Unknown") else "com.unknown"
    if package_name == "com.unknown":
        for s in strings:
            if "com." in s and len(s) < 40 and s.count('.') > 1:
                package_name = s
                break
    potential_activities = []
    if main_activity: potential_activities.append(main_activity)
    for s in strings:
        if s.startswith("com.") and "Activity" in s and "$" not in s and "AdActivity" not in s:
            if s != main_activity: potential_activities.append(s)
    if not potential_activities: return None
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"/sdcard/Download/Attack_{apk_name}_{timestamp}.sh"
    content = f"#!/bin/bash\n# CyberMoranda Attack Vector\n# Target: {apk_name}\n# Package: {package_name}\n\n"
    content += "echo '[*] Note: Target App MUST be installed!'\n"
    if main_activity: content += f"echo '[+] Force Launching Main: {main_activity}'\nam start -n {package_name}/{main_activity}\nsleep 2\n"
    for act in potential_activities[1:15]: content += f"echo '[+] Fuzzing: {act}'\nam start -n {package_name}/{act}\nsleep 0.5\n"
    try:
        with open(filename, "w") as f: f.write(content)
        return filename
    except: return None

def generate_html_report(apk_name, hashes, permissions, suspicious_kws, secrets, urls, trackers, cert_info, snippets, cyber_score, firewall_file, attack_file, components, ai_summary, c2_data, vt_stats):
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f"/sdcard/Download/Report_{apk_name}_{timestamp}.html"
    
    perm_count = len(permissions)
    malware_count = len(suspicious_kws)
    tracker_count = len(trackers)
    secret_count = len(secrets)
    c2_count = len(c2_data["ips"])
    cert_color = '#ff0055' if "Debug" in cert_info else ('#ffcc00' if "Self" in cert_info else '#00f3ff')
    
    action_btns = ""
    if firewall_file: action_btns += f"<div class='card' style='border:1px solid #ffcc00;text-align:center;background:#222;margin-bottom:10px;'><strong style='color:#ffcc00;'>🛡️ DEFENSE: BLOCKLIST</strong><br><a href='{os.path.basename(firewall_file)}' download style='color:#fff;'>Download Rules</a></div>"
    if attack_file: action_btns += f"<div class='card' style='border:1px solid #ff0055;text-align:center;background:#220011;margin-bottom:20px;'><strong style='color:#ff0055;'>⚔️ OFFENSE: ATTACK VECTOR</strong><br><a href='{os.path.basename(attack_file)}' download style='background:#ff0055;color:#fff;padding:5px 15px;text-decoration:none;border-radius:5px;'>DOWNLOAD SCRIPT</a></div>"
    
    comp_html = ""
    if components["boot_receiver"]: comp_html += "<tr><td class='warn'>BOOT RECEIVER</td><td class='warn'>Auto-Start (Common in Apps)</td></tr>"
    if components["sms_receiver"]: comp_html += "<tr><td class='danger'>SMS RECEIVER</td><td class='danger'>Can Intercept OTPs/Messages</td></tr>"
    if components["admin_receiver"]: comp_html += "<tr><td class='danger'>DEVICE ADMIN</td><td class='danger'>Prevents Uninstallation</td></tr>"
    if not comp_html: comp_html = "<tr><td colspan='2' class='safe'>[SAFE] No Dangerous Components Found</td></tr>"

    c2_html = ""
    if c2_data["ips"]:
        for ip in c2_data["ips"]: c2_html += f"<tr><td class='danger'>IPV4 ADDR</td><td class='danger'>{ip}</td></tr>"
    else: c2_html = "<tr><td colspan='2' class='safe'>[SAFE] No C2 Servers Detected</td></tr>"

    vt_html = ""
    if vt_stats:
        vt_color = 'danger' if vt_stats.get('malicious', 0) > 0 else 'safe'
        vt_html = f"<div class='card' style='border:1px solid #fff; margin-bottom: 20px;'><strong>☁️ VIRUSTOTAL INTEL:</strong><br><span class='{vt_color}'>DETECTIONS: {vt_stats.get('malicious', 0)} / {vt_stats.get('total', 0)} ENGINES</span></div>"
    elif VT_API_KEY == "":
        vt_html = "<div class='card' style='opacity:0.5;'>VirusTotal API Key Missing. Cloud scan skipped.</div>"

    css = """
    <style>
        :root { --primary: #00f3ff; --bg: #050505; --alert: #ff0055; --text: #e0e0e0; --card: #111; --warn: #ffcc00; --code-bg: #1e1e1e; }
        body { background-color: var(--bg); color: var(--text); font-family: 'Courier New', monospace; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: auto; border-top: 3px solid var(--primary); padding: 20px; box-shadow: 0 0 30px rgba(0, 243, 255, 0.1); }
        .header { text-align: center; margin-bottom: 40px; }
        h1 { color: var(--primary); font-size: 2.5em; margin-bottom: 5px; text-shadow: 0 0 10px var(--primary); }
        .dashboard { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .card { background: var(--card); padding: 20px; border: 1px solid #333; border-radius: 5px; }
        .score-box { text-align: center; }
        .big-score { font-size: 4em; font-weight: bold; display: block; }
        .risk-label { font-size: 1.2em; font-weight: bold; padding: 5px 15px; border-radius: 5px; }
        h2 { color: #fff; border-left: 4px solid var(--primary); padding-left: 10px; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #0e0e0e; }
        th { background: #1a1a1a; color: var(--primary); padding: 10px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #222; border-left: 1px solid #222; }
        .danger { color: var(--alert); }
        .safe { color: var(--primary); }
        .warn { color: var(--warn); }
        .code-window { background: var(--code-bg); border: 1px solid #444; border-radius: 5px; padding: 15px; font-family: 'Consolas', monospace; font-size: 0.9em; overflow-x: auto; margin-bottom: 15px; }
        .code-line { display: block; color: #aaa; white-space: pre-wrap; word-break: break-all; }
        .highlight { color: var(--alert); font-weight: bold; background: rgba(255, 0, 85, 0.1); }
        .ai-box { background: #001100; border: 1px solid #00ff00; padding: 15px; font-family: 'Consolas', monospace; color: #00ff00; margin-bottom: 20px; box-shadow: 0 0 15px rgba(0, 255, 0, 0.2); }
        .ai-header { font-weight: bold; border-bottom: 1px solid #00ff00; margin-bottom: 10px; padding-bottom: 5px; }
        footer { text-align: center; margin-top: 50px; color: #444; border-top: 1px solid #222; padding-top: 20px; }
    </style>
    """
    
    snippets_html = ""
    if snippets:
        for item in snippets:
            snippets_html += f"<div class='code-window'><span class='context-header'>DETECTION: {html.escape(item['keyword'])}</span>"
            for line in item['context']:
                if item['keyword'] in line: snippets_html += f"<span class='code-line highlight'>{html.escape(line)}</span>"
                else: snippets_html += f"<span class='code-line'>{html.escape(line)}</span>"
            snippets_html += "</div>"
    else: snippets_html = "<div class='card safe'>[SAFE] No Suspicious Code Patterns Found</div>"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>CyberMoranda Report: {apk_name}</title>{css}<script src="https://cdn.jsdelivr.net/npm/chart.js"></script></head>
    <body>
        <div class="container">
            <div class="header"><h1>CYBERMORANDA</h1><p class="motto">APK SHIELD v7.0 | CLOUD UPLINK</p></div>
            <div class="dashboard">
                <div class="card score-box">
                    <div style="text-align:left; font-size:0.8em; color:#888;">TARGET</div>
                    <div style="font-size:1.2em; font-weight:bold; color:#fff;">{apk_name}</div><br>
                    <span class="big-score" style="color: {'#ff0055' if cyber_score > 70 else ('#ffcc00' if cyber_score > 40 else '#00f3ff')}">{cyber_score}</span>
                    <span style="color:#666;">/ 100</span><br><br>
                    <span class="risk-label" style="background: {'#ff0055' if cyber_score > 70 else ('#ffcc00' if cyber_score > 40 else '#00f3ff')}; color: #000;">{'SEVERE THREAT' if cyber_score > 70 else ('SUSPICIOUS / ADWARE' if cyber_score > 40 else 'SAFE SYSTEM')}</span>
                </div>
                <div class="card"><canvas id="threatChart"></canvas></div>
            </div>
            
            <div class="ai-box">
                <div class="ai-header">🤖 AI BEHAVIORAL ANALYSIS</div>
                <div style="white-space: pre-wrap;">{ai_summary}</div>
            </div>

            {vt_html}
            {action_btns}
            
            <div class="card" style="border-left: 4px solid {cert_color}; margin-bottom: 20px;">
                <strong>DIGITAL SIGNATURE:</strong><br><span style="color:{cert_color}; font-size: 1.1em;">{cert_info}</span><br><span style="font-size:0.8em; color:#666;">SHA256: {hashes.get('sha256', 'N/A')[:20]}...</span>
            </div>
            
            <h2>> C2 INFRASTRUCTURE (HACKER IPs)</h2>
            <table><tr><th>Target</th><th>Status</th></tr>{c2_html}</table>

            <h2>> HIDDEN COMPONENT ANALYSIS</h2>
            <table><tr><th>Component Type</th><th>Risk Level</th></tr>{comp_html}</table>

            <h2>> DEEP CODE EVIDENCE</h2>{snippets_html}
            <h2>> THREAT INTELLIGENCE</h2>
            <table>
                {''.join([f"<tr><td class='danger'>MALWARE: {kw}</td></tr>" for kw in suspicious_kws]) if suspicious_kws else "<tr><td class='safe'>[SAFE] No Malware Signatures</td></tr>"}
                {''.join([f"<tr><td class='warn'>TRACKER: {t}</td></tr>" for t in trackers])}
                {''.join([f"<tr><td class='danger'>SECRET: {s[:50]}...</td></tr>" for s in secrets])}
            </table>
            <footer>Developed by Moranda</footer>
        </div>
        <script>
            const ctx = document.getElementById('threatChart').getContext('2d');
            new Chart(ctx, {{ type: 'doughnut', data: {{ labels: ['Permissions', 'Malware', 'Trackers', 'C2 Servers'], datasets: [{{ data: [{perm_count}, {malware_count}, {tracker_count}, {c2_count}], backgroundColor: ['#ff0055', '#ff4444', '#ffcc00', '#ffffff'], borderColor: '#000', borderWidth: 2 }}] }}, options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#fff' }} }} }} }} }});
        </script>
    </body></html>
    """
    try:
        with open(report_filename, "w", encoding='utf-8') as f: f.write(html_content)
        return report_filename
    except: return None

# --- ANALYSIS ENGINE ---
def analyze_apk(path):
    UI.banner()
    init_db()

    if not os.path.exists(path):
        print(f"{UI.RED}[!] Error: File not found: {path}{UI.RESET}")
        return

    print(f"{UI.BLUE}[+] Target Acquired: {UI.BOLD}{os.path.basename(path)}{UI.RESET}")
    UI.progress_bar("Decompiling & Extracting Resources...", 1.0)
    
    apk_info = get_precise_info(path)
    if apk_info["package"] != "Unknown":
        print(f"{UI.GREEN}[+] Precision Target: {apk_info['package']} (v{apk_info['version']}){UI.RESET}")
    else: print(f"{UI.YELLOW}[!] AAPT Missing: Using Heuristics Mode{UI.RESET}")

    md5, sha256 = calc_hashes(path)
    all_strings = extract_strings_ordered(path)
    print(f"{UI.CYAN}[*] Hunting for Hidden Components & C2 Servers...{UI.RESET}")
    components = scan_components(path)
    c2_data = extract_c2_infrastructure(all_strings)
    
    UI.progress_bar("Analyzing Code Vectors & Patterns...", 1.0)
    
    high_risk_perms = []
    found_trackers = []
    bad_kws = []
    secrets = []
    urls = []
    snippets = []
    
    PERM_REGEX = re.compile(r"android\.permission\.([A-Z_]+)")
    URL_REGEX = re.compile(r"https?://[^\s\"']+")
    SECRET_PATTERNS = {
        "Google API": r"AIza[0-9A-Za-z-_]{35}",
        "Firebase": r"https://[a-z0-9-]+\.firebaseio\.com",
        "Private Key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----"
    }
    SUSPICIOUS_KEYWORDS = ["metasploit", "meterpreter", "spynote", "ahmyth", "droidjack", "keylogger", "bind_tcp"]
    SUSPICIOUS_DOMAINS = ["ngrok.io", "discord.gg", "herokuapp.com", "pastebin.com"]

    for i, s in enumerate(all_strings):
        match = PERM_REGEX.search(s)
        if match:
            perm = match.group(1)
            if perm in ["READ_SMS", "SEND_SMS", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "INSTALL_PACKAGES"]:
                if perm not in high_risk_perms: high_risk_perms.append(perm)
        for t_name, t_sig in TRACKER_SIGNATURES.items():
            if t_sig in s and t_name not in found_trackers: found_trackers.append(t_name)
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in s.lower():
                if kw not in bad_kws: bad_kws.append(kw)
                start_idx = max(0, i - 3); end_idx = min(len(all_strings), i + 4)
                snippets.append({'keyword': kw, 'context': all_strings[start_idx:end_idx]})
        for name, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, s):
                secrets.append(f"{name}: {s[:20]}...")
                start_idx = max(0, i - 3); end_idx = min(len(all_strings), i + 4)
                snippets.append({'keyword': name, 'context': all_strings[start_idx:end_idx]})
        match = URL_REGEX.search(s)
        if match:
            url = match.group(0)
            if url not in urls: urls.append(url)

    suspicious_urls = []
    for u in urls:
        for bad in SUSPICIOUS_DOMAINS:
            if bad in u and u not in suspicious_urls: suspicious_urls.append(u)

    cert_info = analyze_certificate(path)

    # --- v7.0: CLOUD UPLINK (VIRUSTOTAL) ---
    print(f"{UI.BLUE}[*] Connecting to Global Threat Grid (VirusTotal)...{UI.RESET}")
    vt_stats = check_virustotal(sha256)
    
    # CLI REPORT
    print(f"\n{UI.CYAN}┌────────────────────────────────────────────────────────┐")
    print(f"│ {UI.BOLD}DIGITAL FORENSICS REPORT{UI.RESET}                               │")
    print(f"└────────────────────────────────────────────────────────┘{UI.RESET}")
    UI.print_box("FILE IDENTITY", f"Name: {os.path.basename(path)}\nPkg:  {apk_info['package']}\nSign: {cert_info}")

    if vt_stats:
        vt_color = UI.RED if vt_stats.get("malicious", 0) > 0 else UI.GREEN
        UI.print_box("CLOUD INTEL", f"VirusTotal Detections: {vt_stats.get('malicious', 0)}/{vt_stats.get('total', 0)}", vt_color)

    if high_risk_perms or found_trackers or bad_kws or c2_data["ips"]:
        UI.table_header("THREAT INDICATOR", "TYPE")
        for p in high_risk_perms: UI.table_row(p, "PERMISSION", UI.RED)
        for t in found_trackers: UI.table_row(t, "TRACKER", UI.YELLOW)
        for k in bad_kws: UI.table_row(k, "MALWARE", UI.RED)
        for ip in c2_data["ips"]: UI.table_row(ip, "C2 SERVER", UI.RED)
        if components["boot_receiver"]: UI.table_row("BOOT RECEIVER", "PERSISTENCE", UI.YELLOW)
        UI.table_footer()
    else:
        UI.print_box("STATUS", "No critical threats detected.", UI.GREEN)

    # --- SCORING ---
    cyber_score = 0
    is_malware_confirmed = len(bad_kws) > 0
    
    # VT Impact
    if vt_stats and vt_stats.get("malicious", 0) > 3:
        cyber_score = 100 # Instant Critical if VT confirms
        is_malware_confirmed = True

    if high_risk_perms: cyber_score += len(high_risk_perms) * 10
    if found_trackers:
        if is_malware_confirmed: cyber_score += len(found_trackers) * 5
        else: cyber_score += min(len(found_trackers) * 2, 20)
    
    if "DEBUG" in cert_info: cyber_score += 30
    elif "Self" in cert_info or "Unknown" in cert_info:
        if is_malware_confirmed: cyber_score += 20
        else: cyber_score += 5
        
    if bad_kws: cyber_score += len(bad_kws) * 25
    if snippets: cyber_score += 10
    if suspicious_urls: cyber_score += len(suspicious_urls) * 15
    if secrets: cyber_score += len(secrets) * 20
    if c2_data["ips"]: cyber_score += len(c2_data["ips"]) * 20
    
    if components["boot_receiver"]: cyber_score += 30 if is_malware_confirmed else 5
    if components["sms_receiver"]: cyber_score += 40
    if components["admin_receiver"]: cyber_score += 30
    if components["overlay_service"]: cyber_score += 20
    
    if cyber_score > 100: cyber_score = 100

    verdict_text = "CLEAN"; verdict_color = UI.GREEN
    if cyber_score >= 80: verdict_text = "SEVERE"; verdict_color = UI.RED
    elif cyber_score >= 50: verdict_text = "HIGH RISK"; verdict_color = UI.RED
    elif cyber_score > 20: verdict_text = "SUSPICIOUS"; verdict_color = UI.YELLOW

    save_scan_to_db(os.path.basename(path), sha256, cyber_score, verdict_text)

    print(f"\n{verdict_color}╔══════════════════════════════════════════════════════╗")
    print(f"║ THREAT SCORE: {str(cyber_score).ljust(3)} | VERDICT: {verdict_text.ljust(15)}           ║")
    print(f"╚══════════════════════════════════════════════════════╝{UI.RESET}")

    firewall_file = None
    if suspicious_urls or found_trackers or c2_data["ips"]:
        firewall_file = generate_firewall_rules(os.path.basename(path), suspicious_urls, found_trackers, c2_data["ips"])
        print(f"{UI.YELLOW}[+] Active Defense Rules Generated (Blocklist){UI.RESET}")

    attack_file = None
    if len(all_strings) > 0:
        attack_file = generate_attack_vector(os.path.basename(path), all_strings, apk_info["package"], apk_info["launchable"])
        if attack_file: print(f"{UI.RED}[+] Red Team Attack Vector Generated{UI.RESET}")

    print(f"{UI.BLUE}[*] Generating AI Threat Summary...{UI.RESET}")
    ai_summary = generate_ai_summary(cyber_score, components, found_trackers, secrets, high_risk_perms, is_malware_confirmed, c2_data, vt_stats)

    json_data = {
        "target": os.path.basename(path),
        "score": cyber_score,
        "verdict": verdict_text,
        "ai_summary": ai_summary,
        "trackers": found_trackers,
        "permissions": high_risk_perms,
        "secrets": secrets,
        "c2_infrastructure": c2_data,
        "virustotal": vt_stats
    }
    json_file = f"/sdcard/Download/Report_{os.path.basename(path)}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(json_file, 'w') as f: json.dump(json_data, f, indent=4)
        print(f"{UI.GREEN}[+] JSON Data Exported: {json_file}{UI.RESET}")
    except: pass

    UI.progress_bar("Compiling Evidence to Dashboard...", 0.5)
    report_file = generate_html_report(
        apk_name=os.path.basename(path),
        hashes={'md5': md5, 'sha256': sha256},
        permissions=high_risk_perms,
        suspicious_kws=bad_kws,
        secrets=secrets,
        urls=suspicious_urls,
        trackers=found_trackers,
        cert_info=cert_info,
        snippets=snippets,
        cyber_score=cyber_score,
        firewall_file=firewall_file,
        attack_file=attack_file,
        components=components,
        ai_summary=ai_summary,
        c2_data=c2_data,
        vt_stats=vt_stats
    )

    if report_file:
        print(f"\n{UI.GREEN}[SUCCESS] Dashboard Ready: {report_file}{UI.RESET}")
        try:
            print(f"{UI.CYAN}[?] Initialize Visualization Server? (Y/n): {UI.RESET}", end="")
            choice = input().strip().lower()
            if choice in ['y', 'yes', '']:
                port = 8080
                report_dir = os.path.dirname(report_file)
                report_name = os.path.basename(report_file)
                print(f"{UI.YELLOW}[*] Server Online: http://localhost:{port}/{report_name}{UI.RESET}")
                cmd = f"python -m http.server {port}"
                subprocess.run(cmd, shell=True, cwd=report_dir)
        except: pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("apk_file", nargs='?')
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    if args.history: show_history()
    elif args.apk_file: analyze_apk(args.apk_file)
    else: UI.banner(); print(f"{UI.YELLOW}Usage: python apk_shield.py <apk_path>{UI.RESET}")
