#!/usr/bin/env python3
# ----------------------------------------------------------------------------------
# CYBERMORANDA APK SHIELD v10.1 (Enterprise Auditor)
# System Architect: MORANDA
# Features: Context-Aware Security Audit, Static Analysis, Threat Intel, Reporting
# ----------------------------------------------------------------------------------

import os
import re
import sys
import zipfile
import hashlib
import argparse
import time
import datetime
import json
import urllib.request
import urllib.error
import math
import shutil
import http.server
import socketserver

# --- CONFIGURATION & CONSTANTS ---

# Default Permission Risk Map with Contextual Confidence
PERMISSION_MAP = {
    "READ_SMS": {"msg": "Privacy: Can read private SMS/OTPs", "sev": "HIGH", "conf": "High"},
    "SEND_SMS": {"msg": "Cost/Spam: Can send SMS in background", "sev": "HIGH", "conf": "High"},
    "CAMERA": {"msg": "Privacy: Can record video/image", "sev": "MEDIUM", "conf": "High"},
    "RECORD_AUDIO": {"msg": "Privacy: Can record audio", "sev": "MEDIUM", "conf": "High"},
    "ACCESS_FINE_LOCATION": {"msg": "Tracking: Precise GPS location", "sev": "MEDIUM", "conf": "High"},
    "INSTALL_PACKAGES": {"msg": "Security: Can request installation of other APKs", "sev": "HIGH", "conf": "High"},
    "SYSTEM_ALERT_WINDOW": {"msg": "Phishing: Overlay attacks (draw over other apps)", "sev": "HIGH", "conf": "Medium"},
    "READ_EXTERNAL_STORAGE": {"msg": "Privacy: Read shared storage files", "sev": "LOW", "conf": "High"},
    "WRITE_EXTERNAL_STORAGE": {"msg": "Privacy: Modify shared storage files", "sev": "LOW", "conf": "High"},
    "GET_ACCOUNTS": {"msg": "Privacy: Enumerate device accounts", "sev": "MEDIUM", "conf": "Medium"},
    "READ_CONTACTS": {"msg": "Privacy: Extract address book", "sev": "MEDIUM", "conf": "High"}
}

# Risky URL Parameters for Deep Link Analysis
RISKY_PARAMS = ["redirect", "next", "url", "target", "dest", "token", "auth", "password", "callback", "execute"]

# Domains/Libraries to filter out (Noise Reduction)
NOISE_DOMAINS = [
    "schemas.android.com", "www.w3.org", "ns.adobe.com", "publicsuffix.org",
    "purl.org", "www.apache.org", "xml.org", "github.com", "android.googlesource.com",
    "example.com", "localhost"
]

# --- ARGUMENT PARSER ---
parser = argparse.ArgumentParser(
    description='CyberMoranda APK Shield v10.1 - Enterprise Security Auditor',
    epilog='Designed for Security Audits & Bug Bounty Recon.'
)
parser.add_argument('apk', help='Path to target APK file')
parser.add_argument('--mode', choices=['bounty', 'privacy', 'fast'], default='bounty', help='Scan Profile (Default: bounty)')
args = parser.parse_args()

# --- UTILS ---

def load_api_key():
    """Safely loads VirusTotal API key from vt_key.txt"""
    key_file = "vt_key.txt"
    if os.path.exists(key_file):
        try:
            with open(key_file, "r") as f:
                key = f.read().strip()
                if len(key) == 64: return key
        except: pass
    return ""

VT_API_KEY = load_api_key()

class UI:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    PURPLE = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'

    @staticmethod
    def banner():
        os.system('clear')
        print(f"{UI.CYAN}{UI.BOLD}")
        print(r"""
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ 
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
        """)
        print(f"\n   CYBERMORANDA APK SHIELD v10.1 | {UI.YELLOW}ENTERPRISE EDITION{UI.CYAN}")
        print(f"   {UI.GRAY}>> Mode: {args.mode.upper()} | System Architect: MORANDA{UI.RESET}\n")

    @staticmethod
    def print_finding(finding):
        sev = finding['sev']
        color = UI.RED if sev == "HIGH" else (UI.YELLOW if sev == "MEDIUM" else UI.BLUE)
        print(f"{color}[{sev}] {finding['title']}{UI.RESET}")
        if 'evidence' in finding:
            print(f"   └─ Evidence: {finding['evidence']}")
        if 'poc' in finding and args.mode == 'bounty':
            print(f"   └─ {UI.PURPLE}PoC: {finding['poc']}{UI.RESET}")

# --- CORE ENGINES ---

def calc_hashes_and_entropy(path):
    """Calculates SHA256, MD5, and File Entropy."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    file_size = os.path.getsize(path)
    
    # Entropy calculation
    byte_counts = [0] * 256
    total_bytes = 0
    
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk: break
            sha256.update(chunk)
            md5.update(chunk)
            for b in chunk:
                byte_counts[b] += 1
            total_bytes += len(chunk)
            
    entropy = 0
    if total_bytes > 0:
        for count in byte_counts:
            if count == 0: continue
            p = count / total_bytes
            entropy -= p * math.log2(p)
            
    return md5.hexdigest(), sha256.hexdigest(), round(entropy, 2), file_size

def detect_context(strings):
    """
    Intelligent Context Engine: Determines if the app is a Launcher, Game, etc.
    to reduce false positives on permissions.
    """
    joined_manifest = " ".join(strings[:8000]).lower()
    joined_code = " ".join(strings).lower()
    
    # FILE MANAGER Detection
    if "manage_external_storage" in joined_manifest or ("read_external_storage" in joined_manifest and "write_external_storage" in joined_manifest):
        if any(x in joined_code for x in ["file explorer", "file manager", "open explorer", "amaze", "root explorer"]):
            return "FILE MANAGER"

    # LAUNCHER Detection
    if "android.intent.category.home" in joined_manifest and "android.intent.action.main" in joined_manifest:
        return "LAUNCHER"

    # BROWSER Detection
    if "webkit" in joined_code and "android.permission.internet" in joined_manifest:
        if any(x in joined_code for x in ["browser", "chrome", "mozilla", "search engine"]):
            return "BROWSER"
            
    # GAME Detection
    if any(x in joined_code for x in ["unity3d", "unreal engine", "cocos2d", "godot", "libgdx"]):
        return "GAME"
    
    # VPN/PROXY
    if "bind_vpn_service" in joined_manifest:
        return "VPN TOOL"

    return "STANDARD APP"

def scan_manifest_security(strings, context):
    """Parses binary manifest strings for configuration risks and permissions."""
    manifest_data = " ".join(strings[:10000]) # Scan head of file roughly
    findings = []
    
    # 1. Configuration Risks
    if 'android:debuggable="true"' in manifest_data:
        findings.append({
            "sev": "HIGH", "title": "App is Debuggable", 
            "type": "Config", "evidence": "android:debuggable=\"true\"", 
            "poc": "adb jdwp"
        })
    
    if 'android:allowbackup="true"' in manifest_data:
        findings.append({
            "sev": "MEDIUM", "title": "Backup Allowed", 
            "type": "Config", "evidence": "android:allowBackup=\"true\" - Data extraction possible"
        })

    if 'android:usescleartexttraffic="true"' in manifest_data:
        findings.append({
            "sev": "MEDIUM", "title": "Cleartext Traffic Allowed", 
            "type": "Network", "evidence": "android:usesCleartextTraffic=\"true\""
        })

    # 2. Permission Analysis with Context Logic
    for perm, info in PERMISSION_MAP.items():
        if perm in manifest_data:
            sev = info['sev']
            conf = info['conf']
            
            # Context Adjustment
            if context == "LAUNCHER" and perm == "INSTALL_PACKAGES":
                sev = "LOW"
                conf = "Medium (Expected for Launchers)"
            
            if context == "FILE MANAGER" and ("STORAGE" in perm or "INSTALL_PACKAGES" in perm):
                sev = "INFO"
                conf = "High (Core Functionality)"
                
            findings.append({
                "sev": sev, "title": f"Permission: {perm}", 
                "type": "Permission", "confidence": conf, "evidence": info['msg']
            })

    # 3. Exported Components (Attack Surface)
    # Heuristic check for binary XML attributes
    if 'android:exported="true"' in manifest_data:
        count = manifest_data.count('android:exported="true"')
        findings.append({
            "sev": "HIGH" if count > 3 else "MEDIUM",
            "title": f"{count} Exported Components Detected",
            "type": "Attack Surface",
            "evidence": "Activities/Services marked exported=true (Potential Entry Points)",
            "poc": "adb shell am start -n <package>/.<Activity>"
        })

    return findings

def scan_deep_links_and_params(strings):
    """Extracts custom schemes and risky URL parameters."""
    findings = []
    joined_data = " ".join(strings)
    
    # Extract Schemes
    schemes = re.findall(r'android:scheme="([a-zA-Z0-9\.\-_]+)"', joined_data)
    custom_schemes = [s for s in set(schemes) if s not in ["http", "https", "file", "content", "android", "package"]]
    
    for scheme in custom_schemes:
        findings.append({
            "sev": "MEDIUM", "title": f"Deep Link Scheme: {scheme}://", 
            "evidence": "Custom Scheme Handler detected"
        })

    # Risky Params (Open Redirect / SSRF clues)
    found_params = [p for p in RISKY_PARAMS if f'"{p}"' in joined_data or f"'{p}'" in joined_data]
    
    if found_params and (custom_schemes or "http" in schemes):
        base_scheme = custom_schemes[0] if custom_schemes else "app"
        param = found_params[0]
        findings.append({
            "sev": "HIGH", "title": "Risky URL Parameters Detected", 
            "type": "Input Validation", 
            "evidence": f"Potential Sink Parameters: {', '.join(found_params)}",
            "poc": f"{base_scheme}://?{param}=http://evil.com"
        })

    return findings

def hunt_secrets_and_endpoints(strings):
    """Regex based secret hunting and endpoint classification."""
    findings = []
    
    # Patterns
    PATTERNS = {
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
        "Private Key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
        "Hardcoded JWT": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
    }

    # Endpoint Classifiers
    ENDPOINTS = {
        "Analytics": ["google-analytics", "crashlytics", "mixpanel", "amplitude", "segment.io"],
        "Ad Network": ["doubleclick", "admob", "facebook.com/ads", "unityads", "applovin"],
        "Cloud Storage": ["amazonaws.com", "blob.core.windows.net", "storage.googleapis.com", "cloudinary"],
        "Messaging/C2": ["discord.com/api", "api.telegram.org", "slack.com/api", "irc."]
    }

    unique_strings = list(set(strings))
    processed_urls = set()

    for s in unique_strings:
        # Secret Hunt
        for name, pattern in PATTERNS.items():
            match = re.search(pattern, s)
            if match:
                findings.append({
                    "sev": "HIGH", "title": f"{name} Leaked", 
                    "type": "Secret", "evidence": match.group(0)[:50] + "..."
                })

        # Endpoint Classification
        if "http" in s:
            url_match = re.search(r'https?://[a-zA-Z0-9.-]+', s)
            if url_match:
                url = url_match.group(0)
                if url in processed_urls: continue
                
                # Filter Noise
                if any(n in url for n in NOISE_DOMAINS): continue
                
                processed_urls.add(url)
                
                category = "Unknown Endpoint"
                severity = "INFO"
                
                for cat, indicators in ENDPOINTS.items():
                    if any(i in url for i in indicators):
                        category = cat
                        if cat == "Analytics" or cat == "Ad Network": severity = "LOW"
                        if cat == "Messaging/C2": severity = "MEDIUM" # Telegram used for C2 often
                        break
                
                # Only report interesting things in Bounty Mode
                if args.mode == "bounty" and category in ["Unknown Endpoint", "Messaging/C2", "Cloud Storage"]:
                    findings.append({"sev": severity, "title": f"Network: {category}", "evidence": url})
                elif args.mode == "privacy" and category in ["Analytics", "Ad Network"]:
                     findings.append({"sev": "MEDIUM", "title": f"Tracker: {category}", "evidence": url})

    return findings

def check_virustotal(sha256):
    """Checks VirusTotal API. Handles errors gracefully."""
    if not VT_API_KEY:
        print(f"{UI.YELLOW}   [!] Scan skipped: No API Key in vt_key.txt{UI.RESET}")
        return None
    
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    
    print(f"{UI.GRAY}   [>] Querying VirusTotal Intelligence...{UI.RESET}")
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
            print(f"{UI.GREEN}   [+] Threat Intelligence Received.{UI.RESET}")
            return data['data']['attributes']['last_analysis_stats']
    except urllib.error.HTTPError as e:
        if e.code == 401: print(f"{UI.RED}   [!] VT Error: Invalid API Key.{UI.RESET}")
        elif e.code == 404: print(f"{UI.BLUE}   [i] VT: File not in database (Unique Sample).{UI.RESET}")
        elif e.code == 429: print(f"{UI.RED}   [!] VT Error: Rate Limit Exceeded.{UI.RESET}")
    except Exception as e:
        print(f"{UI.RED}   [!] Connection Error: {e}{UI.RESET}")
    return None

# --- SCORING & REPORTING ---

def calculate_score(all_findings, vt_stats, entropy):
    score = 0
    weights = {"HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}
    
    # 1. Static Findings
    for f in all_findings:
        score += weights.get(f['sev'], 0)
        
    # 2. Entropy (Obfuscation check)
    if entropy > 7.2:
        score += 10 # Likely packed/obfuscated
        
    # Cap static score at 80 before VT check
    score = min(score, 80)
    
    # 3. Reputation Logic (The "Truth" Check)
    if vt_stats:
        malicious = vt_stats.get('malicious', 0)
        suspicious = vt_stats.get('suspicious', 0)
        total_bad = malicious + suspicious
        
        if total_bad > 3:
            return 100 # Confirmed Malware
        elif total_bad > 0:
            return max(score, 60) # Suspicious
        else:
            # Clean on VT? Cap score to prevent false alarm panic
            # If static score was high (e.g. 70 due to permissions), clamp it to 35
            if score > 40:
                score = 35 
                
    return score

def generate_report(apk_name, score, all_findings, context, vt_stats, entropy, hashes):
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"Report_{apk_name}_{timestamp}.html"
    
    # Verdict Color
    score_color = "#58a6ff" # Blue (Safe)
    if score > 40: score_color = "#d29922" # Orange (Suspicious)
    if score > 75: score_color = "#ff7b72" # Red (Critical)
    
    vt_str = "Offline/Unknown"
    if vt_stats:
        vt_str = f"Detections: {vt_stats.get('malicious',0)} / {sum(vt_stats.values())}"

    # HTML Template (Safe List Construction)
    html_parts = [
        f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberMoranda Audit: {apk_name}</title>
    <style>
        :root {{ --bg: #0d1117; --card: #161b22; --text: #c9d1d9; --red: #ff7b72; --orange: #d29922; --blue: #58a6ff; --green: #238636; }}
        body {{ background-color: var(--bg); color: var(--text); font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #30363d; padding-bottom: 20px; margin-bottom: 30px; }}
        .logo {{ font-size: 1.5rem; font-weight: bold; color: var(--blue); letter-spacing: 1px; }}
        .score {{ font-size: 4rem; font-weight: 800; color: {score_color}; }}
        .card {{ background-color: var(--card); border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .badge {{ background-color: var(--green); color: white; padding: 5px 10px; border-radius: 20px; font-size: 0.8rem; vertical-align: middle; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .label {{ color: #8b949e; font-size: 0.9rem; display: block; margin-bottom: 5px; }}
        .value {{ font-family: monospace; font-size: 1rem; color: #fff; word-break: break-all; }}
        
        .finding {{ border-left: 4px solid var(--blue); background: #0d1117; padding: 15px; margin-bottom: 15px; border-radius: 4px; }}
        .finding.HIGH {{ border-left-color: var(--red); }}
        .finding.MEDIUM {{ border-left-color: var(--orange); }}
        .finding.LOW {{ border-left-color: var(--blue); }}
        .finding.INFO {{ border-left-color: #8b949e; }}
        
        .finding-title {{ font-weight: bold; font-size: 1.1rem; display: flex; justify-content: space-between; }}
        .finding-meta {{ font-size: 0.8rem; color: #8b949e; margin-top: 5px; }}
        .evidence {{ background: #21262d; padding: 10px; border-radius: 4px; font-family: monospace; color: #a5d6ff; margin-top: 10px; display: block; }}
        .poc {{ color: #d2a8ff; font-family: monospace; font-weight: bold; margin-top: 5px; display: block; }}
        
        input[type="text"] {{ width: 100%; padding: 12px; background: #0d1117; border: 1px solid #30363d; color: white; border-radius: 6px; margin-bottom: 20px; box-sizing: border-box; }}
    </style>
    <script>
        function filterFindings() {{
            const filter = document.getElementById('search').value.toUpperCase();
            const findings = document.getElementsByClassName('finding');
            for (let i = 0; i < findings.length; i++) {{
                const txt = findings[i].innerText;
                findings[i].style.display = txt.toUpperCase().indexOf(filter) > -1 ? "" : "none";
            }}
        }}
    </script>
</head>
<body>
    <div class="header">
        <div>
            <div class="logo">CYBERMORANDA SHIELD v10.1</div>
            <h2 style="margin: 5px 0 0 0;">Target: {apk_name} <span class="badge">{context}</span></h2>
        </div>
        <div style="text-align: right;">
            <span class="label">RISK SCORE</span>
            <span class="score">{score}/100</span>
        </div>
    </div>

    <div class="card">
        <h3>📊 Executive Summary</h3>
        <div class="info-grid">
            <div><span class="label">MD5 Hash</span><span class="value">{hashes[0]}</span></div>
            <div><span class="label">SHA256 Hash</span><span class="value">{hashes[1][:16]}...</span></div>
            <div><span class="label">Threat Intel (VT)</span><span class="value">{vt_str}</span></div>
            <div><span class="label">Entropy (Packing)</span><span class="value">{entropy} / 8.0</span></div>
            <div><span class="label">File Size</span><span class="value">{round(hashes[3]/1024/1024, 2)} MB</span></div>
            <div><span class="label">Total Findings</span><span class="value">{len(all_findings)}</span></div>
        </div>
    </div>

    <input type="text" id="search" onkeyup="filterFindings()" placeholder="🔍 Search findings (e.g., 'SMS', 'Critical', 'API')...">

    <div class="card">
        <h3>🛡️ Security Findings</h3>
"""
    ]
    
    # Append findings
    if not all_findings:
        html_parts.append("<p style='color: var(--green); text-align:center;'>✅ No significant security risks found.</p>")
    
    for f in all_findings:
        sev = f['sev']
        poc_html = f'<span class="poc">⚡ PoC: {f["poc"]}</span>' if 'poc' in f else ''
        html_parts.append(f"""
        <div class="finding {sev}">
            <div class="finding-title">
                <span>[{sev}] {f['title']}</span>
                <span style="font-size:0.8rem; font-weight:normal;">{f.get('type', 'General')}</span>
            </div>
            <div class="finding-meta">{f.get('confidence', '')}</div>
            <span class="evidence">{f.get('evidence', 'No evidence provided')}</span>
            {poc_html}
        </div>
        """)
        
    html_parts.append("""
    </div>
    <div style="text-align: center; color: #8b949e; font-size: 0.8rem; margin-top: 40px;">
        Generated by CyberMoranda APK Shield v10.1 • Enterprise Security Auditor
    </div>
</body>
</html>
    """)
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))
    return filename

# --- MAIN ORCHESTRATION ---

def main():
    UI.banner()
    
    if not os.path.exists(args.apk):
        print(f"{UI.RED}[!] Error: File '{args.apk}' not found.{UI.RESET}")
        return

    print(f"{UI.CYAN}[*] Initializing Static Analysis Engine...{UI.RESET}")
    if VT_API_KEY:
        print(f"{UI.GREEN}[*] VirusTotal Key Loaded.{UI.RESET}")
    else:
        print(f"{UI.YELLOW}[!] VirusTotal Key missing/invalid (vt_key.txt). Cloud scan disabled.{UI.RESET}")

    # 1. Crypto & File Forensics
    md5, sha256, entropy, fsize = calc_hashes_and_entropy(args.apk)
    
    # 2. Extract Strings for Analysis
    print(f"{UI.CYAN}[*] Extracting Artifacts & Analyzing Context...{UI.RESET}")
    strings = []
    try:
        with zipfile.ZipFile(args.apk, 'r') as z:
            # Try to grab manifest
            try: strings.append(z.read("AndroidManifest.xml").decode('latin-1', errors='ignore'))
            except: pass
            # Grab some DEX/Res strings (limit to prevent memory crash on Termux)
            file_limit = 0
            for n in z.namelist():
                if file_limit > 500: break
                if n.endswith(".dex") or n.endswith(".xml"):
                    try: 
                        strings.append(z.read(n).decode('latin-1', errors='ignore'))
                        file_limit += 1
                    except: pass
    except zipfile.BadZipFile:
        print(f"{UI.RED}[!] Error: Invalid or Corrupt APK file.{UI.RESET}")
        return

    # 3. Detect Context
    context = detect_context(strings)
    print(f"{UI.BLUE}[i] Detected App Context: {UI.BOLD}{context}{UI.RESET}")
    
    # 4. Run Engines
    print(f"{UI.CYAN}[*] Running Heuristic Engines...{UI.RESET}")
    manifest_risks = scan_manifest_security(strings, context)
    deep_links = scan_deep_links_and_params(strings)
    secrets_net = hunt_secrets_and_endpoints(strings)
    
    all_findings = manifest_risks + deep_links + secrets_net
    
    # 5. Threat Intel
    vt_stats = check_virustotal(sha256)
    
    # 6. Scoring
    score = calculate_score(all_findings, vt_stats, entropy)
    
    # 7. Output
    print(f"\n{UI.PURPLE}--- AUDIT SUMMARY ---{UI.RESET}")
    
    # Sort findings by severity priority
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    all_findings.sort(key=lambda x: sev_order.get(x['sev'], 99))
    
    if not all_findings:
        print(f"{UI.GREEN}✅ No significant risks identified.{UI.RESET}")
    
    for f in all_findings:
        # Filter INFO in fast mode
        if args.mode == "fast" and f['sev'] == "INFO": continue
        UI.print_finding(f)

    print(f"\n{UI.BOLD}FINAL RISK SCORE: {score}/100{UI.RESET}")
    if score > 75: print(f"{UI.RED}[!] VERDICT: CRITICAL{UI.RESET}")
    elif score > 40: print(f"{UI.YELLOW}[!] VERDICT: SUSPICIOUS{UI.RESET}")
    else: print(f"{UI.GREEN}[+] VERDICT: SAFE{UI.RESET}")
    
    # 8. Report
    report_file = generate_report(os.path.basename(args.apk), score, all_findings, context, vt_stats, entropy, [md5, sha256, 0, fsize])
    
    # Move to Download folder for easy access in Termux
    dest_path = os.path.join("/sdcard/Download", report_file)
    try:
        shutil.copy(report_file, dest_path)
        print(f"\n{UI.GREEN}[SUCCESS] Report saved to: {dest_path}{UI.RESET}")
        report_file = dest_path # serve from sdcard if possible
    except:
        print(f"\n{UI.GREEN}[SUCCESS] Report saved to: {os.path.abspath(report_file)}{UI.RESET}")

    # 9. Server
    try:
        if input(f"\n{UI.YELLOW}[?] Launch Local Server to view report? (y/N): {UI.RESET}").lower() == 'y':
            # Change dir to where report is
            report_dir = os.path.dirname(report_file)
            if report_dir: os.chdir(report_dir)
            
            PORT = 8000
            Handler = http.server.SimpleHTTPRequestHandler
            with socketserver.TCPServer(("", PORT), Handler) as httpd:
                print(f"{UI.GREEN}[*] Serving at http://localhost:{PORT}/{os.path.basename(report_file)}{UI.RESET}")
                print(f"{UI.GRAY}(Press Ctrl+C to stop){UI.RESET}")
                httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()
