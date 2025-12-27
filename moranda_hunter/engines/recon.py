import requests
import socket
import urllib3
import re
import time
import random
from urllib.parse import urlparse, urljoin, parse_qs
from core.display import Colors, print_separator, print_status
from core.stealth import StealthManager

# SSL Warnings को बंद करें
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ReconEngine:
    def __init__(self, target, proxies=None):
        self.target = target
        self.domain = urlparse(target).netloc
        self.proxies = proxies
        self.stealth = StealthManager()
        
        # [FIX] Session Object यहाँ Initialize करना ज़रूरी है
        self.session = requests.Session()
        self.session.proxies.update(proxies if proxies else {})
        self.session.verify = False
        
        # Persistent Headers (पूरे सेशन के लिए एक ही User-Agent)
        self.headers = self.stealth.get_random_headers()
        self.session.headers.update(self.headers)
        self.user_agent = self.headers['User-Agent']

    def _make_request(self, url, params=None, allow_redirects=True):
        """Tor Optimized Request Handler"""
        # Jitter (WAF को कंफ्यूज करने के लिए)
        time.sleep(random.uniform(0.5, 2.0))
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # [FIX] requests.get की जगह self.session.get का उपयोग करें
                response = self.session.get(
                    url, 
                    timeout=30,  # Tor के लिए 30s Timeout
                    params=params, 
                    allow_redirects=allow_redirects
                )
                return response
            except requests.exceptions.Timeout:
                continue # Retry
            except requests.exceptions.ConnectionError:
                # अगर Tor सर्किट मर गया है, तो नया सेशन शुरू करें
                self.session = requests.Session()
                self.session.proxies.update(self.proxies if self.proxies else {})
                self.session.headers.update(self.headers)
                time.sleep(2)
                continue
            except Exception:
                return None
        return None

    def normalize_target(self):
        print_separator("Target Intelligence")
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'https://' + self.target
        
        # URL को क्लीन करें
        parsed = urlparse(self.target)
        self.target = f"{parsed.scheme}://{parsed.netloc}"
        return True

    def check_connection(self):
        print_status(f"Establish connection to {self.target}...", "info")
        
        try:
            # अब self.session यहाँ मौजूद है और काम करेगा
            r = self.session.get(
                self.target, 
                timeout=30, 
                allow_redirects=True, 
                verify=False
            )
            
            server_header = r.headers.get('Server', 'Unknown')
            print_status(f"Status: ONLINE [{r.status_code}] | Server: {server_header}", "success")
            
            # अगर रीडायरेक्ट हुआ तो URL अपडेट करें
            if r.url != self.target:
                self.target = r.url
                print_status(f"Target Redirected to: {self.target}", "info")
                
            return True

        except Exception as e:
            print_status(f"Connection Failed: {str(e)}", "failure")
            return False

    def detect_waf(self):
        print_separator("Firewall Analysis")
        waf_payload = {"id": "<script>alert(1)</script>"}
        r = self._make_request(self.target, params=waf_payload)
        
        if r:
            if r.status_code in [403, 406] or "cf-ray" in str(r.headers).lower():
                print_status("WAF DETECTED! (Cloudflare/Generic)", "danger")
            else:
                print_status("No aggressive WAF detected.", "success")
        else:
            print_status("Could not determine WAF status.", "warning")

    def analyze_params(self):
        print_separator("Parameter Risk Scan")
        return []

    def scan_pii(self):
        print_separator("PII Intelligence")
        findings = []
        r = self._make_request(self.target)
        if r:
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text)
            unique_emails = set(emails)
            for email in unique_emails:
                if not any(email.lower().endswith(ext) for ext in ['.png', '.jpg', '.gif', '.svg']):
                    print_status(f"PII DISCLOSED: {email}", "danger")
                    findings.append({"title": "Email Disclosure", "severity": "Medium", "desc": f"Found: {email}"})
        return findings

    def discover_assets(self):
        js_files = set()
        r = self._make_request(self.target)
        if r:
            found_js = re.findall(r'src=["\'](.*?\.js.*?)["\']', r.text)
            for js in found_js: 
                full_url = urljoin(self.target, js)
                js_files.add(full_url)
        return list(js_files)

    def scan_hidden_files(self):
        print_separator("Quick Data Leak Check")
        findings = []
        quick_checks = ['/.git/config', '/.env', '/robots.txt', '/sitemap.xml']
        
        for f in quick_checks:
            url = urljoin(self.target, f)
            r = self._make_request(url)
            
            if r and r.status_code == 200:
                if "html" not in r.headers.get('Content-Type', '').lower():
                    print_status(f"EXPOSED: {f}", "danger")
                    findings.append({"title": f"Sensitive File: {f}", "severity": "High", "desc": "Critical leak discovered"})
        return findings
