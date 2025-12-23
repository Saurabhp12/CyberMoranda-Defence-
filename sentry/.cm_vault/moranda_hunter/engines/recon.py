import requests
import socket
import urllib3
import re
import time
import random
from urllib.parse import urlparse, urljoin, parse_qs
from core.display import Colors, print_separator, print_status
from core.stealth import StealthManager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ReconEngine:
    def __init__(self, target, proxies=None):
        self.target = target
        self.domain = urlparse(target).netloc
        self.proxies = proxies
        self.stealth = StealthManager() 
        self.headers = self.stealth.get_random_headers()
        # [FIX]: Fuzzer के लिए user_agent को यहाँ रजिस्टर किया गया है
        self.user_agent = self.headers['User-Agent'] 

    def _make_request(self, url, params=None, allow_redirects=True):
        """Tor और Random Jitter के साथ रिक्वेस्ट मैनेजर"""
        time.sleep(random.uniform(1, 2))
        try:
            return requests.get(
                url, proxies=self.proxies, headers=self.stealth.get_random_headers(),
                verify=False, timeout=12, params=params, allow_redirects=allow_redirects
            )
        except: return None

    def normalize_target(self):
        print_separator("Target Intelligence")
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'https://' + self.target
        return True

    def check_connection(self):
        r = self._make_request(self.target)
        if r:
            print_status(f"Status: ONLINE [{r.status_code}] | Server: {r.headers.get('Server', 'Unknown')}", "success")
            return True
        return False

    def detect_waf(self):
        print_separator("Firewall Analysis")
        r = self._make_request(self.target)
        if r and "cf-ray" in str(r.headers).lower():
            print_status("WAF Detected: Cloudflare", "danger")
        else: print_status("No obvious WAF detected.", "success")

    def analyze_params(self):
        print_separator("Parameter Risk Scan")
        params = parse_qs(urlparse(self.target).query)
        findings = []
        for p in params:
            print_status(f"Targeting Parameter: {p}", "warning")
            findings.append({"title": f"Active Parameter: {p}", "severity": "Low", "desc": "Potential injection point"})
        return findings

    def scan_pii(self):
        print_separator("PII Intelligence")
        findings = []
        r = self._make_request(self.target)
        if r:
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text)
            for email in set(emails):
                if not any(email.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg']):
                    print_status(f"PII DISCLOSED: {email}", "danger")
                    findings.append({"title": "Email Disclosure", "severity": "Medium", "desc": f"Found: {email}"})
        return findings

    def discover_assets(self):
        js_files = set()
        r = self._make_request(self.target)
        if r:
            found_js = re.findall(r'src=["\'](.*?\.js.*?)["\']', r.text)
            for js in found_js: js_files.add(urljoin(self.target, js))
        return list(js_files)

    def scan_hidden_files(self):
        print_separator("Data Leak Discovery")
        findings = []
        for f in ['/.git/config', '/.env', '/phpinfo.php']:
            r = self._make_request(urljoin(self.target, f))
            if r and r.status_code == 200 and "html" not in r.headers.get('Content-Type', ''):
                print_status(f"EXPOSED: {f}", "danger")
                findings.append({"title": f"Sensitive File: {f}", "severity": "High", "desc": "Critical leak discovered"})
        return findings

    def scan_api_endpoints(self): return []
    def scan_robots_txt(self): return []
    def check_header_security(self): return []
    def discover_links(self): return []
