import requests
import re
import math
import concurrent.futures
from urllib.parse import urljoin
from core.display import print_status

class MorandaJSMiner:
    def __init__(self):
        # [UPGRADE 1] Intelligent Ignore List (Kachra saaf karne ke liye)
        self.ignore_files = [
            "jquery", "bootstrap", "modernizr", "react", "angular", 
            "vue", "moment", "lodash", "underscore"
        ]

        # [UPGRADE 2] Military Grade Signatures
        self.patterns = {
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
            "Generic API Key": r"(?i)(api_key|access_token|auth_token|client_secret|secret_key)\s*[:=]\s*['\"]([a-zA-Z0-9-_\.]{16,})['\"]",
            "Slack Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Twilio API Key": r"SK[0-9a-fA-F]{32}",
            "Mailgun API": r"key-[0-9a-zA-Z]{32}",
            "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
            "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
            "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
            "Facebook Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
            "Heroku API": r"[h|H]eroku[a-zA-Z0-9_]*(\s*[:=]\s*['\"][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}['\"])",
            "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
        }

    # [UPGRADE 3] Shannon Entropy (Ye check karega ki key 'random' hai ya nahi)
    def calculate_entropy(self, s):
        if not s: return 0
        entropy = 0
        for x in range(256):
            p_x = float(s.count(chr(x))) / len(s)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def scan_single_js(self, url):
        # Ignore common libraries to save time
        if any(ignored in url.lower() for ignored in self.ignore_files):
            return []

        try:
            # User-Agent spoofing to bypass simple firewalls
            headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'}
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code != 200:
                return []
                
            content = response.text
            found_secrets = []
            
            # Check file size (Skip if > 2MB to prevent freezing)
            if len(content) > 2000000: 
                return []

            for name, pattern in self.patterns.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    secret_str = match.group()
                    
                    # [BRAIN] Entropy Check
                    # Generic keys must be random (High Entropy)
                    if "Generic" in name:
                        # Extract just the key part for entropy check
                        key_part = re.search(r"['\"]([a-zA-Z0-9-_\.]{16,})['\"]", secret_str)
                        if key_part:
                            clean_key = key_part.group(1)
                            if self.calculate_entropy(clean_key) < 3.5:
                                continue # Skip low entropy (fake keys)

                    # Result formatting
                    finding = {
                        "type": name,
                        "data": secret_str[:100], # Don't print too long lines
                        "url": url
                    }
                    if finding not in found_secrets:
                        found_secrets.append(finding)
            
            return found_secrets
        except Exception:
            return []

    def hunt(self, main_url, js_files):
        print_status(f"🚀 Launching Parallel Miner on {len(js_files)} JS files...", "info")
        all_secrets = []
        
        # Prepare URLs
        target_urls = []
        for js in js_files:
            # Smart URL Joining
            full_url = urljoin(main_url, js)
            target_urls.append(full_url)

        # [UPGRADE 4] Multi-Threading (10x Faster)
        # Termux can handle 10 threads easily
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(self.scan_single_js, url): url for url in target_urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    data = future.result()
                    if data:
                        for secret in data:
                            # Color coded output
                            print_status(f"💣 {secret['type']} FOUND in {url.split('/')[-1]}", "critical")
                            print_status(f"   └── Payload: {secret['data']}", "critical")
                            all_secrets.append(secret)
                except Exception as exc:
                    pass

        if not all_secrets:
            print_status("Clean Scan: No hardcoded secrets found in JS.", "info")
            
        return all_secrets
