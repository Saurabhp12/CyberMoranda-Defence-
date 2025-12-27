import requests
import concurrent.futures
import itertools
from core.display import print_status
from core.validator import SmartValidator

class DirFuzzer:
    def __init__(self, target, proxies=None, headers=None, soft_404_size=0):
        self.target = target.rstrip('/')
        self.proxies = proxies
        self.headers = headers
        self.soft_404_size = soft_404_size
        
        # [UPGRADE 1] Session Pooling (Speed Hack)
        # बार-बार कनेक्शन खोलने/बंद करने का समय बचाएगा
        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        if proxies:
            self.session.proxies.update(proxies)

        # [UPGRADE 2] The "High-Value" Wordlist (Expanded)
        self.base_words = [
            'admin', 'administrator', 'backup', 'backups', 'config', 'conf', 
            'api', 'v1', 'v2', 'dashboard', 'dev', 'staging', 'test', 'tests',
            'login', 'register', 'user', 'users', 'auth', 'oauth',
            'server-status', 'phpinfo.php', '.git/config', '.env', 
            'docker-compose.yml', 'wp-config.php', 'composer.json', 
            'package.json', 'access.log', 'error.log', 'database', 'db',
            'dump', 'sql', 'private', 'secret', 'aws', 's3'
        ]

        # [UPGRADE 3] Smart Extensions
        self.extensions = ['', '.php', '.json', '.xml', '.bak', '.old', '.zip', '.sql', '.txt', '.log']

    def generate_payloads(self):
        """शब्दों और एक्सटेंशन को मिक्स करता है"""
        payloads = []
        for word in self.base_words:
            # अगर शब्द में पहले से डॉट है (जैसे .env), तो एक्सटेंशन मत लगाओ
            if '.' in word and not word.endswith('.php'):
                payloads.append(word)
            else:
                # config -> config, config.php, config.bak, config.json...
                for ext in self.extensions:
                    payloads.append(f"{word}{ext}")
        return list(set(payloads))  # डुप्लिकेट हटा दें

    def check_path(self, path):
        url = f"{self.target}/{path}"
        try:
            # [SPEED] Session का उपयोग (verify=False SSL एरर रोकता है)
            r = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
            
            content_size = len(r.content)

            # --- [SOFT 404 FILTER] ---
            if self.soft_404_size > 0 and abs(content_size - self.soft_404_size) < 100:
                return None

            # --- [SMART ANALYSIS] ---
            if r.status_code == 200:
                # Validator चेक
                validator = SmartValidator()
                validation_result = validator.analyze_page(r.text)

                if "False Positive" in validation_result:
                    return None
                
                # अगर .git/config या .env मिला तो CRITICAL
                severity = "Critical" if "Real" in validation_result or path.startswith('.') else "High"
                
                print_status(f"FOUND ASSET: /{path} (Size: {content_size} | {validation_result})", "success")
                return {
                    "title": f"Asset Found: /{path}",
                    "severity": severity,
                    "desc": f"Status 200 | Size: {content_size} | {validation_result}",
                    "url": url
                }

            elif r.status_code in [403, 401]:
                # 403 Forbidden और 401 Unauthorized भी जरूरी हैं
                print_status(f"PROTECTED PATH: /{path} (Status: {r.status_code})", "warning")
                return {
                    "title": f"Protected Path: /{path}",
                    "severity": "Medium",
                    "desc": f"Status {r.status_code} detected",
                    "url": url
                }
                
            elif r.status_code == 500:
                # 500 एरर का मतलब है हम सर्वर को क्रैश करा रहे हैं (Potential Vulnerability)
                return {
                    "title": f"Server Error: /{path}",
                    "severity": "Low",
                    "desc": f"Status 500 (Potential Injection Point)",
                    "url": url
                }

        except Exception:
            pass
        return None

    def start_fuzzing(self):
        # पहले सारे कॉम्बिनेशन (Payloads) बनाएं
        wordlist_final = self.generate_payloads()
        total_targets = len(wordlist_final)
        print_status(f"Generated {total_targets} smart payloads for fuzzing...", "info")

        findings = []
        # [SPEED] Threads बढ़ाकर 30 कर दिए
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            results = list(executor.map(self.check_path, wordlist_final))
            findings = [r for r in results if r is not None]
        
        self.session.close() # सेशन बंद करें
        return findings
