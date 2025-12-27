import requests
import concurrent.futures
from core.display import print_status

class SensitiveProber:
    def __init__(self, target, discovered_paths, proxies=None, headers=None, soft_404_size=0):
        self.target = target.rstrip('/')
        self.paths = discovered_paths
        self.proxies = proxies
        self.headers = headers
        self.soft_404_size = soft_404_size # Soft 404 फिल्टर के लिए

        # [UPGRADE 1] The Ultimate Loot List (Categorized)
        self.loot_map = {
            "Database": [
                'db.sql', 'dump.sql', 'users.sql', 'data.sql', 'backup.sql',
                'database.sqlite', 'site.sql', 'localhost.sql'
            ],
            "Archives": [
                'backup.zip', 'site_backup.zip', 'www.zip', 'public_html.zip',
                'backup.tar.gz', 'site.tar.gz', 'logs.tar.gz'
            ],
            "Config & Secrets": [
                '.env', 'config.php.bak', 'wp-config.php.bak', '.git/config',
                'docker-compose.yml', 'id_rsa', 'id_rsa.pub', '.npmrc',
                'web.config', 'settings.py'
            ],
            "Cloud": [
                'aws/credentials', '.aws/config', 'storage.json'
            ]
        }

    # [UPGRADE 2] Smart Content Validator (Fake File Detector)
    def validate_content(self, response, filename):
        content_snippet = response.content[:500].lower() # शुरू के 500 बाइट्स पढ़ें
        
        # Rule 1: अगर .env है, तो उसमें '=' होना चाहिए और HTML नहीं
        if filename.endswith('.env'):
            if b'=' in content_snippet and b'<html' not in content_snippet:
                return True
            return False

        # Rule 2: अगर SQL है, तो उसमें SQL कीवर्ड्स होने चाहिए
        if filename.endswith('.sql'):
            if b'create table' in content_snippet or b'insert into' in content_snippet:
                return True
            if b'<html' in content_snippet: # अगर HTML है तो यह नकली है
                return False

        # Rule 3: अगर ZIP/TAR है, तो उसमें HTML टैग्स नहीं होने चाहिए
        if filename.endswith(('.zip', '.tar.gz', '.rar')):
            if b'<html' in content_snippet or b'<!doctype' in content_snippet:
                return False # यह एक एरर पेज है जो 200 OK दे रहा है
            return True # यह असली बाइनरी फाइल है

        # Default: अगर कोई और फाइल है और साइज फिल्टर पास है, तो True
        return True

    def check_file(self, args):
        folder, filename = args
        # URL बनाएं (डबल स्लैश हटाएं)
        clean_folder = folder.strip('/')
        if clean_folder:
            url = f"{self.target}/{clean_folder}/{filename}"
        else:
            url = f"{self.target}/{filename}"

        try:
            # [UPGRADE 3] GET request with Stream (Memory Efficient)
            # stream=True का मतलब पूरी फाइल डाउनलोड नहीं होगी, सिर्फ हेडर और थोड़ा कंटेंट
            r = requests.get(url, proxies=self.proxies, headers=self.headers, timeout=5, stream=True, verify=False)
            
            # --- STATUS CHECK ---
            if r.status_code != 200:
                return None

            # --- SIZE CHECK (Soft 404) ---
            file_size = len(r.content) # यहाँ छोटा कंटेंट ही आएगा क्योंकि हमने read नहीं किया पूरा
            # नोट: stream=True में content-length हेडर चेक करना बेहतर है, 
            # लेकिन सटीकता के लिए हम content पढ़ रहे हैं
            
            if self.soft_404_size > 0 and abs(file_size - self.soft_404_size) < 200:
                return None # यह नकली है

            # --- CONTENT VALIDATION ---
            if self.validate_content(r, filename):
                print_status(f"CRITICAL ASSET EXPOSED: {url} (Size: {file_size})", "danger")
                return {
                    "title": f"Sensitive Asset: {filename}",
                    "severity": "Critical",
                    "desc": f"Verified Asset at {url} | Size: {file_size}",
                    "url": url
                }
        except Exception:
            pass
        return None

    def probe_deep(self):
        findings = []
        tasks = []

        # सभी फोल्डर्स और फाइलों का कॉम्बिनेशन बनाएं
        for path in self.paths:
            print_status(f"Scanning Directory: {path} with 30+ payloads...", "info")
            for category, files in self.loot_map.items():
                for file in files:
                    tasks.append((path, file))

        # [UPGRADE 4] Multi-Threading (20x Faster)
        # 20 वर्कर्स एक साथ अटैक करेंगे
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(self.check_file, tasks)
            
            for res in results:
                if res:
                    findings.append(res)

        return findings
