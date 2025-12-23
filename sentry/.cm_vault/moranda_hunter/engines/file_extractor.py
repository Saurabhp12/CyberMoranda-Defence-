# engines/file_extractor.py
import requests
import os
from core.display import print_status

class FileExtractor:
    def __init__(self, target, discovered_paths, proxies=None, headers=None):
        self.target = target.rstrip('/')
        self.paths = discovered_paths  # DirFuzzer से मिले 200 OK पाथ्स
        self.proxies = proxies
        self.headers = headers
        # 'Gold Mine' फाइल्स की लिस्ट
        self.target_files = [
            'backup.zip', 'db.sql', 'database.sql', '.env', 
            'config.php.bak', 'site_backup.tar.gz', 'dump.sql'
        ]
        # डाउनलोड फोल्डर बनाना
        self.save_path = "loot_captured"
        if not os.path.exists(self.save_path):
            os.makedirs(self.save_path)

    def extract_intel(self):
        findings = []
        for path in self.paths:
            base_folder = path.strip('/')
            print_status(f"Searching for downloadable loot in /{base_folder}...", "info")
            
            for file_name in self.target_files:
                file_url = f"{self.target}/{base_folder}/{file_name}"
                try:
                    # फाइल का साइज चेक करने के लिए HEAD रिक्वेस्ट
                    r = requests.head(file_url, proxies=self.proxies, headers=self.headers, timeout=5)
                    
                    if r.status_code == 200:
                        print_status(f"CRITICAL ASSET DETECTED: {file_name}", "danger")
                        
                        # फाइल को लोकली सेव करना (केवल छोटी फाइलें जैसे .env या .sql के लिए)
                        # बड़ी फाइलों के लिए हम सिर्फ अलर्ट देंगे
                        findings.append({
                            "title": f"Downloadable Backup: {file_name}",
                            "severity": "Critical",
                            "desc": f"Found at: {file_url}"
                        })
                except:
                    pass
        return findings
