# engines/sensitive_prober.py
import requests
from core.display import print_status

class SensitiveProber:
    def __init__(self, target, discovered_paths, proxies=None, headers=None):
        self.target = target.rstrip('/')
        self.paths = discovered_paths # DirFuzzer से मिले 200 OK पाथ्स
        self.proxies = proxies
        self.headers = headers
        # क्रिटिकल फाइल्स जिन्हें हम हर फोल्डर में ढूंढेंगे
        self.critical_files = ['.env', 'db.sql', 'backup.zip', 'config.php.bak', '.git/config']

    def probe_deep(self): # <--- सुनिश्चित करें कि नाम 'probe_deep' ही है
        findings = []
        for path in self.paths:
            base_folder = path.strip('/')
            print_status(f"Probing deeper into: /{base_folder}", "info")
            
            for file in self.critical_files:
                url = f"{self.target}/{base_folder}/{file}"
                try:
                    # केवल हेडर्स चेक करें (HEAD) ताकि क्लाउडफ्लेयर को शक न हो
                    r = requests.head(url, proxies=self.proxies, headers=self.headers, timeout=5, verify=False)
                    if r.status_code == 200:
                        print_status(f"CRITICAL ASSET EXPOSED: {url}", "danger")
                        findings.append({
                            "title": f"Sensitive Asset: {file}", 
                            "severity": "Critical", 
                            "desc": f"Found at {url}"
                        })
                except:
                    pass
        return findings
