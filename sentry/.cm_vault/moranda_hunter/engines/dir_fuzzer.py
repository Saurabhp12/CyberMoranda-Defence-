import requests
import concurrent.futures
from core.display import print_status
from core.validator import SmartValidator #

class DirFuzzer:
    def __init__(self, target, proxies=None, headers=None):
        self.target = target.rstrip('/')
        self.proxies = proxies
        self.headers = headers
        # क्रिटिकल पाथ्स जिन्हें हम स्कैन करेंगे
        self.wordlist = [
            'admin', 'backup', 'config', 'dev', 'staging', 'test',
            '.git/config', '.env', 'phpinfo.php', 'db_backup.sql',
            'api/v1', 'server-status', 'wp-config.php.bak'
        ]

    def check_path(self, path):
        url = f"{self.target}/{path}"
        try:
            # हम GET का उपयोग कर रहे हैं ताकि स्मार्ट वैलिडेशन के लिए कंटेंट पढ़ सकें
            r = requests.get(url, proxies=self.proxies, headers=self.headers, timeout=5, verify=False)
            
            if r.status_code == 200:
                validator = SmartValidator()
                validation_result = validator.analyze_page(r.text) #
                
                # अगर यह केवल एक यूजर प्रोफाइल है (जैसे collabstr पर हुआ), तो इसे इग्नोर करें
                if "False Positive" in validation_result:
                    return None
                
                print_status(f"VALIDATED ASSET: /{path} ({validation_result})", "success")
                return {
                    "title": f"Validated Asset: /{path}",
                    "severity": "Critical" if "Real" in validation_result else "Medium",
                    "desc": f"Status 200 discovered at {url} - Verified as: {validation_result}"
                }
                
            elif r.status_code in [403, 301]:
                # 403 और 301 को हम 'Potential' मानकर रिपोर्ट करेंगे
                print_status(f"HIDDEN PATH FOUND: /{path} (Status: {r.status_code})", "warning")
                return {
                    "title": f"Potential Hidden Path: /{path}",
                    "severity": "Low",
                    "desc": f"Status {r.status_code} discovered at {url}"
                }
        except Exception as e:
            pass
        return None

    def start_fuzzing(self):
        findings = []
        # 10 थ्रेड्स के साथ मल्टी-थ्रेडेड स्कैनिंग
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(self.check_path, self.wordlist))
            findings = [r for r in results if r is not None]
        return findings
