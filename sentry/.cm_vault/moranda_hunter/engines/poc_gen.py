# engines/poc_gen.py
import urllib.parse
from core.display import print_status

class POCGenerator:
    def __init__(self, target, findings):
        self.target = target
        self.findings = findings

    def generate_evidence(self):
        print_status("Generating automated Proof-of-Concept (POC) evidence...", "info")
        pocs = []
        
        for f in self.findings:
            title = f.get('title', 'Unknown Issue')
            desc = f.get('desc', '')
            
            # 1. XSS POC Generation (Clickable Links)
            if "XSS" in title:
                # पेलोड को URL से एक्सट्रैक्ट करना
                payload = desc.split('payload: ')[-1] if 'payload: ' in desc else ''
                param = desc.split("'")[1] if "'" in desc else ''
                
                if payload and param:
                    poc_url = f"{self.target.split('?')[0]}?{param}={urllib.parse.quote(payload)}"
                    pocs.append({
                        "type": "Reflected XSS POC",
                        "evidence": f"Click to Verify: {poc_url}"
                    })

            # 2. SQLi POC Generation (Curl Commands)
            elif "SQL" in title:
                poc_cmd = f"curl -G \"{self.target.split('?')[0]}\" --data-urlencode \"{desc.split('Parameter ')[-1].split(' ')[0]}\"=\"'\""
                pocs.append({
                    "type": "SQL Injection POC",
                    "evidence": f"Run Command: {poc_cmd}"
                })

            # 3. Sensitive Asset POC (Status 200 Verification)
            elif "Sensitive Asset" in title or "Validated Asset" in title:
                path_url = desc.split('at ')[-1] if 'at ' in desc else ''
                if path_url:
                    pocs.append({
                        "type": "Information Disclosure POC",
                        "evidence": f"Direct Access: {path_url}"
                    })

        return pocs
