# engines/api_miner.py
import re
import requests
from core.display import print_status

class APIMiner:
    def __init__(self, target_url, proxies=None):
        self.target = target_url
        self.proxies = proxies

    def extract_secrets(self, js_url):
        print_status(f"Mining API Secrets from: {js_url}", "info")
        try:
            r = requests.get(js_url, proxies=self.proxies, timeout=10)
            content = r.text
            
            # 1. Supabase URL and Key Patterns
            supabase_url = re.findall(r'https://[a-z0-9]{20}\.supabase\.co', content)
            supabase_key = re.findall(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9._-]+', content)

            # 2. Razorpay Key Patterns
            rzp_keys = re.findall(r'rzp_(?:live|test)_[a-zA-Z0-9]{14}', content)

            findings = []
            if supabase_url:
                findings.append({"title": "Supabase Endpoint Found", "severity": "Medium", "desc": supabase_url[0]})
            if supabase_key:
                findings.append({"title": "Supabase Anon Key Found", "severity": "High", "desc": "Check for DB permissions!"})
            if rzp_keys:
                findings.append({"title": "Razorpay Key Found", "severity": "Medium", "desc": rzp_keys[0]})

            return findings
        except Exception as e:
            return []
