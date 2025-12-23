# engines/subdomain.py
import requests
from core.display import print_status, print_separator

class SubdomainHunter:
    def __init__(self, domain, proxies=None, headers=None):
        self.domain = domain
        self.proxies = proxies
        self.headers = headers
        # कॉमन सबडोमेन्स की एक छोटी लिस्ट (इसे तुम बड़ा कर सकते हो)
        self.wordlist = ['dev', 'api', 'admin', 'staging', 'test', 'staff', 'vpn', 'mail', 'cdn', 'shop']
    def start_scan(self):
        print_separator("Subdomain Discovery")
        found_subdomains = []
        
        print_status(f"Bruteforcing subdomains for {self.domain}...", "info")
        
        for sub in self.wordlist:
            subdomain = f"{sub}.{self.domain}"
            url = f"https://{subdomain}"
            try:
                # हम सिर्फ हेडर रिक्वेस्ट भेजेंगे ताकि स्कैन तेज़ हो
                r = requests.head(url, proxies=self.proxies, headers=self.headers, timeout=5, verify=False)
                if r.status_code < 400:
                    print_status(f"SUBDOMAIN FOUND: {subdomain} (Status: {r.status_code})", "success")
                    found_subdomains.append(url)
            except:
                continue
        
        if not found_subdomains:
            print_status("No common subdomains discovered via bruteforce.", "info")
            
        return found_subdomains
