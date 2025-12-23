# engines/js_scanner.py
import concurrent.futures
import requests
import re
from core.display import print_status

class JSScanner:
    def __init__(self, proxies=None, headers=None):
        self.proxies = proxies
        self.headers = headers
        # संवेदनशील डेटा के लिए Regex Patterns
        self.patterns = {
            "Google API Key": r'AIza[0-9A-Za-z\\-_]{35}',
            "Generic Secret": r'(?i)(key|secret|token|auth|password)\s*[:=]\s*["\']([a-zA-Z0-9\-_]{16,})["\']',
            "IP Address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }

    def scan_url(self, js_url):
        """एक सिंगल JS फाइल को स्कैन करने का लॉजिक"""
        findings = []
        try:
            r = requests.get(js_url, proxies=self.proxies, headers=self.headers, timeout=10, verify=False)
            if r.status_code == 200:
                for name, pattern in self.patterns.items():
                    matches = re.findall(pattern, r.text)
                    for match in set(matches):
                        val = match[1] if isinstance(match, tuple) else match
                        print_status(f"JS SECRET FOUND: {name} in {js_url.split('/')[-1]}", "danger")
                        findings.append({
                            "title": f"JS Secret: {name}", 
                            "severity": "High", 
                            "desc": f"Exposed in {js_url}"
                        })
        except:
            pass
        return findings

    def fast_scan(self, js_assets):
        """मल्टी-थ्रेडिंग इंजन (Turbo Mode) जो एरर को फिक्स करेगा"""
        all_results = []
        # एक साथ 10 फाइल्स को स्कैन करने के लिए Workers खड़ा करें
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Map का इस्तेमाल करके सभी URLs को वर्कर्स में बाँट दें
            results = list(executor.map(self.scan_url, js_assets))
            for r in results:
                all_results.extend(r)
        return all_results

