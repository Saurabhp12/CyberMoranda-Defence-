import requests
from core.display import print_status

class PayloadInjector:
    def __init__(self, proxies=None, headers=None):
        self.proxies = proxies
        self.headers = headers
        # बेसिक सेफ्टी पेलोड्स
        self.sqli_payloads = ["'", "1' OR '1'='1", '" OR 1=1--']
        self.xss_payloads = ["<script>alert('Moranda')</script>", "';alert(1)//"]

    def test_endpoint(self, url, params):
        findings = []
        for param in params:
            print_status(f"Injecting safety probes into parameter: {param}", "info")
            
            # 1. SQLi Testing
            for payload in self.sqli_payloads:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    r = requests.get(url, params=test_params, proxies=self.proxies, headers=self.headers, timeout=5)
                    # SQL एरर मैसेज की तलाश
                    if any(error in r.text.lower() for error in ["sql syntax", "mysql_fetch", "sqlite3.error"]):
                        print_status(f"POTENTIAL SQLi DETECTED on {param}!", "danger")
                        findings.append({
                            "title": "Potential SQL Injection",
                            "severity": "Critical",
                            "desc": f"Parameter '{param}' reflected SQL error with payload: {payload}"
                        })
                        break 
                except: pass

            # 2. XSS Testing
            for payload in self.xss_payloads:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    r = requests.get(url, params=test_params, proxies=self.proxies, headers=self.headers, timeout=5)
                    if payload in r.text:
                        print_status(f"XSS REFLECTION FOUND on {param}!", "warning")
                        findings.append({
                            "title": "Reflected XSS Detected",
                            "severity": "High",
                            "desc": f"Payload reflected in response for parameter '{param}'"
                        })
                        break
                except: pass
        return findings
