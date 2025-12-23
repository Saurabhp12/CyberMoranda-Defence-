import requests
from core.display import print_status

class HunterFuzzer:
    def __init__(self, user_agent, proxies=None):
        self.user_agent = user_agent
        self.proxies = proxies

    def test_xss(self, base_url, params):
        print_status("Fuzzing for XSS vulnerabilities...", "info")
        findings = []
        payload = "<script>alert('Moranda')</script>"
        for p in params:
            test_data = params.copy()
            test_data[p] = payload
            try:
                r = requests.get(base_url, params=test_data, proxies=self.proxies, 
                                 headers={'User-Agent': self.user_agent}, timeout=7, verify=False)
                if payload in r.text:
                    print_status(f"CONFIRMED XSS: Parameter '{p}'", "danger")
                    findings.append({"title": f"XSS on {p}", "severity": "High", "desc": "Reflected Payload"})
            except: continue
        return findings

    def test_sqli(self, base_url, params):
        print_status("Fuzzing for SQL Injection (Error Based)...", "info")
        findings = []
        payload = "'"
        errors = ["SQL syntax", "mysql_fetch", "PostgreSQL query failed", "Oracle Error"]
        for p in params:
            test_data = params.copy()
            test_data[p] = payload
            try:
                r = requests.get(base_url, params=test_data, proxies=self.proxies, 
                                 headers={'User-Agent': self.user_agent}, timeout=7, verify=False)
                if any(err in r.text for err in errors):
                    print_status(f"CONFIRMED SQLi: Parameter '{p}'", "danger")
                    findings.append({"title": f"SQLi on {p}", "severity": "Critical", "desc": "Database Error Triggered"})
            except: continue
        return findings
