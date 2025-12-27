import requests
import re
import time
import concurrent.futures  # Race Condition ke liye zaroori hai
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import urllib3

# SSL Warnings disable
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from core.display import print_status
except ImportError:
    def print_status(msg, type="info"):
        print(f"[{type.upper()}] {msg}")

class MorandaVulnScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        # [PAYLOADS]
        self.xss_payloads = [
            "<MorandaXSS>",
            "\"><script>confirm('Moranda')</script>",
            "javascript:confirm('Moranda')"
        ]
        self.sqli_error_payloads = ["'", '"', "')"]
        self.sqli_time_payloads = [
            ("' AND SLEEP(5)--", 5),
            ("'; SELECT PG_SLEEP(5)--", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5)
        ]
        self.ssti_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49")
        ]
        self.lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "file:///etc/passwd"
        ]
        self.sql_errors = [
            "SQL syntax", "mysql_fetch", "syntax error", "ORA-01756",
            "SQLite/JDBCDriver", "System.Data.SqlClient.SqlException",
            "Warning: pg_query"
        ]

    def check_cors(self, url):
        """CORS Misconfiguration Check"""
        try:
            headers = {'Origin': 'https://evil-moranda.com'}
            res = self.session.get(url, headers=headers, timeout=5, verify=False)
            allow_origin = res.headers.get('Access-Control-Allow-Origin')
            allow_creds = res.headers.get('Access-Control-Allow-Credentials')

            if allow_origin and ('evil-moranda' in allow_origin or allow_origin == "null"):
                severity = "CRITICAL" if allow_creds == 'true' else "HIGH"
                return {
                    "type": "CORS Misconfiguration",
                    "severity": severity,
                    "url": url,
                    "details": f"Reflected: {allow_origin} | Creds: {allow_creds}"
                }
        except: pass
        return None

    def check_headers(self, url):
        """Security Headers & Host Injection"""
        findings = []
        try:
            res = self.session.get(url, timeout=5, verify=False)
            if 'X-Frame-Options' not in res.headers:
                findings.append({"type": "Missing X-Frame-Options", "severity": "LOW", "url": url, "details": "Clickjacking risk."})

            try:
                headers = {'X-Forwarded-Host': 'evil-moranda.com'}
                res_host = self.session.get(url, headers=headers, timeout=5, verify=False)
                if 'evil-moranda.com' in res_host.headers.get('Location', ''):
                    print_status("💉 Host Header Injection Found", "critical")
                    findings.append({"type": "Host Header Injection", "severity": "HIGH", "url": url, "details": "Redirects to attacker host."})
            except: pass
        except: pass
        return findings

    def check_rbac_bypass(self, url):
        """[Video 1 Concept] RBAC & Privilege Escalation Tester"""
        findings = []
        admin_headers = {
            'X-Role': 'admin', 'Role': 'admin', 'X-Is-Admin': 'true',
            'Cookie': 'role=admin; is_admin=true; user_role=1'
        }
        try:
            normal_res = self.session.get(url, timeout=5, verify=False)
            admin_res = self.session.get(url, headers=admin_headers, timeout=5, verify=False)
            
            if normal_res.status_code == 403 and admin_res.status_code == 200:
                print_status(f"👑 RBAC Bypass Successful on {url}", "critical")
                findings.append({"type": "Broken Access Control (RBAC Bypass)", "severity": "CRITICAL", "url": url, "details": "Bypassed 403 using admin headers."})
        except: pass
        
        if "delete" in url.lower() or "admin" in url.lower():
            try:
                verbs = ['GET', 'POST', 'HEAD', 'PUT']
                for v in verbs:
                    req = requests.Request(v, url).prepare()
                    res = self.session.send(req, verify=False, timeout=5)
                    if res.status_code == 200 and "access denied" not in res.text.lower():
                        print_status(f"🔓 HTTP Method Bypass ({v}) on {url}", "high")
                        findings.append({"type": "HTTP Verb Tampering", "severity": "HIGH", "url": url, "details": f"Endpoint accessible via {v} method."})
            except: pass
        return findings

    def check_rate_limit_bypass(self, url):
        """[Video 2 Concept] Rate Limit Bypass via Header Spoofing"""
        findings = []
        bypass_headers = [
            {'X-Originating-IP': '127.0.0.1'}, {'X-Forwarded-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'}, {'Client-IP': '127.0.0.1'}
        ]
        try:
            # Proactive check
            for headers in bypass_headers:
                res = self.session.get(url, headers=headers, timeout=5, verify=False)
                # Agar ye request success hoti hai jabki normal user block ho (Simulation logic)
                pass 
        except: pass
        return findings

    def test_race_condition(self, url):
        """[Video 2 Concept] Race Condition (Batch Attack)"""
        findings = []
        # Only test sensitive endpoints
        if any(x in url.lower() for x in ['coupon', 'transfer', 'vote', 'gift', 'redeem']):
            print_status(f"🏎️ Testing Race Condition on {url} (Batch Attack)...", "info")
            
            def send_req(u):
                try: return self.session.post(u, timeout=5, verify=False).status_code
                except: return 500

            try:
                # Launch 10 threads instantly
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(send_req, url) for _ in range(10)]
                    results = [f.result() for f in futures]
                
                success_count = results.count(200)
                if success_count > 1:
                    print_status(f"💣 Possible Race Condition! {success_count}/10 requests succeeded.", "critical")
                    findings.append({
                        "type": "Race Condition (Batch Logic Flaw)",
                        "severity": "CRITICAL",
                        "url": url,
                        "details": f"Server processed {success_count} parallel requests successfully."
                    })
            except: pass
        return findings

    def check_cache_poisoning(self, url):
        """[Video 3 Concept] Weak Caching Policy"""
        try:
            if "user" in url or "profile" in url or "admin" in url:
                res = self.session.get(url, timeout=5, verify=False)
                cc = res.headers.get('Cache-Control', '').lower()
                if not cc or "public" in cc:
                    return [{
                        "type": "Weak Caching Policy",
                        "severity": "MEDIUM",
                        "url": url,
                        "details": "Sensitive endpoint allows caching (Potential Cache Poisoning)."
                    }]
        except: pass
        return []

    def check_idor(self, url):
        """[Extra] IDOR Hunter"""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        numeric_params = {k: v[0] for k, v in params.items() if v[0].isdigit()}
        
        if not numeric_params: return []

        print_status(f"🕵️ Testing IDOR on parameters: {list(numeric_params.keys())}", "info")
        
        try:
            orig_res = self.session.get(url, timeout=5, verify=False)
            orig_len = len(orig_res.content)
        except: return []

        for param, value in numeric_params.items():
            try:
                new_val = str(int(value) - 1)
                new_params = params.copy()
                new_params[param] = new_val
                query_string = urlencode(new_params, doseq=True)
                attack_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))
                
                attack_res = self.session.get(attack_url, timeout=5, verify=False)
                if attack_res.status_code == 200:
                    if abs(len(attack_res.content) - orig_len) < (orig_len * 0.5):
                        if "error" not in attack_res.text.lower():
                            print_status(f"💀 Potential IDOR Found on '{param}'", "critical")
                            findings.append({"type": "IDOR", "severity": "HIGH", "url": attack_url, "details": f"Changed ID {value}->{new_val}."})
            except: pass
        return findings

    def test_ssti(self, url, params, param_name):
        for payload, signature in self.ssti_payloads:
            try:
                new_params = params.copy(); new_params[param_name] = payload
                target_url = self.build_url(url, new_params)
                res = self.session.get(target_url, timeout=5, verify=False)
                if signature in res.text:
                    print_status(f"💥 SSTI Detected in '{param_name}'", "critical")
                    return {"type": "SSTI", "severity": "CRITICAL", "url": target_url, "details": f"Executed {payload}"}
            except: pass
        return None

    def test_sqli_blind(self, url, params, param_name):
        for payload, sleep_time in self.sqli_time_payloads:
            try:
                new_params = params.copy(); new_params[param_name] = payload
                target_url = self.build_url(url, new_params)
                start = time.time()
                self.session.get(target_url, timeout=10, verify=False)
                if (time.time() - start) >= sleep_time:
                    print_status(f"⏳ Blind SQLi Found in '{param_name}'", "critical")
                    return {"type": "Blind SQL Injection", "severity": "CRITICAL", "url": target_url, "details": "Time-based delay successful."}
            except: pass
        return None

    def test_open_redirect(self, url, params, param_name):
        payload = "https://evil-moranda.com"
        try:
            new_params = params.copy(); new_params[param_name] = payload
            target_url = self.build_url(url, new_params)
            res = self.session.get(target_url, timeout=5, verify=False, allow_redirects=False)
            if res.status_code in [301, 302, 307] and "evil-moranda.com" in res.headers.get('Location', ''):
                print_status(f"🚀 Open Redirect Found in '{param_name}'", "medium")
                return {"type": "Open Redirect", "severity": "MEDIUM", "url": target_url, "details": "Redirects to malicious site."}
        except: pass
        return None

    def build_url(self, base_url, params):
        parsed = urlparse(base_url)
        query_string = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

    def inject_params(self, url):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return []

        print_status(f"💉 Engaging Advanced Injector on parameters: {list(params.keys())}", "info")

        for param in params:
            # XSS
            for payload in self.xss_payloads:
                new_params = params.copy(); new_params[param] = payload
                target_url = self.build_url(url, new_params)
                try:
                    res = self.session.get(target_url, timeout=5, verify=False)
                    if payload in res.text:
                        print_status(f"🔥 XSS Found in '{param}'", "high")
                        findings.append({"type": "Reflected XSS", "severity": "HIGH", "url": target_url, "details": "Payload reflected."}); break
                except: pass
            
            # SQLi Error
            for payload in self.sqli_error_payloads:
                new_params = params.copy(); new_params[param] = payload
                target_url = self.build_url(url, new_params)
                try:
                    res = self.session.get(target_url, timeout=5, verify=False)
                    for error in self.sql_errors:
                        if error in res.text:
                            print_status(f"💉 SQLi (Error) in '{param}'", "critical")
                            findings.append({"type": "SQL Injection", "severity": "CRITICAL", "url": target_url, "details": f"Error: {error}"}); break
                except: pass

            # Advanced Logic Checks
            ssti = self.test_ssti(url, params, param); 
            if ssti: findings.append(ssti)

            if any(x in param.lower() for x in ['id', 'user', 'num', 'key']):
                blind = self.test_sqli_blind(url, params, param)
                if blind: findings.append(blind)

            if any(x in param.lower() for x in ['url', 'next', 'goto']):
                redir = self.test_open_redirect(url, params, param)
                if redir: findings.append(redir)

            if any(x in param.lower() for x in ['file', 'path', 'doc']):
                for payload in self.lfi_payloads:
                    new_params = params.copy(); new_params[param] = payload
                    target_url = self.build_url(url, new_params)
                    try:
                        res = self.session.get(target_url, timeout=5, verify=False)
                        if "root:x:0:0" in res.text or "[extensions]" in res.text:
                            print_status(f"📂 LFI Detected in '{param}'", "critical")
                            findings.append({"type": "Local File Inclusion", "severity": "CRITICAL", "url": target_url, "details": "System file read."}); break
                    except: pass
        return findings

    def scan(self, url):
        all_findings = []
        
        # 1. Passive Checks
        cors_bug = self.check_cors(url)
        if cors_bug: all_findings.append(cors_bug)
        all_findings.extend(self.check_headers(url))
        
        # 2. Logic Checks (Videos + IDOR)
        all_findings.extend(self.check_rbac_bypass(url))         # Video 1
        all_findings.extend(self.check_rate_limit_bypass(url))   # Video 2
        all_findings.extend(self.test_race_condition(url))       # Video 2
        all_findings.extend(self.check_cache_poisoning(url))     # Video 3
        
        # 3. Parameter Attacks
        if "?" in url:
            all_findings.extend(self.check_idor(url))            # IDOR Logic
            all_findings.extend(self.inject_params(url))         # Injection
            
        return all_findings
