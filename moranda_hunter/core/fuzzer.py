import requests
import concurrent.futures
from urllib.parse import urljoin
import random
import string
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from core.display import print_status
except ImportError:
    def print_status(msg, type="info"):
        print(f"[{type.upper()}] {msg}")

class MorandaFuzzer:
    def __init__(self):
        # [UPGRADE 1] The "High-Kill" Wordlist (Dangerous Paths Only)
        self.base_paths = [
            # Configs & Secrets
            ".env", ".git/HEAD", ".git/config", "config.php", "wp-config.php", 
            "docker-compose.yml", "package.json", "composer.json", "auth.json",
            "server-status", "nginx.conf", "web.config", "sftp-config.json",
            "id_rsa", "id_rsa.pub", "backup.sql", "dump.sql", "database.sql",
            
            # Admin & Backdoors
            "admin", "administrator", "login", "dashboard", "cpanel", "shell.php",
            "cmd.php", "test.php", "phpinfo.php", "dev", "staging", "api",
            
            # Cloud & Modern Tech
            "actuator/health", "actuator/env", "actuator/heapdump", # Spring Boot
            ".aws/credentials", ".azure/credentials", "metadata/v1.json",
            "swagger-ui.html", "graphql", "api/v1/users", "console"
        ]
        
        # Smart Mutations (Backups & Old files)
        self.extensions = ["", ".bak", ".old", ".save", ".swp", ".txt", ".zip", ".log", "~"]
        
        # Headers to bypass 403 Forbidden
        self.bypass_headers = [
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': '127.0.0.1'},
            {'X-Rewrite-URL': '/'} # For breaking rewrite rules
        ]
        
        # Soft 404 Baseline (Calibration data)
        self.soft_404_size = None
        self.soft_404_status = None

    def calibrate_soft_404(self, session, target_url):
        """
        [UPGRADE 2] Soft 404 Detection
        Server ko ek fake URL bhejo taaki uska 'Error Pattern' samajh sakein.
        """
        random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        fake_url = urljoin(target_url, random_path)
        
        try:
            res = session.get(fake_url, verify=False, timeout=5)
            self.soft_404_status = res.status_code
            self.soft_404_size = len(res.content)
            # Thoda tolerance (buffer) rakhenge size me (+/- 10%)
            print_status(f"📏 Calibrated Soft 404: Status {self.soft_404_status} | Size {self.soft_404_size}", "info")
        except:
            pass

    def attempt_bypass(self, url, session):
        """
        [UPGRADE 3] 403 Bypass Engine
        Agar darwaza band hai, to khidki se ghusne ki koshish karo.
        """
        for headers in self.bypass_headers:
            try:
                res = session.get(url, headers=headers, verify=False, timeout=5)
                if res.status_code == 200:
                    return f"BYPASSED via {list(headers.keys())[0]}"
            except:
                pass
        return None

    def check_path(self, url, session):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            res = session.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
            
            status = res.status_code
            size = len(res.content)

            # [LOGIC] Filter Soft 404s
            # Agar status code aur size bilkul 'Fake Page' jaisa hai, to ignore karo
            if status == self.soft_404_status:
                # Size tolerance (agar size almost same hai)
                if abs(size - self.soft_404_size) < 20: 
                    return None

            # Result Processing
            if status == 200:
                return {"status": 200, "url": url, "size": size, "msg": "FILE FOUND"}
                
            elif status == 403:
                # Agar 403 hai, to Bypass try karo!
                bypass_success = self.attempt_bypass(url, session)
                if bypass_success:
                    return {"status": 200, "url": url, "size": size, "msg": f"🔥 {bypass_success} 🔥"}
                else:
                    return {"status": 403, "url": url, "size": size, "msg": "FORBIDDEN (Locked)"}
                    
            elif status in [301, 302]:
                return {"status": status, "url": url, "size": size, "msg": "REDIRECT"}

        except:
            pass
        return None

    def generate_payloads(self):
        payloads = set()
        for path in self.base_paths:
            # Add base path
            payloads.add(path)
            # Add mutations only for relevant files
            if not path.startswith("."):
                for ext in self.extensions:
                    if ext: payloads.add(f"{path}{ext}")
        return list(payloads)

    def fuzz(self, target_url):
        print_status(f"🌪️ Launching Chaos Fuzzer on {target_url}...", "info")
        
        session = requests.Session()
        
        # Ensure target ends with /
        if not target_url.endswith("/"):
            target_url += "/"
            
        # 1. Calibration (Zaruri hai!)
        self.calibrate_soft_404(session, target_url)
        
        payloads = self.generate_payloads()
        print_status(f"🔥 Testing {len(payloads)} high-impact payloads with 30 threads...", "info")
        
        findings = []
        
        # 30 Threads for Max Speed on Termux
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_to_url = {
                executor.submit(self.check_path, urljoin(target_url, p), session): p 
                for p in payloads
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    result = future.result()
                    if result:
                        status = result['status']
                        
                        if "BYPASSED" in result['msg']:
                            print_status(f"💰 JACKPOT: {result['url']} -> {result['msg']}", "critical")
                            findings.append(result)
                        elif status == 200:
                            print_status(f"✅ FOUND: {result['url']} (Size: {result['size']})", "success")
                            findings.append(result)
                        elif status == 403:
                            # 403 ko sirf warning me dikhao taaki spam na ho
                            print_status(f"🔒 {result['msg']}: {result['url']}", "warning")
                            findings.append(result)
                            
                except Exception:
                    pass
                    
        return findings
