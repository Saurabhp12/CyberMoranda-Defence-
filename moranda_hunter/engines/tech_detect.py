import requests
import re
import hashlib
from core.display import print_status

class TechDetector:
    def __init__(self, target, proxies=None, headers=None):
        self.target = target
        self.proxies = proxies
        self.headers = headers
        self.session = requests.Session()
        if headers: self.session.headers.update(headers)
        if proxies: self.session.proxies.update(proxies)
        self.session.verify = False

        # [UPGRADE 1] Massive Signature Database
        self.signatures = {
            "CMS": {
                "WordPress": [r"wp-content", r"wp-includes", r"xmlrpc.php", r"wp-json"],
                "Joomla": [r"Joomla!", r"/templates/", r"option=com_content"],
                "Drupal": [r"Drupal", r"jQuery.extend\(Drupal", r"/sites/default/files"],
                "Magento": [r"Mage\.Cookies", r"static/version"],
                "Ghost": [r"ghost-sdk", r"generator=\"Ghost"],
                "Wix": [r"wix-warmup-data", r"wix-public"],
                "Shopify": [r"Shopify\.shop", r"cdn\.shopify\.com"]
            },
            "Framework": {
                "Laravel": [r"X-XSRF-TOKEN", r"laravel_session"],
                "Django": [r"csrftoken", r"__admin__", r"csrfmiddlewaretoken"],
                "React": [r"react-dom", r"react-scripts", r"data-reactroot"],
                "Vue.js": [r"vue-router", r"data-v-", r"vuex"],
                "Angular": [r"ng-version", r"app-root", r"ng-content"],
                "Spring Boot": [r"X-Application-Context", r"Whitelabel Error Page"],
                "Flask": [r"werkzeug", r"flask"],
                "ASP.NET": [r"__VIEWSTATE", r"asp\.net", r"X-AspNet-Version"]
            },
            "Server": {
                "Cloudflare": [r"cf-ray", r"__cfduid", r"cf-cache-status"],
                "AWS": [r"x-amz-", r"s3.amazonaws.com", r"AWSALB"],
                "Nginx": [r"nginx"],
                "Apache": [r"Apache"],
                "LiteSpeed": [r"LiteSpeed"],
                "OpenResty": [r"openresty"]
            },
            "Lang": {
                "PHP": [r"PHPSESSID", r"\.php"],
                "Java": [r"JSESSIONID", r"\.jsp", r"\.do"],
                "Python": [r"python", r"gunicorn"],
                "Ruby": [r"Phusion Passenger", r"X-Rack-Cache"]
            }
        }

    # [UPGRADE 2] Cookie Analysis
    def analyze_cookies(self, cookie_jar):
        detected = []
        for cookie in cookie_jar:
            name = cookie.name.upper()
            if "PHP" in name: detected.append("PHP")
            if "JSESSION" in name: detected.append("Java (JSP/Servlet)")
            if "ASP" in name: detected.append("ASP.NET")
            if "LARAVEL" in name or "XSRF" in name: detected.append("Laravel")
            if "DJANGO" in name: detected.append("Django")
            if "RAILS" in name: detected.append("Ruby on Rails")
        return list(set(detected))

    # [UPGRADE 3] Robots.txt & Hidden Files Probe
    def probe_special_files(self):
        extras = []
        try:
            robots_url = f"{self.target.rstrip('/')}/robots.txt"
            res = self.session.get(robots_url, timeout=5)

            if res.status_code == 200:
                if "wp-admin" in res.text: extras.append("WordPress (via robots.txt)")
                if "option=com_" in res.text: extras.append("Joomla (via robots.txt)")
                if "/node_modules/" in res.text: extras.append("Node.js Environment")
                if "Disallow: /admin/" in res.text: extras.append("Admin Panel Detected")
        except: pass
        return extras

    # [NEW] UPGRADE 4: Server Unmasking (BWA Hunter)
    def unmask_server(self):
        """
        Deep Dive: Force the server to reveal its true identity (Nginx/Apache/IIS)
        by sending malformed requests.
        """
        fingerprints = []
        print_status("⚔️ Launching Active Server Unmasking...", "info")

        # 1. Bad Verb Attack (The Confusion Method)
        try:
            # Send nonsense verb 'JUNK'
            req = requests.Request('JUNK', self.target).prepare()
            res_bad = self.session.send(req, timeout=5, verify=False)
            
            # Check Error Page Body for Leaks
            body_lower = res_bad.text.lower()
            if "nginx" in body_lower:
                fingerprints.append("True Identity: Nginx (Revealed via Bad Verb)")
            elif "apache" in body_lower:
                fingerprints.append("True Identity: Apache (Revealed via Bad Verb)")
            elif "microsoft" in body_lower or "iis" in body_lower:
                fingerprints.append("True Identity: IIS (Revealed via Bad Verb)")
        except: pass

        # 2. Long URL Attack (Buffer Overflow Probe)
        try:
            # Send 5000 chars
            long_path = "/" + "A" * 5000
            res_long = self.session.get(self.target + long_path, timeout=5, verify=False)
            
            # Nginx 414 vs AWS 403
            if res_long.status_code == 414 and "nginx" in res_long.text.lower():
                fingerprints.append("True Identity: Nginx (Confirmed via 414 Error)")
            elif res_long.status_code == 403 and "awselb" in res_long.headers.get('Server', '').lower():
                fingerprints.append("Protected by: AWS WAF / ELB")
        except: pass

        return fingerprints

    def detect(self):
        detected_tech = []
        print_status("Fingerprinting target technologies...", "info")

        try:
            # 1. Main Request
            res = self.session.get(self.target, timeout=10, verify=False)
            headers = str(res.headers)
            body = res.text

            # Check Headers
            if 'X-Powered-By' in res.headers:
                tech = res.headers['X-Powered-By']
                detected_tech.append(f"Header Leak: {tech}")
                print_status(f"Server Leak: {tech}", "danger")

            if 'Server' in res.headers:
                detected_tech.append(f"Public Header: {res.headers['Server']}")

            # 2. Signature Matching
            for category, techs in self.signatures.items():
                for tech_name, patterns in techs.items():
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, headers, re.IGNORECASE):
                            if tech_name not in detected_tech:
                                detected_tech.append(tech_name)
                                print_status(f"{category} Detected: {tech_name}", "success")
                                break

            # 3. Cookie Forensics
            cookies = self.analyze_cookies(res.cookies)
            detected_tech.extend(cookies)

            # 4. Special File Probing
            special_finds = self.probe_special_files()
            detected_tech.extend(special_finds)
            
            # 5. [NEW] Active Server Unmasking
            unmasked = self.unmask_server()
            if unmasked:
                for u in unmasked:
                    print_status(f"🎭 Unmasked: {u}", "critical")
                detected_tech.extend(unmasked)

            return list(set(detected_tech))

        except Exception as e:
            return []
