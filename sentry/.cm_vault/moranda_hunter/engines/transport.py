import ssl
import socket
import datetime
from core.display import UI

class TransportEngine:
    def __init__(self, brain):
        self.brain = brain
        self.ui = UI()

    def scan_tls(self, hostname):
        """Module 7: TLS & Transport (Upgrade 61, 67, 69)"""
        print(f"{self.ui.Y}[*] Module 7: Analyzing Transport Layer Security...{self.ui.RESET}")
        
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Upgrade 67: Cert expiry risk
                    exp_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    days_to_expire = (exp_date - datetime.datetime.now()).days
                    
                    if days_to_expire < 30:
                        self.ui.print_finding(f"Cert Exiring Soon: {days_to_expire} days left", "MEDIUM", "100%")
                        self.brain.add_finding("SSL Cert Expiry Risk", "MEDIUM", "Transport", "production", 1.0)
                    
                    # Upgrade 61: TLS version check
                    version = ssock.version()
                    print(f" {self.ui.BOLD}└─ TLS Version:{self.ui.RESET} {version}")
                    
                    if "TLSv1.1" in version or "TLSv1.0" in version:
                        self.ui.print_finding(f"Weak TLS Version: {version}", "HIGH", "100%")
                        self.brain.add_finding("Weak TLS Protocol", "HIGH", "Transport", "production", 1.0)

        except Exception as e:
            print(f"{self.ui.R}[!] TLS Scan Failed: {str(e)}{self.ui.RESET}")
