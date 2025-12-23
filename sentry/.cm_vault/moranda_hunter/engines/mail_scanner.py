# engines/mail_scanner.py
import dns.resolver
import socket
from core.display import print_status

class MailScanner:
    def __init__(self, target_domain):
        self.domain = target_domain.replace('https://', '').replace('http://', '').split('/')[0]

    def scan_records(self):
        findings = []
        print_status(f"Analyzing Mail Infrastructure for: {self.domain}", "info")
        
        # 1. MX Record Discovery (ईमेल गेटवे की पहचान)
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            for rdata in mx_records:
                print_status(f"MX Record Found: {rdata.exchange}", "success")
                findings.append({"title": "Mail Server Found", "severity": "Info", "desc": str(rdata.exchange)})
        except:
            print_status("No MX records found.", "warning")

        # 2. SPF Record Check (स्पूफिंग सुरक्षा जाँच)
        try:
            spf_records = dns.resolver.resolve(self.domain, 'TXT')
            spf_found = False
            for rdata in spf_records:
                if "v=spf1" in str(rdata):
                    spf_found = True
                    print_status(f"SPF Record Detected: {rdata}", "info")
            if not spf_found:
                print_status("VULNERABILITY: Missing SPF Record!", "danger")
                findings.append({"title": "Missing SPF Record", "severity": "High", "desc": "Domain is vulnerable to email spoofing."})
        except: pass

        # 3. SMTP Banner Grabbing (Port 25)
        try:
            s = socket.socket(socket.socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.domain, 25))
            banner = s.recv(1024).decode().strip()
            print_status(f"SMTP Banner: {banner}", "success")
            findings.append({"title": "SMTP Banner Disclosed", "severity": "Low", "desc": banner})
            s.close()
        except:
            print_status("SMTP Port 25 closed or filtered.", "info")

        return findings
