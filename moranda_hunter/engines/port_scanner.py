import socket
import concurrent.futures
import requests
from core.display import print_status, Colors

class PortScanner:
    def __init__(self, target):
        self.target = target
        # Top interesting ports for Web Hunters
        self.ports = [
            21, 22, 23, 25, 53, 81, 300, 445, 1337, 2082, 2083, 2087, 2095, 2096, 
            3000, 3306, 3389, 4000, 4200, 5000, 5432, 5500, 5800, 5900, 
            6000, 6379, 7000, 7001, 8000, 8001, 8008, 8080, 8081, 8088, 
            8089, 8161, 8443, 8888, 9000, 9001, 9090, 9200, 9443, 10000
        ]
        # Resolve Hostname to IP
        try:
            self.ip = socket.gethostbyname(target)
        except:
            self.ip = None

    def check_port(self, port):
        """Checks if a single port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1) # 1 second timeout (Fast Scan)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            
            if result == 0:
                return port
        except:
            pass
        return None

    def identify_web_service(self, port):
        """Checks if the open port is hosting a Website"""
        protocols = ['http', 'https']
        for proto in protocols:
            url = f"{proto}://{self.target}:{port}"
            try:
                res = requests.get(url, timeout=3, verify=False)
                # Agar valid response mila (bhale hi 403/404 ho)
                if res.status_code:
                    return url
            except:
                pass
        return None

    def scan(self):
        """Main Scan Function"""
        if not self.ip:
            print_status(f"Could not resolve IP for {self.target}", "warning")
            return []

        print_status(f"🚪 Scanning {len(self.ports)} hidden ports on {self.ip}...", "info")
        
        open_ports = []
        
        # 1. Fast Port Scan (Multi-threaded)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.check_port, port): port for port in self.ports}
            
            for future in concurrent.futures.as_completed(futures):
                port = future.result()
                if port:
                    print_status(f"🔓 Port {port} is OPEN", "success")
                    open_ports.append(port)

        # 2. Service Identification (Web Check)
        new_web_targets = []
        if open_ports:
            print_status("🕵️ Checking for hidden web services...", "info")
            for p in open_ports:
                web_url = self.identify_web_service(p)
                if web_url:
                    print_status(f"🌐 Hidden Web Server Found: {web_url}", "critical")
                    new_web_targets.append(web_url)
        
        return new_web_targets

