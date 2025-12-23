# core/stealth.py
import requests
import random
import time
from core.display import print_status

class StealthManager:
    def __init__(self):
        self.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        # असली ब्राउज़र्स की लिस्ट
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/119.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
        ]

    def get_random_headers(self):
        """हर बार एक नया पहचान पत्र (Header) बनाएगा"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': random.choice(['https://www.google.com/', 'https://www.bing.com/', 'https://duckduckgo.com/']),
            'DNT': '1', # Do Not Track
            'Connection': 'keep-alive'
        }

    def check_tor(self):
        try:
            r = requests.get('https://check.torproject.org/api/ip', proxies=self.proxies, timeout=10)
            if r.status_code == 200:
                print_status(f"Tor Active | IP: {r.json().get('IP')}", "success")
                return True
        except:
            print_status("Tor not detected! OpSec compromised.", "danger")
            return False

    def get_proxies(self):
        return self.proxies
