import requests
import re
# Try/Except taaki core.display na hone par crash na ho
try:
    from core.display import print_status
except ImportError:
    def print_status(msg, type="info"):
        print(f"[{type.upper()}] {msg}")

class MorandaRecon:
    def __init__(self):
        self.crt_sh_url = "https://crt.sh/?q=%.{}&output=json"

    def get_subdomains(self, domain):
        print_status(f"🛰️ Satellites positioning over: {domain}...", "info")
        subdomains = set()
        
        # 1. Ask crt.sh (Certificate Transparency Logs)
        try:
            url = self.crt_sh_url.format(domain)
            # User-Agent lagana zaruri hai taaki block na ho
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            req = requests.get(url, headers=headers, timeout=20)
            
            if req.status_code == 200:
                data = req.json()
                for entry in data:
                    name_value = entry['name_value']
                    # New lines ko handle karein
                    names = name_value.split('\n')
                    for name in names:
                        # Sirf valid subdomains rakhein (remove *. wildcards)
                        if "*" not in name and domain in name:
                            subdomains.add(name.lower())
                            
                print_status(f"✅ crt.sh found {len(subdomains)} subdomains.", "success")
            else:
                print_status(f"⚠️ crt.sh failed with status {req.status_code}", "warning")
                
        except Exception as e:
            print_status(f"❌ Recon Error: {str(e)}", "warning")

        # 2. HackerTrick: RapidDNS (Optional backup source)
        # Agar crt.sh fail ho jaye to hum RapidDNS use kar sakte hain (future upgrade)

        return list(subdomains)

    def filter_live_subdomains(self, subdomains):
        # Ye function check karega ki kaunse subdomain zinda hain
        print_status(f"🔍 Checking which subdomains are ALIVE...", "info")
        live_subs = []
        
        for sub in subdomains:
            try:
                # Sirf Head request bhejo (Fastest way)
                requests.head(f"https://{sub}", timeout=3)
                print_status(f"🟢 LIVE: {sub}", "success")
                live_subs.append(sub)
            except:
                try:
                    # Agar HTTPS fail ho to HTTP try karo
                    requests.head(f"http://{sub}", timeout=3)
                    print_status(f"🟢 LIVE: {sub}", "success")
                    live_subs.append(sub)
                except:
                    pass
                    
        return live_subs
