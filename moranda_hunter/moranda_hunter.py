#!/usr/bin/env python3
import sys
import os
from urllib.parse import urlparse, parse_qs

# Import Custom Modules
try:
    from core.display import print_banner, Colors, print_status, print_separator
    from core.stealth import StealthManager
    from core.ai_brain import MorandaAIBrain
    from engines.recon import ReconEngine
    from engines.reporter import BountyReporter
    from core.js_miner import MorandaJSMiner
    from core.recon import MorandaRecon
    from core.vuln_scanner import MorandaVulnScanner
    from core.crawler import MorandaCrawler
    from core.fuzzer import MorandaFuzzer
    from engines.port_scanner import PortScanner
    
# Optional Modules (Safe Import)
    try: from engines.tech_detect import TechDetector
    except: pass
    try: from engines.poc_gen import POCGenerator
    except: pass

except ImportError as e:
    print(f"Error: Missing modules. Make sure you are in the correct directory. {e}")
    sys.exit(1)

# [HELPER FUNCTION] Soft 404 Baseline Calculator
def get_soft_404_baseline(target_url, proxies=None):
    import requests
    import random
    import string
    from collections import Counter

    print_status("Calibrating Soft 404 Baseline (Sampling 3 random paths)...", "info")
    session = requests.Session()
    session.proxies.update(proxies if proxies else {})
    session.verify = False

    sizes = []
    for _ in range(3):
        try:
            rand_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
            dummy_url = f"{target_url.rstrip('/')}/{rand_path}"
            resp = session.get(dummy_url, timeout=10, allow_redirects=True)
            sizes.append(len(resp.content))
        except Exception:
            continue

    if not sizes:
        print_status("Calibration Failed! (All requests timed out)", "failure")
        return 0

    most_common_size = Counter(sizes).most_common(1)[0][0]
    return most_common_size

# Configuration
AI_KEY = os.getenv("GROQ_API_KEY")

def main():
    print_banner()

    if len(sys.argv) < 2:
        print_status("Usage: python3 moranda_hunter.py <url>", "warning")
        sys.exit(1)

    # [Standardized Variable]
    target_url = sys.argv[1]
    proxies = None

    # TOR SETUP
    use_tor = input(f"{Colors.YELLOW}[?] Enable Tor Ghost Mode? (y/n): {Colors.RESET}").lower()
    if use_tor == 'y':
        stealth = StealthManager()
        if stealth.check_tor():
            proxies = stealth.get_proxies()
        else:
            sys.exit(1)

    # INITIALIZATION
    engine = ReconEngine(target_url, proxies=proxies)
    
    # 1. Calibration
    print_status("Calibrating Moranda Hunter (Soft 404 Detection)...", "info")
    soft_404_size = get_soft_404_baseline(target_url, proxies)
    print_status(f"Baseline Size: {soft_404_size} bytes", "success")

    reporter = BountyReporter(target_url)

    if engine.normalize_target():
        if engine.check_connection():
            all_findings = []

            # DATABASE CONNECTION
            db = None
            try:
                from core.database import HunterDB
                db = HunterDB()
                print_status("CyberMoranda Database: CONNECTED", "success")
            except Exception as e:
                print_status(f"Database Initialization Failed (Skipping DB): {str(e)}", "warning")

            # PHASE 0: SUBDOMAIN RECON
            print_separator("Subdomain Discovery (OSINT)")
            recon = MorandaRecon()
            parsed_domain = urlparse(target_url).netloc
            discovered_subs = recon.get_subdomains(parsed_domain)

            if discovered_subs:
                live_subs = recon.filter_live_subdomains(discovered_subs)
                for s in live_subs:
                    print_status(f"🎯 Asset Discovered: {s}", "success")
                    all_findings.append({"title": f"Live Subdomain Found: {s}", "severity": "INFO", "url": s})
            else:
                print_status("No subdomains found via OSINT.", "warning")


            # PHASE 0.9: PORT SCANNING (The Gatekeeper)
            # Hum check karenge ki kya 8080, 8443 jaise ports par kuch chal raha hai?
            print_separator("Port & Service Discovery")
            
            # Target domain extract karo (https:// hata ke)
            target_domain_only = urlparse(target_url).netloc
            
            port_engine = PortScanner(target_domain_only)
            hidden_web_services = port_engine.scan()
            
            # Agar naye hidden servers mile, to unhe bhi list me daal do!
            if hidden_web_services:
                for service in hidden_web_services:
                    all_findings.append({
                        "title": f"Hidden Service Discovered: {service}",
                        "severity": "HIGH",
                        "url": service,
                        "details": "Web server running on non-standard port."
                    })
                    # [CRITICAL] Is naye URL ko bhi aage scan hone ke liye list me daalo
                    # Note: targets_to_scan list hum niche banayenge, usme ye add honge
            

            # PHASE 1: TECH RECON
            engine.detect_waf()
            print_separator("Technology Fingerprinting")
            try:
                fingerprinter = TechDetector(target_url, proxies=proxies, headers=engine.headers)
                technologies = fingerprinter.detect()
                for tech in technologies:
                    all_findings.append({
                        "title": f"Technology Detected: {tech}",
                        "severity": "INFO",
                        "desc": "Identified via Advanced Fingerprinting"
                    })
            except Exception as e:
                print_status(f"Tech Detection Failed: {str(e)}", "warning")

            all_findings.extend(engine.scan_pii())

            # PHASE 2: JS MINING
            print_separator("JavaScript Intelligence")
            current_target = target_url
            
            js_assets = engine.discover_assets()

            if js_assets:
                miner = MorandaJSMiner()
                js_findings = miner.hunt(current_target, js_assets)
                all_findings.extend(js_findings)
                if js_findings and db:
                    db.save_scan(target_url, js_findings, "JS API Mining")
            else:
                print_status("No JS assets discovered.", "warning")

            # PHASE 2.5: DEEP CRAWLING
            print_separator("Deep Web Crawling")
            crawler = MorandaCrawler()
            
            internal_links, juicy_links = crawler.crawl(target_url)
            
            if juicy_links:
                for link in juicy_links:
                    all_findings.append({
                        "type": "Juicy Parameter Found", 
                        "severity": "MEDIUM", 
                        "url": link,
                        "details": "Potential SSRF/Open Redirect parameter detected."
                    })

            # List for Vuln Scanner
            # Main Target + Crawler Links + Hidden Ports
            targets_to_scan = [target_url] + juicy_links + (hidden_web_services if 'hidden_web_services' in locals() else [])

            # PHASE 2.7: DEEP DIRECTORY DISCOVERY (The Chaos Fuzzer)
            print_separator("Deep Directory Discovery (Chaos Mode)")
            
            fuzzer = MorandaFuzzer()
            dir_findings = fuzzer.fuzz(target_url)
            
            if dir_findings:
                for d in dir_findings:
                    all_findings.append({
                        "type": f"Sensitive File Found ({d['msg']})",
                        "severity": "CRITICAL" if "JACKPOT" in d['msg'] else "HIGH",
                        "url": d['url'],
                        "details": f"Status: {d['status']} | Size: {d['size']} bytes"
                    })
                if db:
                    db.save_scan(target_url, dir_findings, "Chaos Fuzzer Findings")
            else:
                print_status("No hidden files found.", "info")

            # PHASE 3: VULNERABILITY SCANNING (Multi-Target & Parameters)
            print_separator(f"Active Vulnerability Scan on {len(targets_to_scan)} Endpoints")
            
            # Using 'The Destroyer' v3.0 Scanner
            vuln_scanner = MorandaVulnScanner()
            
            for t_url in targets_to_scan:
                print_status(f"⚔️ Testing: {t_url}", "info")
                vuln_findings = vuln_scanner.scan(t_url)
                if vuln_findings:
                    all_findings.extend(vuln_findings)
            
            if all_findings and db:
                db.save_scan(target_url, all_findings, "Full Recon Scan")

            # PHASE 4: AI ANALYSIS
            ai_report = "AI Analysis Unavailable"
            if all_findings:
                print_separator("Cyber Intelligence (AI)")
                print_status("Consulting Moranda AI (Llama 3)...", "info")
                try:
                    ai_brain = MorandaAIBrain(AI_KEY)
                    ai_report = ai_brain.analyze_findings(all_findings)
                    print(f"\n{Colors.CYAN}[AI ADVICE]:\n{ai_report}{Colors.RESET}")
                    # AI report ko bhi findings list me add kar do taaki HTML report me dikhe
                    all_findings.append({
                        "title": "AI Strategic Analysis",
                        "severity": "INFO",
                        "url": "AI-BRAIN",
                        "details": ai_report
                    })
                except Exception as e:
                    print_status(f"AI Failed: {str(e)}", "warning")

            # PHASE 5: FINALIZING (Fixed HTML Generation)
            print_separator("Finalizing Mission")
            
            if db:
                try:
                    db.save_scan(target_url, all_findings, ai_report)
                    print_status("Intel archived in Database.", "success")
                except Exception as e:
                    print_status(f"DB Save Failed: {str(e)}", "warning")

            # [FIXED LINE] Pass 'all_findings' here
            report_file = reporter.generate_report(all_findings)
            
            print(f"\n{Colors.GREEN}[+] MORANDA HUNTER: Mission Successful.{Colors.RESET}")
            if report_file:
                print(f"{Colors.YELLOW}[+] 📄 HTML Report Ready: {report_file}{Colors.RESET}")

if __name__ == "__main__":
    main()
