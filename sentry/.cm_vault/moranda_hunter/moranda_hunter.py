#!/usr/bin/env python3
import sys
from urllib.parse import urlparse, parse_qs
from core.display import print_banner, Colors, print_status, print_separator
from core.stealth import StealthManager
from core.ai_brain import MorandaAIBrain
from engines.recon import ReconEngine
from engines.fuzzer import HunterFuzzer
from engines.js_scanner import JSScanner
from engines.subdomain import SubdomainHunter
from engines.reporter import BountyReporter
from engines.mailer import BountyMailer
from engines.dir_fuzzer import DirFuzzer
from engines.sensitive_prober import SensitiveProber
from engines.file_extractor import FileExtractor
from engines.payload_injector import PayloadInjector
from engines.mail_scanner import MailScanner

def main():
    import os
    import sys

    print_banner()

    # Load GROQ API key from environment
    AI_KEY = os.getenv("GROQ_API_KEY")

    if not AI_KEY:
        print_status("GROQ_API_KEY not set in environment", "error")
        sys.exit(1)

    if len(sys.argv) < 2:
        print_status("Usage: python3 moranda_hunter.py <url>", "warning")
        sys.exit(1)

    target = sys.argv[1]
    proxies = None

    use_tor = input(
        f"{Colors.YELLOW}[?] Enable Tor Ghost Mode? (y/n): {Colors.RESET}"
    ).lower()

    if use_tor == 'y':
        stealth = StealthManager()
        if stealth.check_tor():
            proxies = stealth.get_proxies()
        else:
            print_status("Tor not available", "error")
            sys.exit(1)

    # Initialize engine and reporter
    engine = ReconEngine(target, proxies=proxies)
    reporter = BountyReporter(target)

    if engine.normalize_target():
        if engine.check_connection():
            all_findings = []
            # continue your logic here
            
            # --- CRITICAL FIX START ---
            try:
                from core.database import HunterDB
                db = HunterDB() # अब 'db' पूरे फंक्शन में उपलब्ध है
                print_status("CyberMoranda Database: CONNECTED", "success")
            except Exception as e:
                print_status(f"Database Initialization Failed: {str(e)}", "warning")
                db = None # फॉलबैक ताकि क्रैश न हो

            # PHASE 0: Subdomain Reconnaissance
            print_separator("Subdomain Discovery")
            sub_hunter = SubdomainHunter(engine.domain, proxies=proxies, headers=engine.headers)
            discovered_subs = sub_hunter.start_scan() # मान लेते हैं यह लिस्ट लौटाता है
            
            for s in discovered_subs:
                finding = {"title": f"Subdomain Found: {s}", "severity": "Info", "desc": "Active host discovered during recon"}
                all_findings.append(finding)
                
                # ऑटोमैटिक मेल स्कैन अगर सबडोमेन में 'mail' मिले
                if "mail." in s.lower():
                    print_status(f"Mail infrastructure detected on {s}. Launching Mail Intel...", "info")
                    from engines.mail_scanner import MailScanner
                    mail_engine = MailScanner(s)
                    mail_findings = mail_engine.scan_records()
                    all_findings.extend(mail_findings)

            # PHASE 0.5: Deep Sub-Fuzzing (Recursive Discovery)
            print_separator("Recursive Sub-Fuzzing")

            from core.notifications import notifier 

            for s in discovered_subs:
                # 'Double Protocol' फिक्स
                sub_url = s if s.startswith("http") else f"https://{s}"
                print_status(f"Launching Deep Fuzzing on Subdomain: {sub_url}", "info")

                # 1. वेरिएबल को पहले खाली लिस्ट के रूप में परिभाषित करें (Safety First)
                sub_findings = [] 

                try:
                    # DirFuzzer को इस सबडोमेन के लिए इनिशियलाइज़ करें
                    sub_fuzzer = DirFuzzer(sub_url, proxies=proxies, headers=engine.headers)
                    sub_findings = sub_fuzzer.start_fuzger() # यहाँ असाइनमेंट हो रहा है
                except Exception as e:
                    print_status(f"Fuzzing failed for {s}: {str(e)}", "warning")

                # 2. अब चेक करें, अब यह कभी 'NameError' नहीं देगा
                if sub_findings:
                    print_status(f"CRITICAL: Found {len(sub_findings)} hidden paths on {s}!", "danger")
                    all_findings.extend(sub_findings)

                    # डेटाबेस और नोटिफिकेशन सिंक
                    db.save_scan(sub_url, sub_findings, "Automated Subdomain Deep Scan")
                    notifier.send_alert(
                        title="Critical Loot Detected!",
                        message=f"Moranda Hunter found {len(sub_findings)} assets on {s}",
                        priority="high"
                    )

            # PHASE 1: Recon
            engine.detect_waf()
            all_findings.extend(engine.scan_pii())
            all_findings.extend(engine.analyze_params())
            all_findings.extend(engine.scan_hidden_files())

            # PHASE 2: JS Mining & Deep API Extraction
            print_separator("JavaScript Intelligence")
            js_assets = engine.discover_assets() # JS फाइलों की लिस्ट प्राप्त करना
            
            if js_assets:
                print_status(f"Found {len(js_assets)} JS files. Launching Multi-threaded Scan...", "info")
                
                # JSScanner अब 'APIMiner' के सीक्रेट पैटर्न्स को भी इस्तेमाल करेगा
                js_worker = JSScanner(proxies=proxies, headers=engine.headers)
                
                # मल्टी-थ्रेडेड स्कैनिंग (V12 Performance)
                # यह फंक्शन एक साथ 5-10 फाइलों को प्रोसेस करेगा
                js_findings = js_worker.fast_scan(js_assets) 
                all_findings.extend(js_findings)

                if js_findings:
                    print_status(f"CRITICAL: Found {len(js_findings)} API secrets in JS assets!", "danger")
                    # 'Loot' को CyberMoranda Database में आर्काइव करें
                    db.save_scan(target, js_findings, "Multi-threaded JS API Mining")
            else:
                print_status("No JS assets discovered for deep mining.", "warning")

            # PHASE 2.7: Deep Directory Discovery
            print_separator("Deep Directory Discovery")
            dfuzzer = DirFuzzer(target, proxies=proxies, headers=engine.headers)
            
            # [FIX]: सुनिश्चित करें कि वेरिएबल का नाम 'dir_findings' ही है
            dir_findings = dfuzzer.start_fuzzing() 
            all_findings.extend(dir_findings)

            # PHASE 2.8: Sensitive Data Probing (Deep Dive)
            # यहाँ अब 'dir_findings' मौजूद है और एरर नहीं आएगा
            valid_paths = [f['title'].split(': ')[1] for f in dir_findings if '200' in f['desc']]
            
            if valid_paths:
                print_separator("Sensitive Asset Probing")
                prober = SensitiveProber(target, valid_paths, proxies=proxies, headers=engine.headers)
                probe_findings = prober.probe_deep()
                all_findings.extend(probe_findings)

            # PHASE 2.9: Smart Intel Extraction (Looting)
            valid_paths = [f['title'].split(': ')[1] for f in dir_findings if '200' in f['desc']]
            if valid_paths:
                print_separator("Sensitive Asset Extraction")
                from engines.file_extractor import FileExtractor
                extractor = FileExtractor(target, valid_paths, proxies=proxies, headers=engine.headers)
                loot_findings = extractor.extract_intel()
                all_findings.extend(loot_findings)

            # PHASE 3: Active Fuzzing & Payload Injection
            parsed = urlparse(target)
            params = parse_qs(parsed.query)

            if params:
                # 3.1: Basic Fuzzing Engine
                print_separator("Active Fuzzing Engine")
                fuzzer = HunterFuzzer(engine.user_agent, proxies=proxies)
                all_findings.extend(fuzzer.test_xss(target.split('?')[0], params))
                all_findings.extend(fuzzer.test_sqli(target.split('?')[0], params))

                # 3.2: Advanced Payload Injection (Active Attack Mode)
                print_separator("Active Payload Injection")
                # के विजन के अनुसार सटीक पेलोड्स का उपयोग
                injector = PayloadInjector(proxies=proxies, headers=engine.headers)
                
                # URL से पैरामीटर्स हटाकर केवल बेस URL भेजें
                base_url = target.split('?')[0]
                injection_results = injector.test_endpoint(base_url, params)
                all_findings.extend(injection_results)
            else:
                print_status("No URL parameters detected. Skipping Phase 3.", "info")

            # --- PHASE 4: AI ANALYSIS (The Cyber Brain) ---
            # इसे सभी स्कैनिंग फेजेस (0-3) के बाद और रिपोर्टिंग (Phase 5) से पहले रखें
            if all_findings:
                print_separator("Cyber Intelligence (AI)")
                print_status("Consulting the CyberMoranda AI (Llama 3)...", "info")

                try:
                    ai_brain = MorandaAIBrain(AI_KEY)
                    ai_report = ai_brain.analyze_findings(all_findings)

                    print(f"\n{Colors.CYAN}[AI ADVICE]:\n{ai_report}{Colors.RESET}")
                    
                    # AI की सलाह को रिपोर्ट में जोड़ें
                    reporter.add_finding("AI Strategic Insight", "Info", ai_report, "Groq Llama-3 Analysis")
                except Exception as e:
                    print_status(f"AI Brain Analysis Failed: {str(e)}", "warning")
                    ai_report = "AI Analysis unavailable for this session."
            else:
                print_status("No findings to analyze. Skipping AI Brain.", "info")


            # PHASE 5: Evidence Collection & Intelligence Archiving
            print_separator("Finalizing Mission Intel")

            # 1. Automated POC Generation (Evidence)
            if all_findings:
                from engines.poc_gen import POCGenerator
                poc_engine = POCGenerator(target, all_findings)
                generated_pocs = poc_engine.generate_evidence()
                
                # रिपोर्ट में साक्ष्य जोड़ना
                for poc in generated_pocs:
                    reporter.add_finding(
                        f"POC: {poc['type']}", 
                        "Info", 
                        poc['evidence'], 
                        "Moranda Hunter Automated POC Engine"
                    )

            # 2. CyberMoranda Database Persistence
            try:
                from core.database import HunterDB
                db = HunterDB()
                final_ai_msg = ai_report if 'ai_report' in locals() else "AI Analysis Unavailable"
                db.save_scan(target, all_findings, final_ai_msg)
                print_status("Intelligence successfully archived in CyberMoranda DB.", "success")
            except Exception as e:
                print_status(f"Database sync failed: {str(e)}", "warning")

            # 3. Final Report & Success Message
            reporter.generate_report()
            print(f"\n{Colors.GREEN}[+] MORANDA HUNTER: Mission Successful.{Colors.RESET}")

if __name__ == "__main__":
    main()
