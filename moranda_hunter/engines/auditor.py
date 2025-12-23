import re
import os
from core.display import UI

class AuditorEngine:
    def __init__(self, brain):
        self.brain = brain
        self.ui = UI()
        # Module 11: Secrets & Correlation Patterns
        self.patterns = {
            "Google API Key": r'AIza[0-9A-Za-z\\-_]{35}',
            "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
            "Staging/Dev URL": r'https?://(?:dev|staging|test|beta)\.[a-zA-Z0-9-]+\.[a-z]{2,}',
            "Internal IP": r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[1-2])|192\.168)\.\d{1,3}\.\d{1,3}\b'
        }

    def audit_apk_content(self, file_path):
        """Module 11: APK ↔ Web Correlation (Upgrade 101-108)"""
        print(f"\n{self.ui.C}[*] Auditor: Analyzing Source/APK Artifacts...{self.ui.RESET}")
        
        if not os.path.exists(file_path):
            print(f"{self.ui.R}[!] File not found: {file_path}{self.ui.RESET}")
            return

        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                
            found_count = 0
            for label, pattern in self.patterns.items():
                matches = set(re.findall(pattern, content))
                for match in matches:
                    # Upgrade 108: Staging backend exposure in production assets
                    severity = "CRITICAL" if "Key" in label else "HIGH"
                    self.ui.print_finding(f"APK Secret: {label} -> {match[:40]}", severity, "100%")
                    
                    # Brain को डेटा भेजें (Module 11 Correlation Logic)
                    self.brain.add_finding(
                        title=f"Hardcoded {label} in APK",
                        severity=severity,
                        module="APK Auditor",
                        context="artifact_leak",
                        confidence=1.0
                    )
                    found_count += 1
            
            if found_count == 0:
                print(f"{self.ui.G}[✓] No hardcoded secrets found in this artifact.{self.ui.RESET}")

        except Exception as e:
            print(f"{self.ui.R}[!] Audit Error: {str(e)}{self.ui.RESET}")
