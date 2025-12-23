# engines/reporter.py
import datetime
from core.display import Colors, print_separator, print_status

class BountyReporter:
    def __init__(self, target):
        self.target = target
        self.findings = []
        self.report_name = f"report_{datetime.date.today()}.md"

    def add_finding(self, title, severity, description, evidence):
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence
        })

    def generate_report(self):
        try:
            with open(self.report_name, "w") as f:
                f.write(f"# Bug Bounty Recon Report: {self.target}\n")
                f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Researcher:** Moranda Hunter v1.0\n\n")
                f.write("--- \n\n")

                if not self.findings:
                    f.write("## No significant vulnerabilities found.\n")
                else:
                    for item in self.findings:
                        f.write(f"## [{item['severity'].upper()}] {item['title']}\n")
                        f.write(f"**Description:** {item['description']}\n\n")
                        f.write(f"**Evidence:**\n```\n{item['evidence']}\n```\n")
                        f.write("\n---\n")

            print_status(f"Bounty Report compiled: {self.report_name}", "success")
            
        except Exception as e:
            print_status(f"Failed to generate report: {e}", "danger")
