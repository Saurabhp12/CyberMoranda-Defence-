# engines/mailer.py
from core.display import print_status, print_separator

class BountyMailer:
    def __init__(self, target, findings):
        self.target = target
        self.findings = findings

    def format_for_submission(self):
        """बग बाउंटी प्लेटफॉर्म्स (HackerOne/Bugcrowd) के लिए रिपोर्ट तैयार करना"""
        print_separator("Drafting Professional Report")
        
        report_draft = f"Subject: Security Vulnerability Report - {self.target}\n\n"
        report_draft += "## Summary:\nAutomated scan via Moranda Hunter v1.0 has identified several security issues.\n\n"
        
        for issue in self.findings:
            report_draft += f"### [{issue['severity'].upper()}] {issue['title']}\n"
            report_draft += f"**Target:** {self.target}\n"
            report_draft += f"**Description:** {issue['desc']}\n"
            report_draft += f"**Impact:** This could lead to unauthorized access or information disclosure.\n"
            report_draft += f"**Steps to Reproduce:**\n1. Use Moranda Hunter to scan {self.target}\n2. Observe the following trace: {issue.get('evidence', 'See attached logs')}\n\n"
            report_draft += "---\n"

        # रिपोर्ट को एक फाइल में सेव करना
        try:
            filename = f"submission_draft_{self.target.replace('https://', '').split('/')[0]}.txt"
            with open(filename, "w") as f:
                f.write(report_draft)
            print_status(f"Professional draft saved as: {filename}", "success")
        except Exception as e:
            print_status(f"Failed to save draft: {e}", "danger")
