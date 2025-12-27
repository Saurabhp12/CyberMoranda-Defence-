import os
import json
import datetime
import re
try:
    from core.display import print_status
except ImportError:
    def print_status(msg, type="info"):
        print(f"[{type.upper()}] {msg}")

def url_to_filename(url):
    """Sanitize URL to make a valid filename"""
    # Remove http/https and replace symbols
    name = re.sub(r'^https?://', '', url)
    name = re.sub(r'[:/\\?*|"<>]', '_', name)
    return name[:50]  # Limit length

class BountyReporter:
    def __init__(self, target):
        self.target = target
        self.findings = []
        # Filename me Date + Time dono honge taaki overwrite na ho
        clean_name = url_to_filename(target)
        self.filename = f"report_{clean_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.html"

    def add_finding(self, title, severity, details, tool):
        """Manually add a finding (Backward Compatibility)"""
        self.findings.append({
            "title": title,
            "severity": severity,
            "url": "N/A",
            "details": details,
            "tool": tool
        })

    def generate_report(self, all_findings_list=None):
        """
        Compiles the Professional HTML Report.
        Accepts the main 'all_findings' list from moranda_hunter.py
        """
        # Merge external list if provided
        if all_findings_list:
            self.findings.extend(all_findings_list)

        print_status(f"📝 Compiling HTML report with {len(self.findings)} findings...", "info")
        
        # 1. Statistics Calculation (For Charts)
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for f in self.findings:
            # Normalize severity (handle lowercase/mixed)
            sev = f.get('severity', 'INFO').upper()
            if sev not in stats: sev = "INFO"
            stats[sev] += 1

        # 2. HTML Template (Cyberpunk Dark Mode)
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Moranda Hunter Report: {self.target}</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; }}
                body {{ background-color: var(--bg); color: var(--text); font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; margin: 0; }}
                h1 {{ color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
                .stat-box {{ display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 30px; justify-content: center; }}
                .card {{ background: var(--card); padding: 15px; border-radius: 8px; border: 1px solid var(--border); flex: 1; min-width: 150px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                .count {{ font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }}
                
                /* Severity Colors */
                .crit {{ color: #ff5555; }} .high {{ color: #ffb86c; }} .med {{ color: #f1fa8c; }} .low {{ color: #50fa7b; }} .info {{ color: #8b949e; }}
                
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: var(--card); border-radius: 8px; overflow: hidden; }}
                th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); }}
                th {{ background-color: #21262d; color: var(--accent); text-transform: uppercase; font-size: 0.9em; }}
                tr:hover {{ background-color: #21262d; transition: 0.2s; }}
                
                .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }}
                .bg-CRITICAL {{ background: #ff5555; color: black; }}
                .bg-HIGH {{ background: #ffb86c; color: black; }}
                .bg-MEDIUM {{ background: #f1fa8c; color: black; }}
                .bg-LOW {{ background: #50fa7b; color: black; }}
                .bg-INFO {{ background: #8b949e; color: black; }}
                
                .chart-container {{ max-width: 500px; margin: 0 auto 40px auto; position: relative; }}
                a {{ color: var(--accent); text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
                .footer {{ margin-top: 40px; text-align: center; font-size: 0.8em; color: #8b949e; }}
            </style>
        </head>
        <body>
            <h1>⚔️ MORANDA HUNTER REPORT</h1>
            <p style="text-align: center;"><strong>Target:</strong> {self.target} | <strong>Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="stat-box">
                <div class="card"><div class="count crit">{stats['CRITICAL']}</div>CRITICAL</div>
                <div class="card"><div class="count high">{stats['HIGH']}</div>HIGH</div>
                <div class="card"><div class="count med">{stats['MEDIUM']}</div>MEDIUM</div>
                <div class="card"><div class="count low">{stats['LOW']}</div>LOW</div>
                <div class="card"><div class="count info">{stats['INFO']}</div>INFO</div>
            </div>

            <div class="chart-container">
                <canvas id="vulnChart"></canvas>
            </div>

            <h2>🔎 Detailed Findings Log</h2>
            <table>
                <thead>
                    <tr>
                        <th width="10%">Severity</th>
                        <th width="20%">Type / Title</th>
                        <th width="30%">Location</th>
                        <th width="40%">Details / Evidence</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # 3. Add Rows Loop
        for f in self.findings:
            sev = f.get('severity', 'INFO').upper()
            if sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]: sev = "INFO"
            
            title = f.get('title') or f.get('type') or "Unknown Issue"
            
            # Handle URL nicely
            raw_url = f.get('url', 'N/A')
            display_url = raw_url
            if len(display_url) > 40: display_url = display_url[:40] + "..."
            url_html = f'<a href="{raw_url}" target="_blank">{display_url}</a>' if raw_url.startswith('http') else raw_url
            
            # Handle Details (Convert objects to string if needed)
            desc = f.get('details') or f.get('desc') or f.get('description') or f.get('evidence') or ""
            if isinstance(desc, dict) or isinstance(desc, list):
                desc = json.dumps(desc)
            
            # Escape HTML in description to prevent breaking layout
            desc = str(desc).replace("<", "&lt;").replace(">", "&gt;")

            html_content += f"""
            <tr>
                <td><span class="badge bg-{sev}">{sev}</span></td>
                <td><strong>{title}</strong></td>
                <td>{url_html}</td>
                <td style="font-family: monospace; font-size: 0.9em; color: #a5d6ff;">{desc}</td>
            </tr>
            """

        # 4. Close HTML & Add JS Chart Logic
        html_content += f"""
                </tbody>
            </table>
            
            <div class="footer">Generated by CyberMoranda Defense System v1.0</div>

            <script>
                const ctx = document.getElementById('vulnChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{{
                            data: [{stats['CRITICAL']}, {stats['HIGH']}, {stats['MEDIUM']}, {stats['LOW']}, {stats['INFO']}],
                            backgroundColor: ['#ff5555', '#ffb86c', '#f1fa8c', '#50fa7b', '#8b949e'],
                            borderColor: '#161b22',
                            borderWidth: 2
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        plugins: {{ 
                            legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9', padding: 20 }} }},
                            title: {{ display: true, text: 'Vulnerability Severity Distribution', color: '#c9d1d9', font: {{ size: 16 }} }}
                        }}
                    }}
                }});
            </script>
        </body>
        </html>
        """

        # Save File
        try:
            with open(self.filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print_status(f"✅ HTML Report Generated: {self.filename}", "success")
            return self.filename
        except Exception as e:
            print_status(f"Report Generation Failed: {str(e)}", "danger")
            return None
