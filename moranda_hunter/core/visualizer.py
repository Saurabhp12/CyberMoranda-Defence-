import os

class Visualizer:
    @staticmethod
    def generate_dashboard(brain):
        """Module 21: Risk Heatmap & Severity Distribution (Upgrade 201, 208)"""
        html_path = "logs/dashboard.html"
        
        # Severity counts for visualization
        crit = sum(1 for f in brain.findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in brain.findings if f['severity'] == 'HIGH')
        med = sum(1 for f in brain.findings if f['severity'] == 'MEDIUM')
        
        html_content = f"""
        <html>
        <head>
            <title>Moranda Hunter Intelligence Dashboard</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }}
                .card {{ background: #1e293b; padding: 20px; border-radius: 12px; border-left: 5px solid #38bdf8; margin-bottom: 20px; }}
                .risk-bar {{ width: 100%; background: #334155; height: 30px; border-radius: 15px; overflow: hidden; }}
                .risk-fill {{ width: {brain.risk_score}%; background: linear-gradient(90deg, #22c55e, #eab308, #ef4444); height: 100%; }}
                .stat-box {{ display: inline-block; padding: 10px 20px; border-radius: 8px; margin-right: 10px; font-weight: bold; }}
                .crit {{ background: #7f1d1d; color: #fecaca; }}
                .high {{ background: #7c2d12; color: #ffedd5; }}
            </style>
        </head>
        <body>
            <h1>Moranda Hunter Intel Summary</h1>
            <div class="card">
                <h2>Overall Risk Score: {brain.risk_score}/100</h2>
                <div class="risk-bar"><div class="risk-fill"></div></div>
            </div>
            <div class="card">
                <h3>Vulnerability Distribution</h3>
                <span class="stat-box crit">CRITICAL: {crit}</span>
                <span class="stat-box high">HIGH: {high}</span>
                <span class="stat-box">MEDIUM: {med}</span>
            </div>
            <h3>Discovery Logs</h3>
            <ul>
                {"".join([f"<li><b>{f['title']}</b> - {f['severity']} ({f['module']})</li>" for f in brain.findings])}
            </ul>
        </body>
        </html>
        """
        
        with open(html_path, "w") as f:
            f.write(html_content)
        return html_path
