# core/notifications.py
import subprocess

class MorandaNotifier:
    def __init__(self):
        self.architect = "Moranda"

    def send_alert(self, title, message, priority="normal"):
        # BMW M-Series themed notifications
        icon = "🚨" if priority == "high" else "🛡️"
        full_msg = f"{icon} {message}"
        
        # Termux-API कमांड का उपयोग करके Android नोटिफिकेशन भेजें
        cmd = [
            "termux-notification",
            "--title", f"Moranda Hunter: {title}",
            "--content", full_msg,
            "--priority", priority,
            "--led-color", "0000FF" if priority == "normal" else "FF0000", # M-Colors: Blue/Red
            "--vibrate", "500,200,500" if priority == "high" else "200"
        ]
        
        subprocess.run(cmd)

# ग्लोबल इंस्टेंस
notifier = MorandaNotifier()
