# engines/validator.py
import requests

class LootValidator:
    def __init__(self, proxies=None):
        self.proxies = proxies

    def is_valid_loot(self, url, content):
        # 1. HTML टैग्स चेक करें (अगर .env में <html> है, तो वह फेक है)
        if "<!doctype html>" in content.lower() or "<html" in content.lower():
            return False
        
        # 2. Content-Length चेक (अगर बहुत छोटा या डिफ़ॉल्ट साइज है)
        if len(content) < 10:
            return False

        # 3. सीक्रेट्स की मौजूदगी (Regex check)
        keywords = ["DB_", "API_KEY", "SECRET", "PASSWORD", "AWS_"]
        if any(key in content for key in keywords):
            return True

        return True # अगर संदेह हो, तो मैन्युअल चेक के लिए रख लें
