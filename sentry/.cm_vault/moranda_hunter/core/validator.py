# core/validator.py
class SmartValidator:
    def __init__(self):
        # ये शब्द मिलने पर पाथ को "False Positive" माना जाएगा
        self.profile_indicators = ["Join as Creator", "Reviews", "Influencer", "Followers", "Add to Cart"]
        # ये शब्द मिलने पर पाथ को "High Priority" माना जाएगा
        self.admin_indicators = ["Login", "Password", "Dashboard", "Index of /", "Admin Panel", "phpMyAdmin"]

    def analyze_page(self, html_text):
        html_text = html_text.lower()
        
        # प्रोफाइल चेक
        for indicator in self.profile_indicators:
            if indicator.lower() in html_text:
                return "False Positive (User Profile)"
        
        # असली एडमिन/सिस्टम चेक
        for indicator in self.admin_indicators:
            if indicator.lower() in html_text:
                return "Real Asset (Critical)"
        
        return "Unknown/Neutral"
