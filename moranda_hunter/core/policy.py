# core/policy.py
from urllib.parse import urlparse

class ScopeGuard:
    def __init__(self, original_target):
        # शुरुआत में दिया गया डोमेन (जैसे testphp.vulnweb.com)
        self.authorized_domain = urlparse(original_target).netloc
        if not self.authorized_domain:
            self.authorized_domain = original_target # Fallback

    def is_in_scope(self, new_url):
        """चेक करता है कि नया URL हमारे स्कोप में है या नहीं"""
        new_domain = urlparse(new_url).netloc
        
        # अगर डोमेन मैच करता है, तो स्कोप में है
        if new_domain == self.authorized_domain or not new_domain:
            return True
        return False
