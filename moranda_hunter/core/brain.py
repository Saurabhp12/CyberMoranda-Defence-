# core/brain.py

class HunterBrain:
    def __init__(self):
        # बग्स को उनके संभावित हमलों (Exploits) के साथ मैप करना
        self.exploit_map = {
            "Missing X-Frame-Options": {
                "vector": "Clickjacking",
                "poc": "<iframe> टैग का इस्तेमाल करके टार्गेट पेज को लोड करने की कोशिश करें।"
            },
            "Interesting Directory: /admin/": {
                "vector": "Broken Access Control",
                "poc": "डिफ़ॉल्ट क्रेडेंशियल्स (admin/admin) या 'admin-bypass' पेलोड्स ट्राई करें।"
            },
            "Exposed API Endpoint": {
                "vector": "Insecure API / Information Disclosure",
                "poc": "Postman का इस्तेमाल करके GET/POST रिक्वेस्ट भेजें और सेंसिटिव डेटा चेक करें।"
            },
            "Information Disclosure: Email Address Found": {
                "vector": "Social Engineering / OSINT",
                "poc": "इस ईमेल का इस्तेमाल करके 'Forgot Password' या फिशिंग अटैक की संभावना देखें।"
            }
        }

    def suggest_exploit(self, title):
        """बग के आधार पर हमले का तरीका सुझाना"""
        for bug, intel in self.exploit_map.items():
            if bug in title:
                return intel
        return None
