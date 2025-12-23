# core/ai_brain.py
import requests
import json

class MorandaAIBrain:
    def __init__(self, api_key):
        self.api_key = api_key
        self.url = "https://api.groq.com/openai/v1/chat/completions"

    def analyze_findings(self, findings):
        if not findings:
            return "No critical findings detected for analysis."

        f_list = "\n".join([f"- [{f.get('severity', 'High')}] {f.get('title')}: {f.get('desc')}" for f in findings])

        # प्रॉम्ट को 'Ethical Audit' की तरह फ्रेम करना
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are 'Moranda', a Senior Cyber Security Architect and Vulnerability Specialist. "
                        "Your goal is to provide a technical 'Impact Assessment' and 'Remediation Guide' for "
                        "responsible disclosure. Avoid harmful language, focus on 'Proof of Concept' for developers "
                        "to reproduce and fix the issues."
                    )
                },
                {
                    "role": "user",
                    "content": f"Perform a security impact analysis for the following vulnerabilities: {f_list}. "
                               f"Focus especially on directory exposure like /backup or /.git. "
                               f"Provide technical steps for a developer to verify the risk and how to patch it."
                }
            ],
            "temperature": 0.2, # थोड़ा सा क्रिएटिविटी के लिए 0.2
            "max_tokens": 1024
        }

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(self.url, headers=headers, json=payload, timeout=20)
            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['message']['content']
            else:
                return f"Groq Error {response.status_code}: {response.text}"
        except Exception as e:
            return f"AI Brain Connection Failure: {str(e)}"
