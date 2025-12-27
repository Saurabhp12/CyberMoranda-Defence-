import os

# फाइल का नाम
filename = "apk_shield/ultimate_virus.apk"

# यह कंटेंट हमारे Auditor और YARA इंजन को ट्रिगर करेगा
malicious_content = """
PK... (Fake Header)

// --- 1. HARDCODED SECRETS (Auditor Trigger) ---
String aws_key = "AKIAIMX752451234EXAMPLE";  // AWS Cloud Key Leak
String google_key = "AIzaSyD-TEST-KEY-123456789"; // Google API Key
String private_key = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA..."; // RSA Private Key Leak

// --- 2. DANGEROUS COMMANDS (Auditor Trigger) ---
Runtime.getRuntime().exec("rm -rf /"); // Wipe System
String url = "http://hacker-server.com/steal_data.php"; // Insecure HTTP
String pass = System.getenv("TEST_PASSWORD"); // Hardcoded Password

// --- 3. MALWARE SIGNATURES (YARA Trigger) ---
payload/android/meterpreter/reverse_tcp  // Metasploit Attack
android.permission.SEND_SMS              // SMS Hijacker
Cipher.getInstance("AES/CBC/PKCS5Padding"); // Ransomware Encryption
com.spyware.camera.hidden                // Hidden Camera
BlackMatter Ransomware                   // Known Ransomware Name
Mimikatz                                 // Password Stealer
"""

# फाइल बनाना
if not os.path.exists("apk_shield"):
    os.makedirs("apk_shield")

with open(filename, "w") as f:
    f.write(malicious_content)

print(f"\n[+] SUCCESS: Created '{filename}'")
print("[!] This file is packed with FAKE viruses to test your scanner.")
print("[!] Go scan it now!")
