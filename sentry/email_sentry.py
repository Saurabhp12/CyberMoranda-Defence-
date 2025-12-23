#!/usr/bin/env python3
import re
import sys

# Colorama Setup (Safe Mode)
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        CYAN = "\033[96m"
        YELLOW = "\033[93m"
        RED = "\033[91m"
        GREEN = "\033[92m"
        MAGENTA = "\033[95m"
    class Style:
        RESET_ALL = "\033[0m"

def banner():
    print(Fore.CYAN + """
    ╔══════════════════════════════════════╗
    ║     MORANDA RFC-822 VALIDATOR        ║
    ║   [ Strict Protocol Enforcement ]    ║
    ╚══════════════════════════════════════╝
    """ + Style.RESET_ALL)

# FIXED: Standard RFC 5322 Regex (Python Compatible)
# Yeh regex "very.unusual.@.unusual.com"@example.com jaise complex emails ko handle karega.
RFC_5322_REGEX = r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"

def scan_email(email_input):
    print(f"{Fore.YELLOW}[*] Analyzing Packet Structure: {email_input}")
    
    # 1. Buffer Overflow Check
    if len(email_input) > 254:
        print(Fore.RED + "[!] THREAT DETECTED: Buffer Overflow Attempt (Length > 254)")
        return False

    # 2. Advanced Regex Check (IGNORECASE flag on)
    match = re.match(RFC_5322_REGEX, email_input, re.IGNORECASE)
    
    if match:
        print(Fore.GREEN + "[✔] RFC-822 COMPLIANT: Valid Structure.")
        
        # Suspicious Payload Check (SQL Injection or Scripting)
        dangerous_chars = ["'", ";", "--", "<script>", "OR 1=1", "UNION"]
        if any(char in email_input for char in dangerous_chars):
             print(Fore.MAGENTA + "[!] WARNING: Valid Syntax but contains Suspicious/Attack Payload.")
        return True
    else:
        print(Fore.RED + "[X] INVALID STRUCTURE: Possible Malformed Header Injection.")
        return False

if __name__ == "__main__":
    banner()
    try:
        # User input prompt
        if len(sys.argv) > 1:
            target = sys.argv[1] # Agar command line se aaya ho
        else:
            target = input(Fore.CYAN + "Enter Email Payload to Test: " + Style.RESET_ALL)
            
        scan_email(target)
    except KeyboardInterrupt:
        print("\n[!] User Interrupted.")
