# core/display.py

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    """Moranda Hunter Iconic Branding"""
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print(r"""
   __  __  ____  _____     _   _ _____   _____  
  |  \/  |/ __ \|  __ \   | \ | |  __ \ / _ \ \ 
  | \  / | |  | | |__) |  |  \| | |  | | |__| |
  | |\/| | |  | |  _  /   | . ` | |  | |  __  |
  | |  | | |__| | | \ \   | |\  | |__| | |  | |
  |_|  |_|\____/|_|  \_\  |_| \_|_____/|_|  |_|
        HUNTER EDITION v1.0
        """)
    print(f"{Colors.YELLOW}[+] Architect: Moranda | System: ONLINE{Colors.RESET}")
    print(f"{Colors.MAGENTA}" + "═" * 50 + f"{Colors.RESET}")

def print_separator(title=None):
    """Sleek divider for sections"""
    if title:
        line = f"── {title.upper()} " + "─" * (45 - len(title))
        print(f"\n{Colors.MAGENTA}{line}{Colors.RESET}")
    else:
        print(f"{Colors.MAGENTA}" + "─" * 50 + f"{Colors.RESET}")

def print_status(message, type="info"):
    """Clean status icons"""
    styles = {
        "info": (f"{Colors.CYAN}[~]{Colors.RESET}", Colors.RESET),
        "success": (f"{Colors.GREEN}[+]{Colors.RESET}", Colors.GREEN),
        "warning": (f"{Colors.YELLOW}[!]{Colors.RESET}", Colors.YELLOW),
        "danger": (f"{Colors.RED}[X]{Colors.RESET}", Colors.RED + Colors.BOLD)
    }
    prefix, msg_color = styles.get(type, styles["info"])
    print(f"{prefix} {msg_color}{message}{Colors.RESET}")
