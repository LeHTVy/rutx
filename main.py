#!/usr/bin/env python3
"""
SNODE AI - Security Node Agent
Main Terminal Interface
"""

import os
import sys
import json
import requests
import time
from datetime import datetime

# Add current directory for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Fix terminal I/O blocking issues with long-running scans
# Set stdout/stderr to line-buffered mode and handle non-blocking writes
def _safe_print(*args, **kwargs):
    """Print with retry logic for non-blocking I/O errors"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            print(*args, **kwargs)
            sys.stdout.flush()
            return
        except BlockingIOError:
            time.sleep(0.1)
    # Last attempt without catching
    print(*args, **kwargs)

from config import OLLAMA_ENDPOINT, OLLAMA_LIST_ENDPOINT, MODEL_NAME
from tools import ALL_TOOLS, get_all_tool_names


# ANSI Color Codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_terminal_width():
    """Get terminal width"""
    try:
        return os.get_terminal_size().columns
    except:
        return 80


def check_ollama_connection() -> tuple:
    """Check if Ollama is running and get model info"""
    try:
        response = requests.get(OLLAMA_LIST_ENDPOINT, timeout=5)
        if response.status_code == 200:
            data = response.json()
            models = [m.get('name', '') for m in data.get('models', [])]
            return True, models
        return False, []
    except:
        return False, []


def get_tool_categories():
    """Categorize tools by type"""
    categories = {
        "Network Scanning": [],
        "Subdomain Enum": [],
        "Web Recon": [],
        "Threat Intel": [],
        "Utilities": []
    }

    for tool in ALL_TOOLS:
        name = tool['function']['name']
        if 'nmap' in name:
            categories["Network Scanning"].append(name)
        elif 'amass' in name:
            categories["Subdomain Enum"].append(name)
        elif 'bbot' in name:
            categories["Web Recon"].append(name)
        elif 'shodan' in name:
            categories["Threat Intel"].append(name)
        else:
            categories["Utilities"].append(name)

    return categories


def print_banner():
    """Print SNODE AI banner"""
    width = get_terminal_width()

    banner = f"""
{Colors.CYAN}{Colors.BOLD}
███████╗███╗   ██╗ ██████╗ ██████╗ ███████╗
██╔════╝████╗  ██║██╔═══██╗██╔══██╗██╔════╝
███████╗██╔██╗ ██║██║   ██║██║  ██║█████╗
╚════██║██║╚██╗██║██║   ██║██║  ██║██╔══╝
███████║██║ ╚████║╚██████╔╝██████╔╝███████╗
╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝{Colors.RESET}
{Colors.DIM}                                        AI{Colors.RESET}
{Colors.YELLOW}═══════════════════════════════════════════{Colors.RESET}
{Colors.GREEN}  Security Node - AI Penetration Testing{Colors.RESET}
{Colors.YELLOW}═══════════════════════════════════════════{Colors.RESET}
"""
    print(banner)


def print_system_info():
    """Print system verification info"""
    width = get_terminal_width()
    col_width = width // 2 - 2

    # Check Ollama
    ollama_ok, models = check_ollama_connection()

    # Get tools
    tool_categories = get_tool_categories()
    total_tools = len(get_all_tool_names())

    print(f"\n{Colors.BOLD}{'─'*width}{Colors.RESET}")

    # Left Column: Model & Tools | Right Column: Usage
    left_lines = []
    right_lines = []

    # Left side - Model Info
    left_lines.append(f"{Colors.CYAN}▸ MODEL{Colors.RESET}")
    if ollama_ok:
        left_lines.append(f"  {Colors.GREEN}✓{Colors.RESET} Ollama: {Colors.GREEN}Connected{Colors.RESET}")
        left_lines.append(f"  {Colors.DIM}Active:{Colors.RESET} {MODEL_NAME}")
        if models:
            left_lines.append(f"  {Colors.DIM}Available:{Colors.RESET} {len(models)} models")
    else:
        left_lines.append(f"  {Colors.RED}✗{Colors.RESET} Ollama: {Colors.RED}Not Connected{Colors.RESET}")
        left_lines.append(f"  {Colors.DIM}Run: ollama serve{Colors.RESET}")

    left_lines.append("")
    left_lines.append(f"{Colors.CYAN}▸ TOOLS ({total_tools}){Colors.RESET}")

    for category, tools in tool_categories.items():
        if tools:
            left_lines.append(f"  {Colors.DIM}{category}:{Colors.RESET} {len(tools)}")

    # Right side - Usage Info
    right_lines.append(f"{Colors.CYAN}▸ HOW IT WORKS{Colors.RESET}")
    right_lines.append(f"  {Colors.GREEN}1.{Colors.RESET} AI selects optimal security tools")
    right_lines.append(f"  {Colors.GREEN}2.{Colors.RESET} Executes scans & saves to DB")
    right_lines.append(f"  {Colors.GREEN}3.{Colors.RESET} Analyzes & generates report")
    right_lines.append("")
    right_lines.append(f"{Colors.CYAN}▸ CONVERSATIONAL AI{Colors.RESET}")
    right_lines.append(f"  {Colors.DIM}»{Colors.RESET} Find subdomains of example.com")
    right_lines.append(f"  {Colors.DIM}»{Colors.RESET} Port scan {Colors.YELLOW}those targets{Colors.RESET}")
    right_lines.append(f"  {Colors.DIM}»{Colors.RESET} Check vulns on {Colors.YELLOW}the api subdomain{Colors.RESET}")
    right_lines.append(f"  {Colors.DIM}»{Colors.RESET} Full assessment of 192.168.1.1")
    right_lines.append("")
    right_lines.append(f"{Colors.CYAN}▸ QUICK COMMANDS{Colors.RESET}")
    right_lines.append(f"  {Colors.DIM}help{Colors.RESET}    Help & tips")
    right_lines.append(f"  {Colors.DIM}tools{Colors.RESET}   List 39 tools")
    right_lines.append(f"  {Colors.DIM}clear{Colors.RESET}   Clear screen")
    right_lines.append(f"  {Colors.DIM}sudo{Colors.RESET}    Run as admin")
    right_lines.append(f"  {Colors.DIM}quit{Colors.RESET}    Exit SNODE")

    # Print side by side
    max_lines = max(len(left_lines), len(right_lines))

    for i in range(max_lines):
        left = left_lines[i] if i < len(left_lines) else ""
        right = right_lines[i] if i < len(right_lines) else ""

        # Strip ANSI codes for length calculation
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        left_clean = ansi_escape.sub('', left)
        right_clean = ansi_escape.sub('', right)

        padding = col_width - len(left_clean)
        if padding < 0:
            padding = 2

        print(f"  {left}{' ' * padding}{Colors.DIM}│{Colors.RESET}  {right}")

    print(f"{Colors.BOLD}{'─'*width}{Colors.RESET}")


def print_phase_header(phase: int, title: str):
    """Print phase header"""
    icons = {1: "📦", 2: "⚙️", 3: "📊"}
    print(f"\n{Colors.YELLOW}{'='*50}{Colors.RESET}")
    print(f"{icons.get(phase, '▸')} {Colors.BOLD}PHASE {phase}: {title}{Colors.RESET}")
    print(f"{Colors.YELLOW}{'='*50}{Colors.RESET}")


def print_tool_list():
    """Print all available tools"""
    categories = get_tool_categories()

    print(f"\n{Colors.CYAN}{Colors.BOLD}Available Security Tools{Colors.RESET}\n")

    for category, tools in categories.items():
        if tools:
            print(f"{Colors.YELLOW}▸ {category}{Colors.RESET}")
            for tool in sorted(tools):
                print(f"  {Colors.DIM}•{Colors.RESET} {tool}")
            print()


def print_help():
    """Print help information"""
    print(f"""
{Colors.CYAN}{Colors.BOLD}SNODE AI Help{Colors.RESET}

{Colors.YELLOW}▸ How It Works{Colors.RESET}
  SNODE AI uses a 3-phase system:

  {Colors.GREEN}Phase 1:{Colors.RESET} Tool Selection (BlackBox)
    - AI analyzes your request
    - Selects appropriate tools automatically

  {Colors.GREEN}Phase 2:{Colors.RESET} Execution & Storage
    - Runs selected security tools
    - Saves results to database

  {Colors.GREEN}Phase 3:{Colors.RESET} Analysis & Report
    - AI analyzes scan results
    - Generates vulnerability report

{Colors.YELLOW}▸ Example Prompts{Colors.RESET}
  • "Scan all ports on 192.168.1.100"
  • "Find subdomains of example.com"
  • "Perform vulnerability scan on 10.0.0.1"
  • "Get threat intel for suspicious IP 1.2.3.4"
  • "Comprehensive security assessment of target.com"

{Colors.YELLOW}▸ Conversational Context (NEW){Colors.RESET}
  Reference previous scan results:
  • "Find subdomains of example.com" → "port scan those subdomains"
  • "Scan 192.168.1.1" → "check vulnerabilities on that target"
  • Use keywords: "those", "them", "the list", "previous scan"

{Colors.YELLOW}▸ Commands{Colors.RESET}
  • help      - Show this help message
  • clear     - Clear the screen
  • tools     - List all available scanning tools
  • history   - Show command history (last 20 commands)
  • sudo      - Restart as Administrator (Windows UAC)
  • banner    - Show the SNODE banner
  • quit/exit - Exit the program

{Colors.YELLOW}▸ Keyboard Shortcuts{Colors.RESET}
  • ↑ / ↓     - Navigate command history
  • ← / →     - Move cursor left/right
  • Ctrl+C    - Interrupt current operation
  • Tab       - Auto-complete (when available)

{Colors.YELLOW}▸ Tips{Colors.RESET}
  • Be specific about targets (IP, domain, URL)
  • Mention scan type if needed (quick, full, vuln)
  • Results are saved for later analysis
  • Use ↑/↓ arrows to recall previous commands
  • Reference previous scans using "those", "them", "the list"
""")


def main():
    """Main entry point"""
    clear_screen()
    print_banner()
    print_system_info()

    # Initialize SNODE Integration (Tracing + Guardrails)
    from utils.snode_integration import get_snode_integration
    snode = get_snode_integration()

    # Import agent here to avoid circular imports
    from agent import SNODEAgent
    from utils import create_input_handler
    from utils.admin_check import is_admin, restart_as_admin

    agent = SNODEAgent()

    # Create interactive input handler with history support
    input_handler = create_input_handler(
        prompt=f"{Colors.CYAN}SNODE{Colors.RESET}> ",
        history_file=".snode_history"
    )

    # Main interaction loop
    while True:
        try:
            # Get user input with history support
            prompt = input_handler.input().strip()

            if not prompt:
                continue

            # Handle built-in commands
            if prompt.lower() in ['quit', 'exit']:
                print(f"\n{Colors.YELLOW}Goodbye!{Colors.RESET}\n")
                break

            elif prompt.lower() == 'help':
                print_help()
                continue

            elif prompt.lower() == 'tools':
                print_tool_list()
                continue

            elif prompt.lower() == 'clear':
                clear_screen()
                print_banner()
                print_system_info()
                continue

            elif prompt.lower() == 'banner':
                clear_screen()
                print_banner()
                continue

            elif prompt.lower() == 'sudo':
                if not is_admin():
                    print(f"\n{Colors.YELLOW}Restarting as Administrator...{Colors.RESET}\n")
                    restart_as_admin()
                else:
                    print(f"\n{Colors.GREEN}Already running as Administrator{Colors.RESET}\n")
                continue

            # Run the 3-phase scan
            print(f"\n{Colors.DIM}Processing: {prompt[:50]}...{Colors.RESET}")

            result = agent.run(prompt)

            if result.get("success"):
                # Get analysis from phase 3 or 4
                phases = result.get("phases", {})
                analysis = phases.get("phase_4_report") or phases.get("phase_3_analysis", "No analysis available")
                scan_type = "Subdomain (4-Phase)" if result.get("is_subdomain_scan") else "Standard (3-Phase)"

                print(f"\n{Colors.YELLOW}{'═'*60}{Colors.RESET}")
                print(f"{Colors.BOLD}📋 FINAL REPORT{Colors.RESET}")
                print(f"{Colors.YELLOW}{'═'*60}{Colors.RESET}")
                print(analysis)
                print(f"\n{Colors.YELLOW}{'═'*60}{Colors.RESET}")
                print(f"{Colors.DIM}Session: {result['session_id']} | Type: {scan_type} | Time: {result['elapsed_seconds']}s{Colors.RESET}")
                print(f"{Colors.YELLOW}{'═'*60}{Colors.RESET}\n")
            else:
                print(f"\n{Colors.RED}Error: {result.get('error', 'Unknown error')}{Colors.RESET}")
                if result.get('reasoning'):
                    print(f"{Colors.DIM}{result['reasoning']}{Colors.RESET}")
                print()

        except KeyboardInterrupt:
            _safe_print(f"\n\n{Colors.YELLOW}Interrupted. Type 'quit' to exit.{Colors.RESET}\n")
            continue

        except EOFError:
            # Terminal input closed (can happen with I/O issues)
            _safe_print(f"\n{Colors.YELLOW}Input stream closed. Exiting...{Colors.RESET}\n")
            break

        except BlockingIOError:
            # Terminal buffer full - wait and retry
            time.sleep(0.5)
            _safe_print(f"\n{Colors.YELLOW}Terminal buffer busy. Please wait...{Colors.RESET}\n")
            continue

        except Exception as e:
            _safe_print(f"\n{Colors.RED}Error: {e}{Colors.RESET}\n")


if __name__ == "__main__":
    main()
