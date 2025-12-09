#!/usr/bin/env python3
"""
SNODE AI - Security Node Agent
LangChain Edition - Terminal Interface
"""

import os
import sys
import time
from datetime import datetime

# Add current directory for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from snode_langchain import create_agent
from llm_configs import get_llm_config
from utils.admin_check import is_admin, restart_as_admin
from utils.interactive_input import create_input_handler


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


def print_banner():
    """Print SNODE AI banner - centered and prominent"""
    width = get_terminal_width()
    
    # ASCII art lines
    logo_lines = [
        "███████╗███╗   ██╗ ██████╗ ██████╗ ███████╗",
        "██╔════╝████╗  ██║██╔═══██╗██╔══██╗██╔════╝",
        "███████╗██╔██╗ ██║██║   ██║██║  ██║█████╗  ",
        "╚════██║██║╚██╗██║██║   ██║██║  ██║██╔══╝  ",
        "███████║██║ ╚████║╚██████╔╝██████╔╝███████╗",
        "╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝"
    ]
    
    # Calculate padding for centering
    logo_width = len(logo_lines[0])
    padding = max(0, (width - logo_width) // 2)
    indent = " " * padding
    
    # Print with centering
    print("\n")
    print(f"{Colors.CYAN}{Colors.BOLD}")
    for line in logo_lines:
        print(f"{indent}{line}")
    print(f"{Colors.RESET}")
    
    ai_art = [
        " ▄▀█ █",
        " █▀█ █"
    ]
    
    ai_width = len(ai_art[0])
    ai_padding = padding + logo_width - ai_width - 2
    ai_indent = " " * ai_padding
    
    print(f"{Colors.DIM}")
    for ai_line in ai_art:
        print(f"{ai_indent}{ai_line}")
    print(f"{Colors.RESET}")
    
    # Center the separator and title
    separator = "═" * 60
    sep_padding = " " * ((width - len(separator)) // 2)
    print(f"{Colors.YELLOW}{sep_padding}{separator}{Colors.RESET}")
    
    title = "Security Node - AI Penetration Testing"
    title_padding = " " * ((width - len(title)) // 2)
    print(f"{Colors.GREEN}{title_padding}{title}{Colors.RESET}")
    
    print(f"{Colors.YELLOW}{sep_padding}{separator}{Colors.RESET}")
    print()


def print_system_info(agent):
    """Print system verification info"""
    width = get_terminal_width()
    col_width = width // 2 - 2
    
    tools = agent.get_tools()
    
    print(f"\n{Colors.BOLD}{'-'*width}{Colors.RESET}")
    
    # Left Column: Model & Tools | Right Column: Usage
    left_lines = []
    right_lines = []
    
    # Left side - Model Info
    left_lines.append(f"{Colors.CYAN}> MODEL{Colors.RESET}")
    left_lines.append(f"  {Colors.GREEN}[OK]{Colors.RESET} SNODE Agent")
    left_lines.append(f"  {Colors.DIM}Model:{Colors.RESET} {agent.model_name}")
    
    # Privilege status
    if is_admin():
        left_lines.append(f"  {Colors.GREEN}[OK]{Colors.RESET} Root privileges")
    else:
        left_lines.append(f"  {Colors.YELLOW}[⚠]{Colors.RESET} User mode (some tools limited)")
    
    # Guardrails status
    if hasattr(agent, 'guardrails_enabled') and agent.guardrails_enabled:
        left_lines.append(f"  {Colors.GREEN}[OK]{Colors.RESET} Security guardrails")
    else:
        left_lines.append(f"  {Colors.RED}[⚠]{Colors.RESET} Guardrails OFF")
    
    left_lines.append("")
    left_lines.append(f"{Colors.CYAN}> TOOLS ({len(tools)}){Colors.RESET}")
    
    # Categorize tools
    tool_cats = {"Nmap": 0, "Subdomain": 0, "Web": 0, "Vuln": 0, "Recon": 0, "CVE": 0, "Intel": 0}
    for t in tools:
        if "nmap" in t or "rustscan" in t:
            tool_cats["Nmap"] += 1
        elif "subdomain" in t or "amass" in t or "bbot" in t or "subfinder" in t:
            tool_cats["Subdomain"] += 1
        elif "ffuf" in t or "gobuster" in t or "nikto" in t or "katana" in t or "httpx" in t:
            tool_cats["Web"] += 1
        elif "nuclei" in t or "sqlmap" in t or "dalfox" in t or "xss" in t:
            tool_cats["Vuln"] += 1
        elif "gau" in t or "wayback" in t or "arjun" in t or "param" in t:
            tool_cats["Recon"] += 1
        elif "cve" in t.lower():
            tool_cats["CVE"] += 1
        else:
            tool_cats["Intel"] += 1
    
    for cat, count in tool_cats.items():
        if count > 0:
            left_lines.append(f"  {Colors.DIM}{cat}:{Colors.RESET} {count}")
    
    # Right side - Usage Info
    right_lines.append(f"{Colors.CYAN}> HOW IT WORKS{Colors.RESET}")
    right_lines.append(f"  {Colors.GREEN}1.{Colors.RESET} AI selects optimal security tools")
    right_lines.append(f"  {Colors.GREEN}2.{Colors.RESET} Executes scans & analyzes results")
    right_lines.append(f"  {Colors.GREEN}3.{Colors.RESET} Remembers context for follow-ups")
    right_lines.append("")
    right_lines.append(f"{Colors.CYAN}> CONVERSATIONAL AI{Colors.RESET}")
    right_lines.append(f"  {Colors.DIM}»{Colors.RESET} Find subdomains of example.com")
    right_lines.append(f"  {Colors.DIM}»{Colors.RESET} Which ones look {Colors.YELLOW}critical?{Colors.RESET}")
    right_lines.append(f"  {Colors.DIM}»{Colors.RESET} Port scan {Colors.YELLOW}those targets{Colors.RESET}")
    right_lines.append("")
    right_lines.append(f"{Colors.CYAN}> COMMANDS{Colors.RESET}")
    right_lines.append(f"  {Colors.DIM}help{Colors.RESET}      Show tools & tips")
    right_lines.append(f"  {Colors.DIM}history{Colors.RESET}   Conversation memory")
    right_lines.append(f"  {Colors.DIM}switch{Colors.RESET}    Switch LLM model")
    right_lines.append(f"  {Colors.DIM}clear{Colors.RESET}     Clear memory")
    right_lines.append(f"  {Colors.DIM}quit{Colors.RESET}      Exit SNODE")
    
    # Print side by side
    import re
    max_lines = max(len(left_lines), len(right_lines))
    
    for i in range(max_lines):
        left = left_lines[i] if i < len(left_lines) else ""
        right = right_lines[i] if i < len(right_lines) else ""
        
        # Strip ANSI codes for length calculation
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        left_clean = ansi_escape.sub('', left)
        
        padding = col_width - len(left_clean)
        if padding < 0:
            padding = 2
        
        print(f"  {left}{' ' * padding}{Colors.DIM}|{Colors.RESET}  {right}")
    
    print(f"{Colors.BOLD}{'─'*width}{Colors.RESET}")


def print_help(agent):
    """Print help information"""
    print(f"""
{Colors.CYAN}{Colors.BOLD}SNODE AI Help{Colors.RESET}

{Colors.YELLOW}> Available Tools{Colors.RESET}""")
    
    for tool in agent.tools:
        desc = tool.description.split('\n')[0][:50]
        print(f"  {Colors.DIM}•{Colors.RESET} {tool.name}: {desc}...")
    
    print(f"""
{Colors.YELLOW}> Example Prompts{Colors.RESET}
  • "Scan all ports on 192.168.1.100"
  • "Find subdomains of example.com"
  • "Check vulnerabilities on 10.0.0.1"
  • "Get Shodan intel for 1.2.3.4"

{Colors.YELLOW}> Conversational Context{Colors.RESET}
  The AI remembers previous scans:
  • "Find subdomains of example.com" → "which look critical?"
  • "Scan 192.168.1.1" → "what services are running?"

{Colors.YELLOW}> Commands{Colors.RESET}
  • help       - Show this help
  • history    - Show conversation history
  • sessions   - List saved sessions
  • load <id>  - Load a previous session
  • results    - List saved result files
  • workflows  - List available workflows
  • switch     - Switch LLM model 
  • verbose    - Toggle raw output display on/off
  • guardrails - Toggle security guardrails on/off
  • clear      - Clear conversation memory
  • quit/exit  - Exit SNODE

{Colors.YELLOW}> Workflows (LangGraph-powered){Colors.RESET}
  • recon <domain>          - Smart recon with conditional branching
  • vuln_scan <target>      - Vulnerability assessment
  • attack_surface <domain> - Attack surface mapping
  
  Or just ask naturally: "find subdomains of example.com"
""")


def main():
    """Main entry point"""
    clear_screen()
    print_banner()
    
    # Parse command line args
    verbose = False
    use_config = True  
    cmd_model = None
    
    for arg in sys.argv[1:]:
        if arg.startswith("--model="):
            cmd_model = arg.split("=")[1]
            use_config = False
        elif arg == "--setup":
            # Force interactive setup
            config = get_llm_config()
            config.interactive_setup()
            use_config = True
        elif arg == "--verbose" or arg == "-v":
            verbose = True
    
    # Get model from config or command line
    llm_config = get_llm_config()
    model = cmd_model if cmd_model else llm_config.get_model()
    
    print(f"{Colors.DIM}🔧 Initializing SNODE with model: {model}{Colors.RESET}")
    print(f"{Colors.DIM}   This may take a moment...{Colors.RESET}\n")
    
    try:
        agent = create_agent(model=model, verbose=verbose)
        print(f"{Colors.GREEN}✓{Colors.RESET} Agent ready!\n")
    except Exception as e:
        print(f"{Colors.RED}✗{Colors.RESET} Failed to initialize: {e}")
        print(f"\n{Colors.DIM}Make sure Ollama is running:{Colors.RESET}")
        print(f"  ollama pull {model}")
        print(f"  ollama serve")
        return 1
    
    print_system_info(agent)
    
    # Create interactive input handler with history support
    input_handler = create_input_handler(
        prompt=f"{Colors.CYAN}SNODE{Colors.RESET}> ",
        history_file=".snode_history"
    )
    
    # Main loop
    while True:
        try:
            user_input = input_handler.input().strip()
            
            if not user_input:
                continue
            
            # Handle special commands
            if user_input.lower() in ["exit", "quit", "q"]:
                print(f"\n{Colors.YELLOW}Goodbye!{Colors.RESET}\n")
                break
            
            if user_input.lower() == "help":
                print_help(agent)
                continue
            
            if user_input.lower() == "clear":
                agent.clear_memory()
                print(f"{Colors.GREEN}✓{Colors.RESET} Conversation memory cleared.\n")
                continue
            
            if user_input.lower() == "history":
                if agent.messages:
                    print(f"\n{Colors.CYAN}📜 Conversation History:{Colors.RESET}")
                    for i, msg in enumerate(agent.messages):
                        role = "You" if hasattr(msg, 'type') and msg.type == 'human' else "SNODE"
                        # Truncate long content
                        content = msg.content
                        if len(content) > 150:
                            content = content[:150] + "..."
                        print(f"  {Colors.DIM}[{i+1}]{Colors.RESET} {Colors.BOLD}{role}:{Colors.RESET} {content}")
                    print()
                else:
                    print(f"\n{Colors.DIM}📜 No conversation history yet.{Colors.RESET}\n")
                continue
            
            if user_input.lower() == "banner":
                clear_screen()
                print_banner()
                print_system_info(agent)
                continue
            
            if user_input.lower() == "sessions":
                sessions = agent.list_sessions()
                if sessions:
                    print(f"\n{Colors.CYAN}📁 Saved Sessions:{Colors.RESET}")
                    for i, s in enumerate(sessions[:10]):  # Show last 10
                        msg_count = s['messages']
                        created = s['created'][:16] if len(s['created']) > 16 else s['created']
                        current = " (current)" if s['id'] == agent.session_id else ""
                        print(f"  {Colors.DIM}[{i+1}]{Colors.RESET} {s['id'][:20]}... | {msg_count} msgs | {created}{Colors.GREEN}{current}{Colors.RESET}")
                    print(f"\n{Colors.DIM}Use 'load <session_id>' to restore a session{Colors.RESET}\n")
                else:
                    print(f"\n{Colors.DIM}📁 No saved sessions yet.{Colors.RESET}\n")
                continue
            
            if user_input.lower().startswith("load "):
                session_id = user_input[5:].strip()
                if agent.load_session(session_id):
                    print(f"{Colors.GREEN}✓{Colors.RESET} Loaded session: {session_id}")
                    print(f"  {len(agent.messages)} messages restored.\n")
                else:
                    print(f"{Colors.RED}✗{Colors.RESET} Session not found: {session_id}\n")
                continue
            
            if user_input.lower() == "guardrails":
                agent.guardrails_enabled = not agent.guardrails_enabled
                state = "ON" if agent.guardrails_enabled else "OFF"
                color = Colors.GREEN if agent.guardrails_enabled else Colors.RED
                print(f"🛡️ Security guardrails: {color}{state}{Colors.RESET}")
                if not agent.guardrails_enabled:
                    print(f"  {Colors.YELLOW}⚠️  Warning: Prompt injection protection disabled!{Colors.RESET}\n")
                else:
                    print()
                continue
            
            if user_input.lower() == "verbose":
                agent.show_raw_results = not agent.show_raw_results
                state = "ON" if agent.show_raw_results else "OFF"
                color = Colors.GREEN if agent.show_raw_results else Colors.DIM
                print(f"📊 Raw output display: {color}{state}{Colors.RESET}")
                if agent.show_raw_results:
                    print(f"  Tool results will be shown before AI analysis.\n")
                else:
                    print(f"  Only AI analysis will be shown.\n")
                continue
            
            if user_input.lower() == "results":
                import os
                results_dir = agent.results_dir
                if results_dir.exists():
                    files = sorted(results_dir.glob("*.json"), key=os.path.getmtime, reverse=True)[:10]
                    if files:
                        print(f"\n{Colors.CYAN}📁 Recent Results:{Colors.RESET}")
                        for f in files:
                            size = f.stat().st_size
                            print(f"  {Colors.DIM}•{Colors.RESET} {f.name} ({size} bytes)")
                        print(f"\n{Colors.DIM}Results saved in: {results_dir}{Colors.RESET}\n")
                    else:
                        print(f"\n{Colors.DIM}📁 No result files yet.{Colors.RESET}\n")
                else:
                    print(f"\n{Colors.DIM}📁 Results directory not created yet.{Colors.RESET}\n")
                continue
            
            # Switch model command
            if user_input.lower() == "switch" or user_input.lower().startswith("switch "):
                parts = user_input.split(maxsplit=1)
                if len(parts) == 1:
                    # Show available models
                    print(f"\n{Colors.CYAN}🔄 Switch LLM Model{Colors.RESET}")
                    print(f"   Current: {Colors.GREEN}{agent.model_name}{Colors.RESET}")
                    print(f"\n   Usage: switch <model_name>")
                    print(f"   Example: switch llama3.2")
                    print(f"\n{Colors.DIM}Available models depend on your Ollama setup.{Colors.RESET}")
                    print(f"{Colors.DIM}Run 'ollama list' in terminal to see installed models.{Colors.RESET}\n")
                else:
                    new_model = parts[1].strip()
                    try:
                        old_model = agent.model_name
                        agent = create_agent(model=new_model, verbose=verbose)
                        print(f"\n{Colors.GREEN}✓ Model switched: {old_model} → {new_model}{Colors.RESET}\n")
                    except Exception as e:
                        print(f"\n{Colors.RED}✗ Failed to switch model: {e}{Colors.RESET}\n")
                continue
            
            # Workflow commands
            if user_input.lower() == "workflows":
                print(f"\n{Colors.CYAN}🔀 Available Multi-Tools Workflows:{Colors.RESET}")
                print(f"  • {Colors.BOLD}recon{Colors.RESET}: Smart reconnaissance with conditional branching")
                print(f"  • {Colors.BOLD}vuln_scan{Colors.RESET}: Vulnerability assessment workflow")
                print(f"  • {Colors.BOLD}attack_surface{Colors.RESET}: Attack surface mapping")
                print(f"\n{Colors.DIM}Usage: recon <domain>, vuln_scan <target>, attack_surface <domain>{Colors.RESET}")
                print(f"{Colors.DIM}Or ask naturally: 'find subdomains of example.com'{Colors.RESET}\n")
                continue
            
            # Workflow: smart_recon (LangGraph-based with conditional branching)
            if user_input.lower().startswith("smart_recon "):
                target = user_input.split(" ", 1)[1].strip()
                print(f"\n{Colors.YELLOW}{'═'*60}{Colors.RESET}")
                try:
                    from snode_langchain.orchestration import SmartReconGraph, LANGGRAPH_AVAILABLE
                    if LANGGRAPH_AVAILABLE:
                        graph = SmartReconGraph(agent)
                        result = graph.run(target)
                        # Display summary
                        print(f"\n📋 Summary:")
                        print(f"   Subdomains: {len(result['subdomains'])}")
                        print(f"   Hosts scanned: {len(result['open_ports'])}")
                        print(f"   Technologies: {len(result['technologies'])}")
                        print(f"   Vulnerabilities: {len(result['vulnerabilities'])}")
                    else:
                        print(f"{Colors.RED}LangGraph not available. Install: pip install langgraph{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}Error: {e}{Colors.RESET}")
                print(f"{Colors.YELLOW}{'═'*60}{Colors.RESET}\n")
                continue
            
            # Workflow: recon (use SmartReconGraph)
            if user_input.lower().startswith("recon "):
                target = user_input.split(" ", 1)[1].strip()
                print(f"\n{Colors.YELLOW}{'═'*60}{Colors.RESET}")
                try:
                    from snode_langchain.orchestration import SmartReconGraph
                    graph = SmartReconGraph(agent)
                    result = graph.run(target)
                except Exception as e:
                    print(f"{Colors.RED}Error: {e}{Colors.RESET}")
                print(f"{Colors.YELLOW}{'═'*60}{Colors.RESET}\n")
                continue
            
            # Workflow: vuln_scan (use VulnScanGraph)
            if user_input.lower().startswith("vuln_scan "):
                target = user_input.split(" ", 1)[1].strip()
                print(f"\n{Colors.YELLOW}{'═'*60}{Colors.RESET}")
                try:
                    from snode_langchain.orchestration import VulnScanGraph
                    graph = VulnScanGraph(agent)
                    result = graph.run(target)
                    print(graph.format_results(result))
                except Exception as e:
                    print(f"{Colors.RED}Error: {e}{Colors.RESET}")
                print(f"{Colors.YELLOW}{'═'*60}{Colors.RESET}\n")
                continue
            
            # Workflow: attack_surface (use AttackSurfaceGraph)
            if user_input.lower().startswith("attack_surface "):
                target = user_input.split(" ", 1)[1].strip()
                print(f"\n{Colors.YELLOW}{'═'*60}{Colors.RESET}")
                try:
                    from snode_langchain.orchestration import AttackSurfaceGraph
                    graph = AttackSurfaceGraph(agent)
                    result = graph.run(target)
                    print(graph.format_results(result))
                except Exception as e:
                    print(f"{Colors.RED}Error: {e}{Colors.RESET}")
                print(f"{Colors.YELLOW}{'═'*60}{Colors.RESET}\n")
                continue
            
            # Process user input
            print(f"\n{Colors.DIM}Processing: {user_input[:50]}...{Colors.RESET}")
            
            response = agent.run(user_input)
            
            # Display response with clean formatting (dynamic width)
            width = get_terminal_width() - 4  # Leave some margin
            print(f"\n{Colors.CYAN}╔{'═'*width}╗{Colors.RESET}")
            print(f"{Colors.CYAN}║{Colors.RESET} {Colors.BOLD}🔒 SNODE Analysis{Colors.RESET}")
            print(f"{Colors.CYAN}╠{'═'*width}╣{Colors.RESET}")
            print(f"{Colors.CYAN}║{Colors.RESET}")
            # Print full response without truncation
            for line in response.split('\n'):
                print(f"{Colors.CYAN}║{Colors.RESET}  {line}")
            print(f"{Colors.CYAN}║{Colors.RESET}")
            print(f"{Colors.CYAN}╚{'═'*width}╝{Colors.RESET}\n")
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}Interrupted. Type 'quit' to exit.{Colors.RESET}\n")
            continue
        
        except EOFError:
            print(f"\n{Colors.YELLOW}Input stream closed. Exiting...{Colors.RESET}\n")
            break
        
        except Exception as e:
            error_msg = str(e) if str(e) else type(e).__name__
            print(f"\n{Colors.RED}Error: {error_msg}{Colors.RESET}\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
