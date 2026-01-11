#!/usr/bin/env python3
"""
SNODE CLI - Main Entry Point
=============================

Enhanced with Gemini CLI-like features:
- Tab autocomplete
- Command history (arrow keys)
- Thinking spinner
- /clear command
"""
import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.spinner import Spinner
from rich.live import Live

# prompt_toolkit for enhanced input
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter, Completer, Completion
from prompt_toolkit.styles import Style


def print_banner(console: Console):
    """Print SNODE banner."""
    banner = """
░██████╗███╗░░██╗░█████╗░██████╗░███████╗
██╔════╝████╗░██║██╔══██╗██╔══██╗██╔════╝
╚█████╗░██╔██╗██║██║░░██║██║░░██║█████╗░░
░╚═══██╗██║╚████║██║░░██║██║░░██║██╔══╝░░
██████╔╝██║░╚███║╚█████╔╝██████╔╝███████╗
╚═════╝░╚═╝░░╚══╝░╚════╝░╚═════╝░╚══════╝
    Security Node - Autonomous AI Agent
    """
    console.print(Panel(banner, style="bold cyan", border_style="cyan"))


class SnodeCompleter(Completer):
    """Smart autocomplete for SNODE CLI."""
    
    def __init__(self, context: dict = None):
        self.context = context or {}
        
        # Slash commands
        self.slash_commands = [
            "/model", "/resume", "/sessions", "/memory", "/tools", 
            "/cve", "/report", "/shortcuts", "/clear", "/help"
        ]
        
        # Quick commands
        self.quick_commands = [
            "scan", "portscan", "fullscan", "vuln", "nikto", "web", 
            "dirs", "fuzz", "recon", "subs", "full", "pentest",
            "whois", "dns", "tech", "brute", "crack", "map"
        ]
        
        # Tool names (will be populated dynamically)
        self.tools = [
            "nmap", "nuclei", "nikto", "gobuster", "ffuf", "subfinder",
            "httpx", "amass", "hydra", "medusa", "john", "hashcat",
            "sqlmap", "katana", "theHarvester", "bbot", "feroxbuster",
            "searchsploit", "dig", "whois", "masscan", "cpanelbrute",
            "passgen", "credcheck"
        ]
        
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor.lower()
        word = document.get_word_before_cursor()
        
        # Complete slash commands
        if text.startswith("/"):
            for cmd in self.slash_commands:
                if cmd.startswith(text):
                    yield Completion(cmd, start_position=-len(text))
        
        # Complete quick commands (at start of line)
        elif not " " in text:
            for cmd in self.quick_commands:
                if cmd.startswith(word.lower()):
                    yield Completion(cmd, start_position=-len(word))
        
        # Complete tool names after "use"
        elif "use " in text:
            for tool in self.tools:
                if tool.lower().startswith(word.lower()):
                    yield Completion(tool, start_position=-len(word))
        
        # Complete recent targets
        if self.context.get("last_domain"):
            domain = self.context["last_domain"]
            if word and domain.startswith(word):
                yield Completion(domain, start_position=-len(word))


# Prompt style
PROMPT_STYLE = Style.from_dict({
    'prompt': 'ansicyan bold',
})


def run_snode():
    """Run the SNODE CLI with LangGraph agent."""
    console = Console()
    print_banner(console)
    
    # Import after path setup - use LangGraph agent
    from app.agent.graph import LangGraphAgent
    from app.core.config import get_config
    from app.llm import get_llm_config
    
    config = get_config()
    llm_config = get_llm_config()
    
    # Initialize persistent memory
    try:
        from app.memory import get_memory_manager
        memory = get_memory_manager()
        memory.start_session()
    except Exception as e:
        print(f"⚠️ Memory init failed: {e}")
        memory = None
    
    # Create the LangGraph agent
    agent = LangGraphAgent()
    
    # Context for conversation
    context = {
        "last_domain": None,
        "has_subdomains": False,
        "has_ports": False,
    }
    
    # Setup enhanced input with history and autocomplete
    history_file = Path.home() / ".snode_history"
    completer = SnodeCompleter(context)
    session = PromptSession(
        history=FileHistory(str(history_file)),
        auto_suggest=AutoSuggestFromHistory(),
        completer=completer,
        complete_while_typing=False,  # Only on Tab
    )
    
    model_name = llm_config.get_model()
    console.print(f"\n[bold green]🤖 Snode Agent Ready![/] [dim](Model: {model_name})[/]")
    console.print("[dim]Type 'help' for commands, Tab for autocomplete, ↑/↓ for history[/]")
    console.print("[dim]Quick: scan, vuln, recon, web, full + target[/]")
    console.print("[dim]Use @file.txt to load targets, ``` for multi-line input[/]\n")
    
    while True:
        try:
            # Use prompt_toolkit for enhanced input
            user_input = session.prompt("SNODE> ").strip()
            
            if not user_input:
                continue
            
            # Multi-line input mode (start with ```)
            if user_input.startswith("```"):
                console.print("[dim]Multi-line mode. Enter ``` on new line to finish:[/]")
                lines = [user_input[3:]] if len(user_input) > 3 else []
                while True:
                    line = session.prompt("... ")
                    if line.strip() == "```":
                        break
                    lines.append(line)
                user_input = "\n".join(lines)
                console.print(f"[dim]Got {len(lines)} lines[/]")
            
            # Parse @file.txt syntax - load file contents
            import re
            file_matches = re.findall(r'@([^\s]+\.(?:txt|list|csv))', user_input)
            if file_matches:
                for file_path in file_matches:
                    try:
                        # Try relative and absolute paths
                        if os.path.exists(file_path):
                            full_path = file_path
                        elif os.path.exists(f"discoveries/{file_path}"):
                            full_path = f"discoveries/{file_path}"
                        elif os.path.exists(os.path.expanduser(f"~/{file_path}")):
                            full_path = os.path.expanduser(f"~/{file_path}")
                        else:
                            console.print(f"[red]File not found: {file_path}[/]")
                            continue
                        
                        with open(full_path, 'r') as f:
                            file_content = f.read().strip()
                        
                        # Parse targets from file (one per line)
                        targets = [line.strip() for line in file_content.split('\n') if line.strip()]
                        console.print(f"[green]📁 Loaded {len(targets)} targets from {file_path}[/]")
                        
                        # Replace @file with comma-separated targets
                        user_input = user_input.replace(f"@{file_path}", ", ".join(targets[:20]))
                        if len(targets) > 20:
                            console.print(f"[yellow]⚠️ Truncated to first 20 targets[/]")
                        
                    except Exception as e:
                        console.print(f"[red]Error reading {file_path}: {e}[/]")
            
            # /clear command
            if user_input.lower() == "/clear":
                os.system('clear' if os.name == 'posix' else 'cls')
                print_banner(console)
                continue
            
            if user_input.lower() in ["exit", "quit", "q"]:
                # End session on exit
                if memory:
                    memory.end_session()
                console.print("[yellow]Goodbye![/]")
                break
            
            if user_input.lower() == "help":
                _print_help(console)
                continue
            
            # Model switch command
            if user_input.lower().startswith("/model"):
                parts = user_input.split(maxsplit=1)
                if len(parts) == 1:
                    # Show available models
                    import subprocess
                    from app.agent.graph import get_current_model
                    result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
                    console.print(f"\n[bold]Current model:[/] {get_current_model()}")
                    console.print(f"\n[bold]Available models:[/]\n{result.stdout}")
                    console.print("[dim]Usage: /model <model_name>[/]\n")
                else:
                    new_model = parts[1].strip()
                    from app.agent.graph import set_current_model
                    set_current_model(new_model)
                    llm_config.set_model(new_model)
                    # Clear agent's LLM cache to use new model
                    agent.messages = []
                    console.print(f"[green]✅ Switched to model: {new_model}[/]\n")
                continue
            
            # Resume session command
            if user_input.lower().startswith("/resume"):
                if not memory:
                    console.print("[yellow]⚠️ Memory system not available[/]\n")
                    continue
                
                # Check if specific session ID provided
                parts = user_input.split()
                session_id = parts[1] if len(parts) > 1 else None
                
                result = memory.resume_session(session_id)
                if result:
                    resumed_context = result.get("context", {})
                    # Update local context with restored session data
                    if resumed_context:
                        context.update(resumed_context)
                    
                    # Show resume info
                    domain = resumed_context.get("last_domain") or memory.target_domain or "No domain"
                    console.print(f"[green]✅ Resumed session: {result['session_id'][:8]}...[/]")
                    console.print(f"[dim]Target: {domain}[/]")
                    if result.get("summary"):
                        console.print(f"[dim]Summary: {result['summary']}[/]")
                    
                    # Show what's in context
                    if resumed_context.get("subdomain_count"):
                        console.print(f"[dim]Subdomains: {resumed_context.get('subdomain_count')}[/]")
                    if resumed_context.get("detected_tech"):
                        console.print(f"[dim]Tech: {', '.join(resumed_context.get('detected_tech', [])[:3])}[/]")
                    console.print()
                else:
                    console.print("[yellow]No previous session found[/]\n")
                continue
            
            # List sessions command
            if user_input.lower().startswith("/sessions"):
                if not memory:
                    console.print("[yellow]⚠️ Memory system not available[/]\n")
                    continue
                
                console.print("\n[bold cyan]📋 Available Sessions[/]")
                from app.memory.postgres import get_postgres
                pg = get_postgres()
                from psycopg2.extras import RealDictCursor
                with pg.conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute('''
                        SELECT session_id, target_domain, context, started_at, last_active 
                        FROM sessions 
                        ORDER BY last_active DESC 
                        LIMIT 10
                    ''')
                    sessions = cur.fetchall()
                    
                    for s in sessions:
                        sid = str(s['session_id'])  # Full UUID
                        ctx = s.get('context', {}) or {}
                        domain = ctx.get('last_domain') or s.get('target_domain') or 'no domain'
                        last = s.get('last_active')
                        console.print(f"  [bold]{sid}[/] - {domain}")
                console.print("\n[dim]Use /resume <session_id> to resume a specific session[/]\n")
                continue
            
            # Memory stats command
            if user_input.lower().startswith("/memory"):
                if not memory:
                    console.print("[yellow]⚠️ Memory system not available[/]\n")
                    continue
                
                console.print("\n[bold cyan]📊 Memory Stats[/]")
                console.print(f"  Session: {memory.session_id[:8] if memory.session_id else 'None'}...")
                console.print(f"  Vector count: {memory.vector.count()}")
                
                # Show recent messages
                from app.memory.postgres import get_postgres
                pg = get_postgres()
                recent = pg.get_recent_messages_all_sessions(limit=5)
                if recent:
                    console.print("\n[bold]Recent messages:[/]")
                    for msg in recent:
                        role = "👤" if msg["role"] == "user" else "🤖"
                        content = msg["content"][:50]
                        console.print(f"  {role} {content}...")
                console.print()
                continue  # Don't process /memory through LLM
            
            # Tools list command
            if user_input.lower() in ["/tools", "/tool", "tools"]:
                from app.tools.registry import get_registry, ToolCategory
                registry = get_registry()
                
                console.print("\n[bold cyan]📦 Available Security Tools[/]\n")
                
                # Group by category
                by_category = {}
                for name in registry.list_tools():
                    spec = registry.tools.get(name)
                    if spec:
                        cat = spec.category.value
                        if cat not in by_category:
                            by_category[cat] = []
                        by_category[cat].append((name, spec.description[:50]))
                
                # Display by category
                icons = {
                    "recon": "🔍", "scanning": "📡", "vulnerability": "🛡️",
                    "exploitation": "💥", "enumeration": "📋", "osint": "🌐",
                    "brute_force": "🔓", "utility": "🔧"
                }
                
                for cat, tools in sorted(by_category.items()):
                    icon = icons.get(cat, "•")
                    console.print(f"[bold]{icon} {cat.upper()}[/]")
                    for name, desc in tools:
                        console.print(f"  [green]• {name}[/]: [dim]{desc}...[/]")
                    console.print()
                
                # Count
                total = sum(len(t) for t in by_category.values())
                console.print(f"[dim]Total: {total} tools available[/]\n")
                continue
            
            # CVE search command
            if user_input.lower().startswith("/cve"):
                parts = user_input.split(maxsplit=1)
                query = parts[1] if len(parts) > 1 else None
                
                # If no query, show CVEs from last scan
                if not query and context.get("last_cves"):
                    console.print(f"\n[bold cyan]🔍 CVEs found for: {context.get('cve_query', 'last scan')}[/]\n")
                    for cve in context["last_cves"]:
                        severity = cve.get("severity", "Unknown")
                        color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan"}.get(severity, "white")
                        console.print(f"[bold {color}]{cve.get('cve_id')}[/] ({severity})")
                        console.print(f"  {cve.get('description', 'No description')[:150]}...")
                        if cve.get("cvss"):
                            console.print(f"  [dim]CVSS: {cve.get('cvss')}[/]")
                        console.print()
                    continue
                
                # Otherwise search for new query
                search_query = query or context.get("last_domain", "")
                if not search_query:
                    console.print("[yellow]Usage: /cve <search term>[/]")
                    console.print("[dim]Example: /cve apache, /cve wordpress, /cve ssh[/]\n")
                    continue
                
                console.print(f"\n[bold cyan]🔍 Searching CVEs for: {search_query}[/]\n")
                
                try:
                    from app.rag.cve_rag import search_cves
                    results = search_cves(search_query, n_results=10)
                    
                    if results.get("cves"):
                        for cve in results["cves"]:
                            severity = cve.get("severity", "Unknown")
                            color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan"}.get(severity, "white")
                            console.print(f"[bold {color}]{cve.get('cve_id')}[/] ({severity})")
                            console.print(f"  {cve.get('description', 'No description')[:150]}...")
                            if cve.get("cvss"):
                                console.print(f"  [dim]CVSS: {cve.get('cvss')}[/]")
                            console.print()
                    else:
                        console.print("[dim]No CVEs found for this query[/]\n")
                except Exception as e:
                    console.print(f"[red]❌ CVE search failed: {e}[/]\n")
                
                continue
            
            # Report generation command
            if user_input.lower() in ["/report", "/rep", "report"]:
                if not context.get("last_domain"):
                    console.print("[yellow]⚠️ No scan data available. Run some scans first![/]\n")
                    continue
                
                console.print("\n[bold cyan]🤖 Generating Report with CrewAI...[/]\n")
                
                try:
                    from app.reporting import create_report_crew
                    
                    crew = create_report_crew()
                    
                    # Get results from agent's last execution
                    last_results = getattr(agent, 'last_results', {})
                    
                    result = crew.generate_report(
                        context=context,
                        results=last_results,
                        output_dir="reports"
                    )
                    
                    console.print(f"\n[green]✅ Report generated![/]")
                    console.print(f"[bold]File:[/] {result['file_path']}\n")
                    
                    # Show executive summary
                    console.print(Panel(
                        Markdown(result['summary']),
                        title="📋 Executive Summary",
                        border_style="cyan"
                    ))
                    
                except Exception as e:
                    console.print(f"[red]❌ Report generation failed: {e}[/]\n")
                
                continue
            
            # ============================================================
            # AUTONOMOUS MODE - Self-driving pentest
            # ============================================================
            if user_input.lower().startswith("auto ") or user_input.lower().startswith("autonomous "):
                # Extract target
                parts = user_input.split(maxsplit=1)
                task = parts[1] if len(parts) > 1 else ""
                
                if not task:
                    console.print("[yellow]Usage: auto <target or task>[/]")
                    console.print("[dim]Example: auto attack example.com[/]")
                    console.print("[dim]         auto find vulns in 192.168.1.0/24[/]\n")
                    continue
                
                console.print(f"\n[bold cyan]🤖 Starting Autonomous Mode[/]")
                console.print(f"[dim]Task: {task}[/]")
                console.print(f"[dim]Press Ctrl+C to stop at any time[/]\n")
                
                try:
                    from app.agent.orchestration import get_orchestrator, OrchestrationStatus
                    from app.cli.countdown import get_countdown_runner
                    
                    orchestrator = get_orchestrator()
                    runner = get_countdown_runner()
                    
                    # Run autonomous loop
                    for event in orchestrator.run_autonomous(task, context):
                        
                        if event.status == OrchestrationStatus.PLANNING:
                            console.print(f"[cyan]{event.message}[/]")
                        
                        elif event.status == OrchestrationStatus.COUNTDOWN:
                            # Show plan and countdown
                            console.print(event.message)
                            
                            # Run countdown
                            if not runner.countdown(event.countdown, "Auto-executing..."):
                                orchestrator.cancel()
                                console.print("[yellow]Autonomous mode cancelled[/]\n")
                                break
                        
                        elif event.status == OrchestrationStatus.EXECUTING:
                            console.print(f"[green]{event.message}[/]")
                        
                        elif event.status == OrchestrationStatus.ANALYZING:
                            console.print(f"[dim]{event.message}[/]")
                        
                        elif event.status == OrchestrationStatus.PHASE_COMPLETE:
                            console.print(f"\n[bold green]{event.message}[/]\n")
                            # Update local context
                            if event.data:
                                context.update(event.data)
                        
                        elif event.status == OrchestrationStatus.TASK_COMPLETE:
                            console.print(f"\n[bold cyan]{event.message}[/]")
                            
                            # Show summary
                            summary = event.data
                            if summary:
                                console.print(f"\n[bold]📊 Summary:[/]")
                                console.print(f"   Target: {summary.get('target', 'unknown')}")
                                console.print(f"   Subdomains: {summary.get('subdomains_found', 0)}")
                                console.print(f"   IPs: {summary.get('ips_found', 0)}")
                                console.print(f"   Open Ports: {summary.get('open_ports', 0)}")
                                console.print(f"   Vulns: {summary.get('vulnerabilities', 0)}")
                                console.print(f"   Tools: {', '.join(summary.get('tools_used', []))}")
                                console.print(f"   Runtime: {summary.get('runtime_seconds', 0):.1f}s")
                            console.print()
                            break
                        
                        elif event.status == OrchestrationStatus.CANCELLED:
                            console.print(f"[yellow]{event.message}[/]\n")
                            break
                        
                        elif event.status == OrchestrationStatus.ERROR:
                            console.print(f"[red]{event.message}[/]\n")
                            break
                    
                except KeyboardInterrupt:
                    console.print("\n[yellow]Autonomous mode stopped[/]\n")
                except Exception as e:
                    console.print(f"[red]Autonomous mode error: {e}[/]\n")
                    import traceback
                    traceback.print_exc()
                
                continue
            
            # ============================================================
            # QUICK COMMAND SHORTCUTS - Fast access to common operations
            # ============================================================
            # These shortcuts expand to full commands for faster workflow
            
            quick_commands = {
                # Reconnaissance shortcuts
                "scan": "use nmap quick scan on",
                "portscan": "use nmap syn scan on",
                "fullscan": "use nmap full scan on",
                
                # Vulnerability shortcuts
                "vuln": "use nuclei scan on",
                "vulnscan": "use nuclei scan on",
                "nikto": "use nikto on",
                
                # Web shortcuts
                "web": "use gobuster and nikto on",
                "dirs": "use gobuster on",
                "fuzz": "use ffuf on",
                
                # Subdomain/Recon shortcuts
                "recon": "use subfinder and httpx on",
                "subs": "use subfinder on",
                "subdomains": "use subfinder on",
                
                # Full pipeline
                "full": "use subfinder, nmap, nuclei on",
                "pentest": "use nmap, nikto, nuclei, gobuster on",
                
                # Info gathering
                "whois": "use whois on",
                "dns": "use dig on",
                "tech": "use httpx on",
                
                # Brute force
                "brute": "use hydra on",
                "crack": "use hydra ssh on",
            }
            
            # MAP COMMAND - Run tool on all discovered subdomains
            if user_input.lower().startswith("map "):
                parts = user_input.split(maxsplit=1)
                tool_to_run = parts[1].strip() if len(parts) > 1 else ""
                
                if not tool_to_run:
                    console.print("[yellow]Usage: map <tool>[/]")
                    console.print("[dim]Example: map httpx, map katana, map nuclei[/]\n")
                    continue
                
                subdomains = context.get("subdomains", [])
                if not subdomains:
                    console.print("[yellow]⚠️ No subdomains discovered yet.[/]")
                    console.print("[dim]Run 'subs <domain>' or 'recon <domain>' first.[/]\n")
                    continue
                
                console.print(f"\n[bold cyan]🗺️  Mapping {len(subdomains)} subdomains with {tool_to_run}[/]\n")
                
                # Run tool on each subdomain
                from app.tools.registry import get_registry
                registry = get_registry()
                
                if not registry.is_available(tool_to_run):
                    console.print(f"[red]❌ Tool '{tool_to_run}' not available[/]\n")
                    continue
                
                spec = registry.tools.get(tool_to_run)
                command = list(spec.commands.keys())[0]
                
                results_summary = []
                for i, subdomain in enumerate(subdomains[:20], 1):  # Limit to 20
                    console.print(f"  [{i}/{min(len(subdomains), 20)}] {subdomain}")
                    
                    # Prepare params based on tool
                    params = {"target": subdomain, "domain": subdomain}
                    if tool_to_run in ["httpx", "katana", "gobuster", "nikto", "nuclei"]:
                        params["url"] = f"https://{subdomain}"
                        params["target"] = f"https://{subdomain}"
                    if tool_to_run == "gobuster":
                        params["wordlist"] = "/usr/share/wordlists/dirb/common.txt"
                    
                    try:
                        result = registry.execute(tool_to_run, command, params, timeout_override=30)
                        if result.success and result.output.strip():
                            # Show summary
                            lines = result.output.strip().split('\n')
                            results_summary.append((subdomain, len(lines), lines[:3]))
                            console.print(f"    [green]✓ {len(lines)} results[/]")
                        else:
                            console.print(f"    [dim]No results[/]")
                    except Exception as e:
                        console.print(f"    [red]Error: {e}[/]")
                
                # Show summary
                if results_summary:
                    console.print(f"\n[bold green]📊 Map Results Summary:[/]")
                    for sub, count, sample in results_summary[:10]:
                        console.print(f"  • {sub}: {count} endpoints")
                        for line in sample:
                            console.print(f"    [dim]{line[:80]}[/]")
                else:
                    console.print(f"\n[yellow]No results from mapping.[/]")
                
                console.print()
                continue
            
            # Check for quick command
            input_parts = user_input.split(maxsplit=1)
            if len(input_parts) >= 1:
                cmd = input_parts[0].lower()
                if cmd in quick_commands:
                    target = input_parts[1] if len(input_parts) > 1 else context.get("last_domain", "")
                    if not target:
                        console.print(f"[yellow]Usage: {cmd} <target>[/]")
                        console.print(f"[dim]Example: {cmd} example.com[/]\n")
                        continue
                    # Expand to full command
                    user_input = f"{quick_commands[cmd]} {target}"
                    console.print(f"[dim]→ Expanding to: {user_input}[/]\n")
            
            # Show shortcuts command
            if user_input.lower() in ["/shortcuts", "/short", "/sc", "shortcuts"]:
                console.print("\n[bold cyan]⚡ Quick Command Shortcuts[/]\n")
                
                shortcut_groups = {
                    "🔍 SCANNING": ["scan <target>", "portscan <target>", "fullscan <target>"],
                    "🛡️ VULNERABILITIES": ["vuln <target>", "nikto <target>"],
                    "🌐 WEB": ["web <target>", "dirs <target>", "fuzz <target>"],
                    "📋 RECON": ["recon <target>", "subs <target>", "whois <target>", "dns <target>"],
                    "⚔️ ATTACK": ["brute <target>", "crack <target>"],
                    "🚀 FULL PIPELINE": ["full <target>", "pentest <target>"],
                }
                
                for group, shortcuts in shortcut_groups.items():
                    console.print(f"[bold]{group}[/]")
                    for sc in shortcuts:
                        # Get expansion
                        cmd = sc.split()[0]
                        expansion = quick_commands.get(cmd, "")
                        console.print(f"  [green]{sc}[/] → [dim]{expansion}...[/]")
                    console.print()
                
                console.print("[dim]Example: scan example.com[/]\n")
                continue
            
            # Run through LangGraph agent
            console.print(f"\n[dim]Processing: {user_input}...[/]\n")
            
            response, context, needs_confirmation = agent.run(user_input, context)
            
            # Display result
            console.print()
            
            if needs_confirmation:
                # Show suggestion with minimal formatting
                console.print(Panel(
                    Markdown(response),
                    title="💡 SNODE Suggestion",
                    border_style="yellow",
                ))
                console.print("[dim]Type 'yes' to proceed, 'no' to cancel[/]\n")
            else:
                # Show raw LLM response without box wrapper
                console.print(Markdown(response))
                console.print()  # Add spacing
            
            # Save to persistent memory
            if memory:
                try:
                    tools_used = context.get("tools_run", [])[-3:] if context.get("tools_run") else None
                    memory.save_turn(user_input, response, tools_used, context)
                except Exception as e:
                    pass  # Silent failure for memory
            
            console.print()  # Spacing before next prompt
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Type 'exit' to quit.[/]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/]")
            import traceback
            traceback.print_exc()


def _print_help(console: Console):
    """Print help information."""
    help_text = """
## 🤖 Autonomous Mode (NEW!)

Let SNODE run automatically with intelligent phase transitions:

```
auto attack example.com
auto find vulns in 192.168.1.0/24
autonomous pentest target.com
```

Shows plan → 5s countdown → Auto-executes → Chains phases

---

## Quick Commands (Shortcuts)

Fast commands for common operations:

| Command | Description |
|---------|-------------|
| `scan <target>` | Quick port scan |
| `vuln <target>` | Vulnerability scan |
| `recon <target>` | Subdomain + tech detection |
| `web <target>` | Directory + web scan |
| `full <target>` | Full pipeline scan |

Type `/shortcuts` to see all available shortcuts.

---

## Slash Commands

| Command | Description |
|---------|-------------|
| `/tools` | List all security tools |
| `/shortcuts` | Show all quick commands |
| `/model` | Change LLM model |
| `/cve <query>` | Search CVE database |
| `/memory` | Show memory stats |
| `/resume` | Resume previous session |
| `/report` | Generate pentest report |

---

## Natural Language

Just describe what you want:
- `Find vulnerabilities in example.com`
- `Scan ports on 192.168.1.1`
- `Check for SQL injection on target.com`

Type `exit` to quit.
"""
    console.print(Panel(Markdown(help_text), title="📖 SNODE Help", border_style="blue"))


def main():
    """Entry point."""
    run_snode()


if __name__ == "__main__":
    main()
