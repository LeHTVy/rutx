"""
Scan Agent - Port Scanning and Service Enumeration (Phase 2)
=============================================================

Specializes in port scanning, directory bruteforcing, service detection.
Tools: nmap, masscan, gobuster, dirsearch, httpx
"""
from typing import Dict, Any, List
from .base_agent import BaseAgent


class ScanAgent(BaseAgent):
    """
    Agent for Phase 2: Scanning & Enumeration.
    
    PTES Phase 2 Goals:
    - Find open ports (nmap, masscan)
    - Detect services and versions
    - Discover directories/files (gobuster, dirsearch)
    - HTTP probing (httpx)
    
    NOTE: Routing is handled by LLM in coordinator.py - no keyword matching needed.
    """
    
    def __init__(self, llm=None):
        super().__init__(llm)
        self.name = "scan"
        self.description = "Port scanning, service detection, and directory enumeration"
        
        # Phase 2 tools from tool specs
        self.specialized_tools = [
            # Port Scanning (specs/scanning.py, specs/network.py)
            "nmap",
            "masscan",
            "httpx",
            
            # Directory Bruteforce (specs/vuln.py, specs/web.py)
            "gobuster",
            "dirsearch",
            "feroxbuster",
            
            # Service Enumeration (specs/network.py)
            "netcat",
            "nbtscan",
            "enum4linux",
        ]
        
        self.pentest_phases = [2]  # Scanning phase
    
    def plan(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Plan scanning tools and actions."""
        tools = self._select_tools(query, context)
        commands = self._get_suggested_commands(tools, context)
        
        return {
            "agent": self.name,
            "tools": tools,
            "commands": commands,
            "reasoning": f"Phase 2 (Scanning): Selected {', '.join(tools)} for port/service enumeration"
        }
    
    def _classify_scan_type(self, query: str, context: Dict[str, Any] = None) -> str:
        """
        Classify what type of scan the user wants using LLM intelligence.
        
        NO HARDCODED KEYWORDS - LLM decides based on semantic understanding.
        """
        from app.agent.prompts import format_prompt
        from app.llm.client import OllamaClient
        
        context = context or {}
        
        try:
            prompt = format_prompt(
                "classify_scan",
                query=query,
                has_subdomains=context.get("has_subdomains", False),
                has_ports=context.get("has_ports", False),
                target=context.get("target_domain") or context.get("last_domain") or "not set"
            )
            
            llm = OllamaClient()
            response = llm.generate(prompt, timeout=10, stream=False).strip().lower()
            
            # Extract valid scan type
            valid_types = ["port_scan", "dir_bruteforce", "http_probe", "smb_enum", "full_scan"]
            for scan_type in valid_types:
                if scan_type in response:
                    return scan_type
            
        except Exception as e:
            print(f"  ⚠️ LLM classification failed: {e}")
        
        return "full_scan"
    
    def _select_tools(self, query: str, context: Dict[str, Any]) -> List[str]:
        """Select appropriate scanning tools based on context."""
        scan_type = self._classify_scan_type(query, context)
        tools = []
        
        if scan_type == "port_scan":
            # Prefer nmap for detailed scan, masscan for speed
            if "fast" in query.lower() or "quick" in query.lower():
                tools.append("masscan")
            else:
                tools.append("nmap")
                
        elif scan_type == "dir_bruteforce":
            # Directory bruteforce
            if self.registry.is_available("gobuster"):
                tools.append("gobuster")
            elif self.registry.is_available("dirsearch"):
                tools.append("dirsearch")
            elif self.registry.is_available("feroxbuster"):
                tools.append("feroxbuster")
                
        elif scan_type == "http_probe":
            tools.append("httpx")
            
        elif scan_type == "smb_enum":
            if self.registry.is_available("enum4linux"):
                tools.append("enum4linux")
            if self.registry.is_available("nbtscan"):
                tools.append("nbtscan")
                
        elif scan_type == "full_scan":
            # Full scan: port scan + http probe
            tools.append("nmap")
            tools.append("httpx")
        
        return tools
    
    def _get_suggested_commands(self, tools: List[str], context: Dict[str, Any]) -> Dict[str, str]:
        """
        Get recommended commands for selected tools.
        
        Dynamically looks up commands from actual tool specs - no hardcoding.
        """
        commands = {}
        
        # Command preferences based on context (ordered by priority)
        COMMAND_PREFERENCES = {
            "nmap": ["quick_scan", "service_scan", "tcp_scan"],  # Ordered by preference
            "masscan": ["scan", "fast_scan"],
            "httpx": ["probe", "tech_detect"],
            "gobuster": ["dir", "dns"],
            "dirsearch": ["scan", "ext"],
            "enum4linux": ["full", "shares"],
        }
        
        for tool in tools:
            spec = self.registry.tools.get(tool)
            if not spec or not spec.commands:
                continue
            
            available_commands = list(spec.commands.keys())
            
            # Use preference list if available
            if tool in COMMAND_PREFERENCES:
                for preferred in COMMAND_PREFERENCES[tool]:
                    if preferred in available_commands:
                        commands[tool] = preferred
                        break
            
            # If no preference matched or no preference exists, use first available
            if tool not in commands and available_commands:
                commands[tool] = available_commands[0]
        
        return commands
    
    def analyze_results(self, results: Dict[str, Any], context: Dict[str, Any]) -> str:
        """
        Analyze scanning results using semantic analysis.
        
        HYBRID APPROACH: Uses _analyze_output_semantic() for intelligent parsing.
        """
        analysis = []
        has_critical = False
        
        for tool, result in results.items():
            if not result.get("success"):
                analysis.append(f"❌ {tool}: {result.get('error', 'Failed')[:50]}")
                continue
            
            output = result.get("output", "")
            
            # Use semantic analysis instead of hardcoded checks
            parsed = self._analyze_output_semantic(tool, output)
            
            if parsed.get("has_findings"):
                severity = parsed.get("severity", "info")
                severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "✅")
                analysis.append(f"{severity_icon} {tool}: {parsed.get('summary', 'Findings detected')}")
                
                if parsed.get("key_items"):
                    for item in parsed["key_items"][:3]:
                        analysis.append(f"   • {item}")
                
                if severity in ["critical", "high"]:
                    has_critical = True
            else:
                analysis.append(f"ℹ️ {tool}: {parsed.get('summary', 'No significant findings')}")
        
        # Suggest next step based on overall findings
        if has_critical:
            analysis.append("\n→ Next: Move to Phase 3 - Vulnerability scanning (nuclei/nikto)")
        elif any(p.get("has_findings") for p in [self._analyze_output_semantic(t, r.get("output", "")) 
                                                   for t, r in results.items() if r.get("success")]):
            analysis.append("\n→ Next: Continue enumeration or run vulnerability scanners")
        else:
            analysis.append("\n→ Try different scan options or check target accessibility")
        
        return "\n".join(analysis)
