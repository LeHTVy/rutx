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
    """
    
    # Keywords that trigger this agent
    SCAN_KEYWORDS = [
        "scan", "port", "nmap", "masscan", "service", "open port",
        "gobuster", "dirsearch", "directory", "enum", "probe",
        "httpx", "http", "discover", "enumerate"
    ]
    
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
        
        self.keywords = self.SCAN_KEYWORDS
    
    def can_handle(self, phase: int, query: str) -> bool:
        """Check if this agent should handle the query."""
        # Handle if in scanning phase or explicit scan request
        if phase == 2:
            return True
        return any(kw in query.lower() for kw in self.SCAN_KEYWORDS)
    
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
        """Analyze scanning results and suggest next steps."""
        analysis = []
        
        for tool, result in results.items():
            if not result.get("success"):
                continue
            
            output = result.get("output", "")
            
            if tool == "nmap":
                # Check for open ports
                open_ports = []
                if "open" in output:
                    analysis.append(f"✅ nmap found open ports")
                    # Suggest vuln scan next
                    analysis.append("  → Next: Run nuclei or nikto for vulnerability scanning")
                    
            elif tool == "httpx":
                # Count live hosts
                if "200" in output or "301" in output:
                    analysis.append("✅ httpx found live HTTP endpoints")
                    analysis.append("  → Next: Run gobuster for directory enumeration")
                    
            elif tool in ["gobuster", "dirsearch"]:
                if "Status: 200" in output or "200 -" in output:
                    analysis.append("✅ Directory bruteforce found endpoints")
                    analysis.append("  → Next: Run nuclei to scan discovered endpoints")
        
        if not analysis:
            analysis.append("⚠️ No significant findings from scan")
            analysis.append("  → Try different scan options or tools")
        
        return "\n".join(analysis)
