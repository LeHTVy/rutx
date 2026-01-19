"""
Scan Agent - Port Scanning and Service Enumeration (Phase 2)
=============================================================

Specializes in port scanning, directory bruteforcing, service detection.
Tools: nmap, masscan, gobuster, dirsearch, httpx
"""
from typing import Dict, Any, List
from .base_agent import BaseAgent
from app.ui import get_logger

logger = get_logger()


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
    
    AGENT_NAME = "scan"
    AGENT_DESCRIPTION = "Port scanning, service detection, and directory enumeration"
    SPECIALIZED_TOOLS = [
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
    PENTEST_PHASES = [2]  # Scanning phase
    
    def __init__(self, llm=None):
        super().__init__(llm)
        self.name = self.AGENT_NAME
        self.description = self.AGENT_DESCRIPTION
        # Keep for backward compatibility
        self.specialized_tools = self.SPECIALIZED_TOOLS
        self.pentest_phases = self.PENTEST_PHASES
    
    def plan(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Plan scanning tools and actions."""
        tools = self._select_tools(query, context)
        commands = self._get_suggested_commands(tools, context)
        
        # Handle empty tools list
        if not tools:
            reasoning = "Phase 2 (Scanning): No tools selected - all scanning tools already run or unavailable"
        else:
            reasoning = f"Phase 2 (Scanning): Selected {', '.join(tools)} for port/service enumeration"
        
        return {
            "agent": self.name,
            "tools": tools,
            "commands": commands,
            "reasoning": reasoning
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
            
            # Use planner model for tool selection
            llm = OllamaClient(model="planner")
            response = llm.generate(prompt, timeout=10, stream=False).strip().lower()
            
            # Extract valid scan type
            valid_types = ["port_scan", "dir_bruteforce", "http_probe", "smb_enum", "full_scan"]
            for scan_type in valid_types:
                if scan_type in response:
                    return scan_type
            
        except Exception as e:
            logger.warning(f"LLM classification failed: {e}", icon="")
        
        return "full_scan"
    
    def _select_tools(self, query: str, context: Dict[str, Any]) -> List[str]:
        """
        Select appropriate scanning tools using vector search + agent intelligence.
        
        HYBRID APPROACH:
        1. Check user/analyzer requested tools (highest priority)
        2. Use ChromaDB vector search to discover relevant tools
        3. Filter and rank by agent's specialized_tools and context
        4. Fallback to specialized_tools if vector search fails
        """
        tools = []
        tools_run = set(context.get("tools_run", []))
        
        # PRIORITY 1: User/analyzer requested tools
        user_requested_tool = context.get("user_requested_tool")
        analyzer_next_tool = context.get("analyzer_next_tool")
        requested_tool = user_requested_tool or analyzer_next_tool
        if requested_tool:
            if requested_tool in self.specialized_tools and self.registry.is_available(requested_tool):
                if requested_tool not in tools_run:
                    tools.append(requested_tool)
                    return tools  # Return early with requested tool
        
        # PRIORITY 2: Vector search discovery
        discovered = self._discover_tools_via_rag(query, context, n_results=10)
        
        # Filter discovered tools: must be available, in specialized_tools, and not already run
        for match in discovered:
            tool_name = match["tool"]
            if (tool_name in self.specialized_tools and 
                self.registry.is_available(tool_name) and 
                tool_name not in tools_run):
                tools.append(tool_name)
                # Limit to top 3 tools from vector search
                if len(tools) >= 3:
                    break
        
        # PRIORITY 3: Fallback to classification-based selection if vector search found nothing
        if not tools:
            scan_type = self._classify_scan_type(query, context)
            
            # Map scan types to tool preferences (still use classification as fallback)
            type_tool_map = {
                "port_scan": ["nmap", "masscan"],
                "dir_bruteforce": ["gobuster", "dirsearch", "feroxbuster"],
                "http_probe": ["httpx"],
                "smb_enum": ["enum4linux", "nbtscan"],
                "full_scan": ["nmap", "httpx"],
            }
            
            preferred_tools = type_tool_map.get(scan_type, ["nmap"])
            for tool in preferred_tools:
                if self.registry.is_available(tool) and tool not in tools_run:
                    tools.append(tool)
                    break
        
        # FINAL FALLBACK: Select any available specialized tool
        if not tools:
            for tool in self.specialized_tools:
                if self.registry.is_available(tool) and tool not in tools_run:
                    tools.append(tool)
                    break
        
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
