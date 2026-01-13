"""
Vulnerability Assessment Agent - Phase 3
=========================================

Specializes in vulnerability detection and CVE identification.
Tools: nuclei, nikto, nessus, burpsuite, wpscan
"""
from typing import Dict, Any, List
from .base_agent import BaseAgent


class VulnAgent(BaseAgent):
    """
    Agent for Phase 3: Vulnerability Assessment.
    
    PTES Phase 3 Goals:
    - Scan for known CVEs (nuclei)
    - Web server misconfigurations (nikto)
    - CMS vulnerabilities (wpscan, joomscan)
    - Automated vulnerability detection
    
    NOTE: Routing is handled by LLM in coordinator.py - no keyword matching needed.
    """
    
    AGENT_NAME = "vuln"
    AGENT_DESCRIPTION = "Vulnerability assessment and CVE detection"
    SPECIALIZED_TOOLS = [
        # Vulnerability Scanners (specs/vuln.py)
        "nuclei",
        "nikto",
        
        # CMS Scanners (specs/web.py)
        "wpscan",
        "whatweb",
        
        # WAF Detection (specs/web.py)
        "wafw00f",
        
        # API/Parameter fuzzing (specs/web.py, specs/vuln.py)
        "arjun",
        "ffuf",
    ]
    PENTEST_PHASES = [3]  # Vulnerability phase
    
    def __init__(self, llm=None):
        super().__init__(llm)
        self.name = self.AGENT_NAME
        self.description = self.AGENT_DESCRIPTION
        # Keep for backward compatibility
        self.specialized_tools = self.SPECIALIZED_TOOLS
        self.pentest_phases = self.PENTEST_PHASES
    
    def plan(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Plan vulnerability scanning tools and actions."""
        tools = self._select_tools(query, context)
        commands = self._get_suggested_commands(tools, context)
        
        return {
            "agent": self.name,
            "tools": tools,
            "commands": commands,
            "reasoning": f"Phase 3 (Vulnerability): Selected {', '.join(tools)} for CVE/vuln detection"
        }
    
    def _classify_vuln_type(self, query: str, context: Dict[str, Any]) -> str:
        """
        Classify what type of vulnerability scan the user wants using LLM intelligence.
        
        NO HARDCODED KEYWORDS - LLM decides based on semantic understanding.
        """
        from app.agent.prompts import format_prompt
        from app.llm.client import OllamaClient
        
        detected_tech = context.get("detected_tech", [])
        
        try:
            prompt = format_prompt(
                "classify_vuln",
                query=query,
                detected_tech=", ".join(detected_tech) if detected_tech else "none",
                target=context.get("target_domain") or context.get("last_domain") or "not set"
            )
            
            llm = OllamaClient()
            response = llm.generate(prompt, timeout=10, stream=False).strip().lower()
            
            # Extract valid vuln type
            valid_types = ["cve_scan", "web_server", "wordpress", "joomla", "waf_detect", "api_fuzz", "full_vuln"]
            for vuln_type in valid_types:
                if vuln_type in response:
                    return vuln_type
            
        except Exception as e:
            print(f"  ⚠️ LLM classification failed: {e}")
        
        return "full_vuln"
    
    def _select_tools(self, query: str, context: Dict[str, Any]) -> List[str]:
        """
        Select vulnerability scanning tools using vector search + vuln type classification.
        
        HYBRID APPROACH:
        1. Use ChromaDB vector search with vuln_type-enhanced query
        2. Filter by specialized_tools and availability
        3. Fallback to type-based tool mapping if vector search fails
        """
        vuln_type = self._classify_vuln_type(query, context)
        tools = []
        tools_run = set(context.get("tools_run", []))
        
        # Build enhanced query for vector search
        vuln_queries = {
            "wordpress": "WordPress vulnerability scanning CMS",
            "cve_scan": "CVE vulnerability scanning nuclei",
            "web_server": "web server vulnerability scanning nikto",
            "waf_detect": "WAF detection bypass",
            "api_fuzz": "API fuzzing discovery",
            "full_vuln": "vulnerability scanning CVE detection",
        }
        
        enhanced_query = query + " " + vuln_queries.get(vuln_type, vuln_queries["full_vuln"])
        
        # Use vector search to discover tools
        discovered = self._discover_tools_via_rag(enhanced_query, context, n_results=10)
        
        # Filter discovered tools
        for match in discovered:
            tool = match["tool"]
            if (tool in self.SPECIALIZED_TOOLS and 
                self.registry.is_available(tool) and 
                tool not in tools_run):
                tools.append(tool)
                if len(tools) >= 3:
                    break
        
        # FALLBACK: Type-based mapping if vector search found nothing
        if not tools:
            type_tool_map = {
                "wordpress": ["wpscan", "nuclei"],
                "cve_scan": ["nuclei"],
                "web_server": ["nikto", "nuclei"],
                "waf_detect": ["wafw00f"],
                "api_fuzz": ["arjun", "ffuf"],
                "full_vuln": ["nuclei", "nikto"],
            }
            
            preferred_tools = type_tool_map.get(vuln_type, ["nuclei"])
            for tool in preferred_tools:
                if self.registry.is_available(tool) and tool not in tools_run:
                    tools.append(tool)
                    break
        
        # FINAL FALLBACK: Any available specialized tool
        if not tools:
            for tool in self.SPECIALIZED_TOOLS:
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
            "nuclei": ["scan", "scan_fast", "scan_all"],
            "nikto": ["scan_https", "scan_http", "scan"],
            "wpscan": ["enum", "brute", "stealth"],
            "wafw00f": ["detect"],
            "arjun": ["discover"],
            "gobuster": ["dir", "dns"],
            "ffuf": ["fuzz", "fuzz_json"],
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
        Analyze vulnerability scan results using semantic analysis.
        
        HYBRID APPROACH: Uses _analyze_output_semantic() for intelligent parsing.
        """
        analysis = []
        max_severity = "none"
        severity_order = ["none", "info", "low", "medium", "high", "critical"]
        
        for tool, result in results.items():
            if not result.get("success"):
                analysis.append(f"❌ {tool}: {result.get('error', 'Failed')[:50]}")
                continue
            
            output = result.get("output", "")
            
            # Use semantic analysis
            parsed = self._analyze_output_semantic(tool, output)
            
            if parsed.get("has_findings"):
                severity = parsed.get("severity", "info")
                severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚠️")
                analysis.append(f"{severity_icon} {tool}: {parsed.get('summary', 'Vulnerabilities detected')}")
                
                if parsed.get("key_items"):
                    for item in parsed["key_items"][:5]:
                        analysis.append(f"   • {item}")
                
                # Track max severity
                if severity_order.index(severity) > severity_order.index(max_severity):
                    max_severity = severity
            else:
                analysis.append(f"✅ {tool}: No vulnerabilities found")
        
        # Suggest next step based on severity
        if max_severity in ["critical", "high"]:
            analysis.append("\n→ 🎯 Move to Phase 4 - Exploitation")
            analysis.append("  High severity vulnerabilities found - ready for exploitation")
        elif max_severity in ["medium", "low"]:
            analysis.append("\n→ Investigate findings manually or try different templates")
        else:
            analysis.append("\n→ No significant vulnerabilities - try different scan options")
        
        return "\n".join(analysis)
