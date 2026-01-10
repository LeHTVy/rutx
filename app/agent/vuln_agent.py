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
    """
    
    # Keywords that trigger this agent
    VULN_KEYWORDS = [
        "vuln", "vulnerability", "cve", "nuclei", "nikto", "nessus",
        "scan for vuln", "find vuln", "security scan", "openvas",
        "wpscan", "wordpress", "joomla", "cms", "burp"
    ]
    
    def __init__(self, llm=None):
        super().__init__(llm)
        self.name = "vuln"
        self.description = "Vulnerability assessment and CVE detection"
        
        # Phase 3 tools from tool specs
        self.specialized_tools = [
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
        
        self.pentest_phases = [3]  # Vulnerability phase
        
        self.keywords = self.VULN_KEYWORDS
    
    def can_handle(self, phase: int, query: str) -> bool:
        """Check if this agent should handle the query."""
        if phase == 3:
            return True
        return any(kw in query.lower() for kw in self.VULN_KEYWORDS)
    
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
        """Select vulnerability scanning tools based on context."""
        vuln_type = self._classify_vuln_type(query, context)
        tools = []
        
        if vuln_type == "wordpress":
            if self.registry.is_available("wpscan"):
                tools.append("wpscan")
            tools.append("nuclei")  # WordPress templates
            
        elif vuln_type == "cve_scan":
            tools.append("nuclei")
            
        elif vuln_type == "web_server":
            if self.registry.is_available("nikto"):
                tools.append("nikto")
            tools.append("nuclei")
            
        elif vuln_type == "waf_detect":
            if self.registry.is_available("wafw00f"):
                tools.append("wafw00f")
                
        elif vuln_type == "api_fuzz":
            if self.registry.is_available("arjun"):
                tools.append("arjun")
            if self.registry.is_available("ffuf"):
                tools.append("ffuf")
                
        elif vuln_type == "full_vuln":
            # Full vuln scan
            tools.append("nuclei")
            if self.registry.is_available("nikto"):
                tools.append("nikto")
        
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
        """Analyze vulnerability scan results and suggest exploitation."""
        analysis = []
        vulns_found = []
        
        for tool, result in results.items():
            if not result.get("success"):
                continue
            
            output = result.get("output", "")
            
            if tool == "nuclei":
                # Check for findings by severity
                if "[critical]" in output.lower():
                    analysis.append("🔴 CRITICAL vulnerabilities found by nuclei!")
                    vulns_found.append("critical")
                if "[high]" in output.lower():
                    analysis.append("🟠 HIGH severity issues found")
                    vulns_found.append("high")
                if "[medium]" in output.lower():
                    analysis.append("🟡 Medium severity issues found")
                    
            elif tool == "nikto":
                if "OSVDB" in output or "CVE" in output:
                    analysis.append("⚠️ Nikto found potential vulnerabilities")
                    vulns_found.append("nikto_findings")
                    
            elif tool == "wpscan":
                if "Vulnerability" in output or "[!]" in output:
                    analysis.append("🔴 WordPress vulnerabilities detected!")
                    vulns_found.append("wordpress")
        
        # Suggest next steps based on findings
        if "critical" in vulns_found or "high" in vulns_found:
            analysis.append("\n→ Next: Move to Phase 4 - Exploitation")
            analysis.append("  Use sqlmap for SQL injection or metasploit for CVE exploits")
        elif vulns_found:
            analysis.append("\n→ Next: Investigate findings manually or try exploitation")
        else:
            analysis.append("ℹ️ No critical vulnerabilities found")
            analysis.append("→ Try different scan templates or manual testing")
        
        return "\n".join(analysis)
