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
