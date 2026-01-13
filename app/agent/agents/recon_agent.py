"""
Recon Agent - Specializes in Reconnaissance & OSINT
====================================================

Handles Phase 1 operations:
- Subdomain enumeration
- OSINT gathering
- DNS/WHOIS lookups
- Passive information collection
"""
from typing import List, Dict, Any
from .base_agent import BaseAgent


class ReconAgent(BaseAgent):
    """Specialized agent for reconnaissance and OSINT operations."""
    
    AGENT_NAME = "recon"
    AGENT_DESCRIPTION = "Reconnaissance specialist - passive info gathering, OSINT, subdomain enumeration"
    SPECIALIZED_TOOLS = [
        "subfinder", "amass", "bbot", "theHarvester", "shodan", "clatscope",
        "whois", "dig", "dnsrecon", "recon-ng", "whatweb", "wafw00f", "httpx"
    ]
    PENTEST_PHASES = [1]  # Reconnaissance phase only
    
    # Keywords that suggest recon tasks
    RECON_KEYWORDS = [
        "subdomain", "osint", "whois", "dns", "domain", "recon", "discover",
        "enumerate", "find", "gather", "information", "passive", "fingerprint",
        "waf", "technology", "tech stack", "what is", "identify"
    ]
    
    def plan(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan reconnaissance tools based on query.
        
        Returns tools for passive info gathering.
        """
        query_lower = query.lower()
        
        # Determine what type of recon is needed
        recon_type = self._classify_recon_type(query_lower, context)
        
        # Get tools for this recon type
        tools, commands, reasoning = self._select_tools(recon_type, context)
        
        return {
            "agent": self.AGENT_NAME,
            "tools": tools,
            "commands": commands,
            "reasoning": reasoning,
            "recon_type": recon_type
        }
    
    def _classify_recon_type(self, query: str, context: Dict[str, Any]) -> str:
        """
        Classify the type of reconnaissance needed using LLM intelligence.
        
        NO HARDCODED KEYWORDS - LLM decides based on semantic understanding.
        """
        from app.agent.prompts import format_prompt
        from app.llm.client import OllamaClient
        
        has_subdomains = context.get("has_subdomains", False)
        has_domain = bool(context.get("last_domain") or context.get("target_domain"))
        
        try:
            prompt = format_prompt(
                "classify_recon",
                query=query,
                has_domain=has_domain,
                has_subdomains=has_subdomains
            )
            
            llm = OllamaClient()
            response = llm.generate(prompt, timeout=10, stream=False).strip().lower()
            
            # Extract valid recon type
            valid_types = ["subdomain_enum", "osint", "dns_info", "waf_detect", "tech_fingerprint", "device_search", "general_recon"]
            for recon_type in valid_types:
                if recon_type in response:
                    return recon_type
            
        except Exception as e:
            print(f"  ⚠️ LLM classification failed: {e}")
        
        # Default to subdomain enum if we have a domain but no subdomains
        if has_domain and not has_subdomains:
            return "subdomain_enum"
        
        return "general_recon"
    
    def _select_tools(self, recon_type: str, context: Dict[str, Any]) -> tuple:
        """
        Select appropriate tools using vector search + recon type classification.
        
        HYBRID APPROACH:
        1. Use ChromaDB vector search with recon_type-enhanced query
        2. Filter by specialized_tools and availability
        3. Fallback to type-based tool mapping if vector search fails
        """
        # Build enhanced query for vector search
        query = context.get("query", "")
        recon_queries = {
            "subdomain_enum": "subdomain enumeration passive OSINT",
            "osint": "OSINT gathering emails hosts public data",
            "dns_info": "DNS enumeration WHOIS lookup",
            "waf_detect": "WAF detection technology fingerprinting",
            "tech_fingerprint": "technology stack identification",
            "device_search": "search exposed devices services",
            "general_recon": "reconnaissance information gathering",
        }
        
        enhanced_query = query + " " + recon_queries.get(recon_type, recon_queries["general_recon"])
        
        # Use vector search to discover tools
        discovered = self._discover_tools_via_rag(enhanced_query, context, n_results=10)
        
        tools_run = set(context.get("tools_run", []))
        available = []
        commands = {}
        skipped_already_run = []
        
        # Filter discovered tools
        for match in discovered:
            tool = match["tool"]
            if not self.registry.is_available(tool):
                continue
            if tool in tools_run:
                skipped_already_run.append(tool)
                continue
            if tool not in self.SPECIALIZED_TOOLS:
                continue  # Only use specialized tools
            
            available.append(tool)
            
            # Use command from vector search result, or get from spec
            command = match.get("command", "")
            if command:
                # Validate command exists in tool spec
                spec = self.registry.tools.get(tool)
                if spec and command in spec.commands:
                    commands[tool] = command
                else:
                    # Fallback to first available command
                    if spec and spec.commands:
                        commands[tool] = list(spec.commands.keys())[0]
            else:
                # Get first available command
                spec = self.registry.tools.get(tool)
                if spec and spec.commands:
                    commands[tool] = list(spec.commands.keys())[0]
            
            # Limit to top 3 tools
            if len(available) >= 3:
                break
        
        # FALLBACK: If vector search found nothing, use type-based mapping
        if not available:
            fallback_tools = {
                "subdomain_enum": ["subfinder", "amass", "bbot"],
                "osint": ["theHarvester", "recon-ng", "clatscope"],
                "dns_info": ["dig", "dnsrecon", "clatscope"],
                "waf_detect": ["wafw00f", "httpx"],
                "tech_fingerprint": ["httpx", "whatweb", "wafw00f"],
                "device_search": ["shodan", "clatscope"],
                "general_recon": ["httpx", "subfinder", "clatscope"],
            }
            
            tools_for_type = fallback_tools.get(recon_type, fallback_tools["general_recon"])
            for tool in tools_for_type:
                if self.registry.is_available(tool) and tool not in tools_run:
                    available.append(tool)
                    spec = self.registry.tools.get(tool)
                    if spec and spec.commands:
                        commands[tool] = list(spec.commands.keys())[0]
                    break
        
        # Build reasoning
        reasoning_map = {
            "subdomain_enum": "Subdomain enumeration using passive OSINT sources",
            "osint": "OSINT gathering - emails, hosts, public data",
            "dns_info": "DNS enumeration and WHOIS lookup",
            "waf_detect": "WAF detection and technology fingerprinting",
            "tech_fingerprint": "Technology stack identification",
            "device_search": "Search for exposed devices/services",
            "general_recon": "General reconnaissance starting point",
        }
        reasoning = reasoning_map.get(recon_type, reasoning_map["general_recon"])
        
        if skipped_already_run:
            reasoning += f" (skipped already-run: {', '.join(skipped_already_run)})"
        
        # If all tools were already run, suggest moving to next phase
        if not available and skipped_already_run:
            reasoning = f"All recon tools already run ({', '.join(skipped_already_run)}). Ready for port scanning phase."
            available = ["nmap"] if self.registry.is_available("nmap") else []
            if available:
                spec = self.registry.tools.get("nmap")
                if spec and spec.commands:
                    commands["nmap"] = list(spec.commands.keys())[0]
        
        return available, commands, reasoning
    
    def analyze_results(self, results: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Analyze recon results and provide insights."""
        
        findings = []
        
        # Extract key findings from results
        for tool, data in results.items():
            if not data.get("success"):
                continue
            
            output = data.get("output", "")
            
            # Count subdomains found
            if tool in ["subfinder", "amass", "bbot"]:
                lines = [l for l in output.split("\n") if l.strip()]
                findings.append(f"**{tool}**: Found {len(lines)} subdomains")
            
            # Email findings
            if "email" in output.lower():
                email_count = output.lower().count("@")
                if email_count > 0:
                    findings.append(f"**{tool}**: Found ~{email_count} email addresses")
        
        if not findings:
            return "No significant reconnaissance findings."
        
        summary = "## 🔍 Recon Summary\n\n"
        summary += "\n".join(f"- {f}" for f in findings)
        
        # Suggest next phase
        if context.get("has_subdomains"):
            summary += "\n\n**Next Step:** Move to scanning phase (nmap, nuclei)"
        
        return summary
    
    def can_handle(self, phase: int, query: str) -> bool:
        """Check if this is a recon task."""
        if phase == 1:
            return True
        
        # Also handle if explicitly recon-related
        query_lower = query.lower()
        return any(kw in query_lower for kw in self.RECON_KEYWORDS)
    
    # ─────────────────────────────────────────────────────────
    # NATIVE OSINT METHODS (no external tool dependency)
    # ─────────────────────────────────────────────────────────
    
    def ip_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Native IP lookup using ipinfo.io (like clatscope).
        Returns: {ip, isp, asn, city, country, org, ...}
        """
        from app.osint import lookup_ip
        return lookup_ip(ip)
    
    def dns_lookup(self, domain: str) -> Dict[str, Any]:
        """Native DNS lookup."""
        from app.osint import dns_lookup
        return dns_lookup(domain)
    
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Native WHOIS lookup."""
        from app.osint import whois_lookup
        return whois_lookup(domain)
    
    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses."""
        from app.osint import resolve_domain
        return resolve_domain(domain)
    
    def full_recon(self, target: str) -> Dict[str, Any]:
        """
        Perform full OSINT recon on target (domain or IP).
        Combines IP lookup, DNS, WHOIS, etc.
        """
        from app.osint import full_recon
        return full_recon(target)
    
    def get_isp(self, ip: str) -> str:
        """Get ISP for an IP address."""
        from app.osint import get_isp
        return get_isp(ip)
    
    def get_asn(self, ip: str) -> int:
        """Get ASN for an IP address."""
        from app.osint import get_asn
        return get_asn(ip)

