"""
SNODE Intelligence Layer
========================

Central intelligence module that provides:
1. Semantic query understanding with embeddings
2. RAG-based context retrieval
3. Query expansion for better tool/concept matching
4. Rich prompt construction with injected context
"""
import re
from typing import Dict, Any, List, Optional, Tuple


class SNODEIntelligence:
    """
    Central intelligence layer for SNODE.
    
    Provides semantic understanding, context retrieval, and rich prompting.
    """
    
    def __init__(self):
        self._rag = None
        self._embedding_model = None
        self._llm = None
    
    @property
    def rag(self):
        """Lazy-load RAG system."""
        if self._rag is None:
            try:
                from app.rag.unified_memory import get_unified_rag
                self._rag = get_unified_rag()
            except Exception:
                pass
        return self._rag
    
    @property
    def llm(self):
        """Lazy-load LLM client."""
        if self._llm is None:
            from app.llm.client import OllamaClient
            self._llm = OllamaClient()
        return self._llm
    
    def understand_query(self, query: str, context: dict = None) -> Dict[str, Any]:
        """
        Understand user query with semantic analysis.
        
        Returns:
        {
            "original_query": str,
            "expanded_terms": [str],  # Related concepts
            "intent": str,  # SECURITY_TASK, MEMORY_QUERY, QUESTION
            "detected_target": str,  # Extracted domain/IP
            "detected_phase": int,  # Inferred pentest phase
            "relevant_tools": [str],  # Suggested tools
            "retrieved_context": {...},  # From RAG
        }
        """
        from app.agent.prompts import expand_query
        
        result = {
            "original_query": query,
            "expanded_terms": expand_query(query),
            "intent": None,
            "detected_target": self._extract_target(query),
            "detected_phase": self._infer_phase(query, context),
            "relevant_tools": [],
            "retrieved_context": {},
        }
        
        # Get RAG context if target is known
        target = result["detected_target"] or (context.get("last_domain") if context else None)
        if target and self.rag:
            try:
                # Search for relevant past findings
                result["retrieved_context"] = {
                    "domain_findings": self.rag.get_findings_for_domain(target),
                    "similar_queries": self.rag.get_relevant_context(query, domain=target, n_results=3),
                }
            except Exception:
                pass
        
        # Get relevant tools based on expanded query
        if self.rag:
            try:
                for term in result["expanded_terms"][:3]:
                    tools = self.rag.search_tools(term, n_results=2)
                    for t in tools:
                        if t.get("tool") not in result["relevant_tools"]:
                            result["relevant_tools"].append(t.get("tool"))
            except Exception:
                pass
        
        return result
    
    def _extract_target(self, query: str) -> Optional[str]:
        """Extract domain or IP from query."""
        # Domain pattern
        domain_pattern = r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        match = re.search(domain_pattern, query)
        if match:
            return match.group(0)
        
        # IP pattern
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        match = re.search(ip_pattern, query)
        if match:
            return match.group(0)
        
        return None
    
    def _infer_phase(self, query: str, context: dict = None) -> int:
        """Infer current pentest phase from query and context."""
        query_lower = query.lower()
        
        # Phase indicators in query
        phase_keywords = {
            1: ["recon", "subdomain", "osint", "dns", "whois", "harvest", "enumerate", "gather", "find"],
            2: ["scan", "port", "nmap", "masscan", "discover", "probe", "httpx"],
            3: ["vuln", "nuclei", "nikto", "cve", "assess", "wpscan", "check"],
            4: ["exploit", "attack", "sqlmap", "inject", "bypass", "crack", "shell"],
            5: ["privesc", "lateral", "pivot", "persist", "escalat", "dump", "mimikatz"],
            6: ["report", "document", "summarize", "finding", "executive"],
        }
        
        for phase, keywords in phase_keywords.items():
            if any(kw in query_lower for kw in keywords):
                return phase
        
        # Infer from context state
        if context:
            has_subs = context.get("has_subdomains", False)
            has_ports = context.get("has_ports", False)
            has_vulns = context.get("vulns_found", [])
            has_shell = context.get("shell_obtained", False)
            
            if has_shell:
                return 5
            if has_vulns:
                return 4
            if has_ports:
                return 3
            if has_subs:
                return 2
        
        return 1  # Default to recon
    
    def build_rich_prompt(self, query: str, context: dict = None, 
                          understanding: dict = None) -> str:
        """
        Build a rich prompt with all context for LLM.
        
        Combines:
        - Expert system prompt
        - Phase-specific guidance
        - Session context
        - Retrieved RAG context
        """
        from app.agent.prompts import build_system_prompt, get_phase_prompt
        
        if understanding is None:
            understanding = self.understand_query(query, context)
        
        phase = understanding.get("detected_phase", 1)
        
        # Build system prompt with context
        system_prompt = build_system_prompt(phase, context)
        
        # Add retrieved context from RAG
        rag_context = understanding.get("retrieved_context", {})
        if rag_context:
            domain_findings = rag_context.get("domain_findings", {})
            if domain_findings:
                system_prompt += "\n\n## Previous Findings (from RAG)\n"
                if domain_findings.get("subdomains"):
                    subs = domain_findings["subdomains"][:10]
                    sub_strs = [f"{s.get('subdomain')} ({s.get('ip', '?')})" for s in subs]
                    system_prompt += f"- Subdomains: {', '.join(sub_strs)}\n"
                if domain_findings.get("hosts"):
                    hosts = domain_findings["hosts"][:10]
                    host_strs = [f"{h.get('ip')} ({h.get('hostname', '?')})" for h in hosts]
                    system_prompt += f"- Hosts: {', '.join(host_strs)}\n"
                if domain_findings.get("vulnerabilities"):
                    vulns = domain_findings["vulnerabilities"][:5]
                    vuln_strs = [f"{v.get('severity', '?').upper()}: {v.get('type', '?')}" for v in vulns]
                    system_prompt += f"- Known Vulns: {'; '.join(vuln_strs)}\n"
        
        return system_prompt
    
    def classify_intent(self, query: str, context: dict = None) -> str:
        """
        Classify user intent using LLM with rich context.
        
        Returns: SECURITY_TASK, MEMORY_QUERY, or QUESTION
        """
        from app.agent.prompts import INTENT_CLASSIFICATION_PROMPT
        
        # Build context summary
        context_summary = "No previous context"
        if context:
            parts = []
            if context.get("last_domain"):
                parts.append(f"Target: {context['last_domain']}")
            if context.get("subdomain_count"):
                parts.append(f"Subdomains: {context['subdomain_count']}")
            if context.get("port_count"):
                parts.append(f"Ports: {context['port_count']}")
            if context.get("tools_run"):
                parts.append(f"Tools run: {', '.join(context['tools_run'][-3:])}")
            if parts:
                context_summary = "; ".join(parts)
        
        prompt = INTENT_CLASSIFICATION_PROMPT.format(
            query=query,
            context_summary=context_summary
        )
        
        try:
            response = self.llm.generate(prompt, timeout=60, stream=False)  # No stream for quick classification
            response_clean = response.strip().upper()
            
            # Look for exact intent words at start or alone
            # SECURITY_TASK indicators
            if response_clean.startswith("SECURITY") or response_clean == "SECURITY_TASK":
                return "SECURITY_TASK"
            # MEMORY_QUERY indicators - must be exact or explicit
            if response_clean == "MEMORY_QUERY" or response_clean.startswith("MEMORY_QUERY"):
                return "MEMORY_QUERY"
            # QUESTION indicators
            if response_clean.startswith("QUESTION") or response_clean == "QUESTION":
                return "QUESTION"
            
            # Fallback - check for task-related keywords
            if any(kw in response_clean for kw in ["TASK", "SCAN", "ATTACK", "RUN", "EXECUTE"]):
                return "SECURITY_TASK"
            elif "MEMORY" in response_clean and "QUERY" in response_clean:
                return "MEMORY_QUERY"
            else:
                # Default to QUESTION for unclear cases (safer - will use LLM to answer)
                return "QUESTION"
        except Exception:
            # Default to security task for pentest assistant
            return "SECURITY_TASK"
    
    def get_relevant_cves(self, technologies: List[str]) -> List[Dict]:
        """Get CVEs for detected technologies."""
        if not self.rag or not technologies:
            return []
        
        try:
            return self.rag.search_cves_for_tech(technologies, n_per_tech=3)
        except Exception:
            return []
    
    def suggest_tools(self, query: str, context: dict = None, 
                      max_tools: int = 3) -> List[str]:
        """
        Suggest appropriate tools for the query.
        
        Uses semantic search + context awareness.
        """
        understanding = self.understand_query(query, context)
        suggested = understanding.get("relevant_tools", [])[:max_tools]
        
        # Filter out already-run tools if repeating
        if context:
            tools_run = context.get("tools_run", [])
            # Don't repeat same tool unless explicitly asked
            if "again" not in query.lower() and "retry" not in query.lower():
                suggested = [t for t in suggested if t not in tools_run[-2:]]
        
        return suggested[:max_tools]


# Singleton
_intelligence: Optional[SNODEIntelligence] = None


def get_intelligence() -> SNODEIntelligence:
    """Get singleton SNODEIntelligence instance."""
    global _intelligence
    if _intelligence is None:
        _intelligence = SNODEIntelligence()
    return _intelligence


def infer_phase(context: dict, llm=None) -> dict:
    """
    Infer the current pentest phase based on context.
    
    Returns: {"phase": 1-6, "reason": "..."}
    
    Phases:
    1 = Reconnaissance (gathering info, OSINT, subdomains)
    2 = Scanning (ports, services, web discovery)
    3 = Vulnerability Assessment (vuln scanning, CVEs)
    4 = Exploitation (exploiting vulns, gaining access)
    5 = Post-Exploitation (privesc, lateral movement)
    6 = Reporting (documenting findings)
    """
    import re
    import json
    
    has_subdomains = context.get("has_subdomains", False)
    subdomain_count = context.get("subdomain_count", 0)
    has_ports = context.get("has_ports", False)
    open_ports = context.get("open_ports", [])
    vulns_found = context.get("vulns_found", [])
    services = context.get("services", [])
    tools_run = context.get("tools_run", [])
    exploits_run = context.get("exploits_run", [])
    shell_obtained = context.get("shell_obtained", False)
    
    # Quick heuristic (no LLM call needed for obvious cases)
    if shell_obtained:
        return {"phase": 5, "reason": "Shell obtained, in post-exploitation"}
    
    if exploits_run or "sqlmap" in tools_run or "hydra" in tools_run or "msfconsole" in tools_run:
        return {"phase": 4, "reason": "Exploitation tools have been run"}
    
    if vulns_found or "nuclei" in tools_run or "nikto" in tools_run:
        return {"phase": 3, "reason": "Vulnerability scanning in progress"}
    
    if has_ports or open_ports or "nmap" in tools_run or "masscan" in tools_run:
        return {"phase": 2, "reason": "Port scanning completed, in scanning phase"}
    
    if has_subdomains or subdomain_count > 0:
        return {"phase": 2, "reason": "Subdomains found, ready for scanning"}
    
    if not tools_run:
        return {"phase": 1, "reason": "No tools run yet, starting reconnaissance"}
    
    # For ambiguous cases, ask LLM if available
    if llm:
        prompt = f'''Analyze this pentest context and determine the current phase.

CONTEXT:
- Subdomains: {subdomain_count}
- Ports scanned: {has_ports}
- Open ports: {open_ports[:5] if open_ports else "none"}
- Vulnerabilities: {len(vulns_found)}
- Tools run: {tools_run[-5:] if tools_run else "none"}

PHASES: 1=Recon, 2=Scanning, 3=VulnAssess, 4=Exploit, 5=PostExploit, 6=Report

Return ONLY: {{"phase": N, "reason": "brief explanation"}}'''

        try:
            response = llm.generate(prompt, timeout=20)
            clean = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
            match = re.search(r'\{[^}]+\}', clean)
            if match:
                result = json.loads(match.group())
                return {
                    "phase": int(result.get("phase", 1)),
                    "reason": result.get("reason", "LLM inference")
                }
        except Exception:
            pass
    
    return {"phase": 1, "reason": "Default - starting reconnaissance"}
