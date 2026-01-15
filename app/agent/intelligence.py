"""
SNODE Intelligence Layer
========================

REDESIGNED: Pure LLM-based intelligence with no hardcoded keywords.

Central intelligence module that provides:
1. Semantic query understanding via LLM
2. RAG-based context retrieval
3. Query expansion for better tool/concept matching
4. Rich prompt construction with injected context
"""
import re
import json
from typing import Dict, Any, List, Optional, Tuple


class SNODEIntelligence:
    """
    Central intelligence layer for SNODE.
    
    REDESIGNED: Uses LLM for all semantic understanding.
    No hardcoded keyword matching.
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
            # Use lightweight model for intelligence layer (fast classification)
            from app.llm.config import get_planner_model
            planner_model = get_planner_model()
            if "functiongemma" in planner_model.lower() or "nemotron" in planner_model.lower():
                self._llm = OllamaClient(model="planner")
            else:
                self._llm = OllamaClient()
        return self._llm
    
    def understand_query(self, query: str, context: dict = None) -> Dict[str, Any]:
        """
        Understand user query with semantic analysis via LLM.
        
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
            "detected_phase": self._infer_phase_llm(query, context),
            "relevant_tools": [],
            "retrieved_context": {},
        }
        
        # Get RAG context if target is known
        target = result["detected_target"] or (context.get("last_domain") if context else None)
        if target and self.rag:
            try:
                result["retrieved_context"] = {
                    "domain_findings": self.rag.get_findings_for_domain(target),
                    "similar_queries": self.rag.get_relevant_context(query, domain=target, n_results=3),
                }
            except Exception:
                pass
        
        if self.rag:
            try:
                for term in result["expanded_terms"][:3]:
                    tools = self.rag.search_tools(term, n_results=2)
                    for t in tools:
                        if t.get("tool") not in result["relevant_tools"]:
                            result["relevant_tools"].append(t.get("tool"))
            except Exception:
                pass
        
        if context and "next step" in query.lower() and context.get("analyzer_next_tool"):
            analyzer_tool = context.get("analyzer_next_tool")
            result["relevant_tools"] = [analyzer_tool] + result["relevant_tools"]
        
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
    
    def _infer_phase_llm(self, query: str, context: dict = None) -> int:
        """
        Infer current pentest phase using LLM.
        
        REDESIGNED: No hardcoded keywords. Pure LLM inference.
        """
        # Quick context-based inference (no LLM needed for obvious cases)
        if context:
            if context.get("shell_obtained"):
                return 5
            if context.get("vulns_found"):
                return 4 if len(context.get("vulns_found", [])) > 0 else 3
            if context.get("has_ports") or context.get("open_ports"):
                return 3
            if context.get("has_subdomains") or context.get("subdomains"):
                return 2
        
        # Use LLM for query-based inference
        try:
            context_summary = self._build_context_summary(context) if context else "No context"
            
            prompt = f"""Determine the pentest phase for this task.

TASK: {query}
CONTEXT: {context_summary}

PHASES:
1 = Reconnaissance (OSINT, subdomains, DNS, info gathering)
2 = Scanning (port scans, service detection, web discovery)
3 = Vulnerability Assessment (vuln scans, CVE detection)
4 = Exploitation (SQLi, RCE, gaining access)
5 = Post-Exploitation (privesc, lateral movement)
6 = Reporting (documentation, summaries)

Return ONLY the phase number (1-6):"""

            response = self.llm.generate(prompt, timeout=15, stream=False)
            
            # Extract number from response
            match = re.search(r'[1-6]', response)
            if match:
                return int(match.group())
                
        except Exception:
            pass
        
        return 1  # Default to recon
    
    def _build_context_summary(self, context: dict) -> str:
        """Build a concise context summary."""
        parts = []
        
        if context.get("last_domain"):
            parts.append(f"Target: {context['last_domain']}")
        if context.get("subdomain_count") or context.get("subdomains"):
            count = context.get("subdomain_count") or len(context.get("subdomains", []))
            parts.append(f"Subdomains: {count}")
        if context.get("port_count") or context.get("open_ports"):
            count = context.get("port_count") or len(context.get("open_ports", []))
            parts.append(f"Ports: {count}")
        if context.get("vulns_found"):
            parts.append(f"Vulns: {len(context['vulns_found'])}")
        if context.get("tools_run"):
            parts.append(f"Tools: {', '.join(context['tools_run'][-3:])}")
        
        return "; ".join(parts) if parts else "No data"
    
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
        Classify user intent using LLM.
        
        Returns: SECURITY_TASK, MEMORY_QUERY, or QUESTION
        """
        from app.agent.prompts import INTENT_CLASSIFICATION_PROMPT
        
        context_summary = self._build_context_summary(context) if context else "No context"
        
        prompt = INTENT_CLASSIFICATION_PROMPT.format(
            query=query,
            context_summary=context_summary
        )
        
        # #region agent log
        try:
            import json
            with open("snode_debug.log", "a") as f:
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H1","location":"intelligence.py:245","message":"Intent classification LLM call","data":{"query":query,"context_summary":context_summary[:100]},"timestamp":int(__import__("time").time()*1000)})+"\n")
        except: pass
        # #endregion
        
        try:
            # Use shorter timeout for intent classification (should be fast)
            response = self.llm.generate(prompt, timeout=15, stream=False)
            response_clean = response.strip().upper()
            
            # #region agent log
            try:
                import json
                with open("snode_debug.log", "a") as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H1","location":"intelligence.py:253","message":"Intent classification LLM response","data":{"response_clean":response_clean[:200],"has_question": "QUESTION" in response_clean,"has_security": "SECURITY" in response_clean or "TASK" in response_clean},"timestamp":int(__import__("time").time()*1000)})+"\n")
            except: pass
            # #endregion
            
            # Extract intent from response - check QUESTION first (more specific)
            if "QUESTION" in response_clean:
                # #region agent log
                try:
                    import json
                    with open("snode_debug.log", "a") as f:
                        f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H1","location":"intelligence.py:260","message":"Intent classified as QUESTION","data":{"query":query},"timestamp":int(__import__("time").time()*1000)})+"\n")
                except: pass
                # #endregion
                return "QUESTION"
            if "MEMORY" in response_clean:
                return "MEMORY_QUERY"
            if "SECURITY" in response_clean or "TASK" in response_clean:
                # #region agent log
                try:
                    import json
                    with open("snode_debug.log", "a") as f:
                        f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H1","location":"intelligence.py:268","message":"Intent classified as SECURITY_TASK","data":{"query":query},"timestamp":int(__import__("time").time()*1000)})+"\n")
                except: pass
                # #endregion
                return "SECURITY_TASK"
            
            # Default to QUESTION for unclear cases (safer than assuming SECURITY_TASK)
            # #region agent log
            try:
                import json
                with open("snode_debug.log", "a") as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H1","location":"intelligence.py:272","message":"Intent defaulted to QUESTION","data":{"query":query,"response_clean":response_clean[:100]},"timestamp":int(__import__("time").time()*1000)})+"\n")
            except: pass
            # #endregion
            return "QUESTION"
            
        except Exception as e:
            # #region agent log
            try:
                import json
                with open("snode_debug.log", "a") as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H1","location":"intelligence.py:277","message":"Intent classification exception","data":{"query":query,"error":str(e)},"timestamp":int(__import__("time").time()*1000)})+"\n")
            except: pass
            # #endregion
            # On timeout/error, default to QUESTION (safer than SECURITY_TASK)
            return "QUESTION"
    
    def get_relevant_cves(self, technologies: List[str]) -> List[Dict]:
        """Get CVEs for detected technologies."""
        if not self.rag or not technologies:
            return []
        
        try:
            return self.rag.search_cves_for_tech(technologies, n_per_tech=3)
        except Exception:
            return []
    
    def suggest_tools_llm(self, query: str, context: dict = None, 
                          max_tools: int = 3) -> List[str]:
        """
        Suggest tools using LLM intelligence.
        
        REDESIGNED: Pure LLM-based tool suggestion.
        """
        context_summary = self._build_context_summary(context) if context else "No data"
        
        prompt = f"""Suggest the best security tools for this task.

TASK: {query}
CURRENT STATE: {context_summary}

AVAILABLE TOOLS (by category):
- Recon: subfinder, amass, bbot, clatscope, whois
- Scanning: nmap, masscan, httpx, gobuster, ffuf
- Vuln: nuclei, nikto, wpscan, testssl
- Exploit: sqlmap, hydra, searchsploit, metasploit
- PostExploit: linpeas, mimikatz, bloodhound

Return ONLY a comma-separated list of {max_tools} tools (no explanation):"""

        try:
            response = self.llm.generate(prompt, timeout=15, stream=False)
            
            # Parse comma-separated tools
            tools = [t.strip().lower() for t in response.split(',')]
            tools = [t for t in tools if t and len(t) < 30]  # Filter invalid
            
            return tools[:max_tools]
            
        except Exception:
            return []
    
    def suggest_tools(self, query: str, context: dict = None, 
                      max_tools: int = 3) -> List[str]:
        """
        Suggest appropriate tools for the query.
        
        Uses LLM + RAG for intelligent suggestion.
        """
        # Try LLM first
        llm_tools = self.suggest_tools_llm(query, context, max_tools)
        if llm_tools:
            return llm_tools
        
        # Fallback to RAG-based
        understanding = self.understand_query(query, context)
        suggested = understanding.get("relevant_tools", [])[:max_tools]
        
        # Filter out recently-run tools
        if context:
            tools_run = context.get("tools_run", [])
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
    
    REDESIGNED: Uses LLM for ambiguous cases.
    
    Returns: {"phase": 1-6, "reason": "..."}
    """
    # Quick heuristic for clear cases
    if context.get("shell_obtained"):
        return {"phase": 5, "reason": "Shell obtained, in post-exploitation"}
    
    exploits_run = context.get("exploits_run", [])
    tools_run = context.get("tools_run", [])
    
    if exploits_run:
        return {"phase": 4, "reason": "Exploitation in progress"}
    
    vulns_found = context.get("vulns_found", [])
    if vulns_found:
        return {"phase": 3, "reason": "Vulnerabilities found, assessment in progress"}
    
    open_ports = context.get("open_ports", [])
    has_ports = context.get("has_ports", False)
    if has_ports or open_ports:
        return {"phase": 2, "reason": "Ports discovered, scanning phase"}
    
    has_subdomains = context.get("has_subdomains", False)
    subdomain_count = context.get("subdomain_count", 0)
    subdomains = context.get("subdomains", [])
    if has_subdomains or subdomain_count > 0 or subdomains:
        return {"phase": 2, "reason": "Subdomains found, ready for scanning"}
    
    if not tools_run:
        return {"phase": 1, "reason": "Starting reconnaissance"}
    
    # For ambiguous cases, use LLM
    if llm:
        try:
            prompt = f"""Analyze this pentest context and determine the phase.

CONTEXT:
- Subdomains: {len(subdomains)}
- Ports: {len(open_ports)}
- Vulnerabilities: {len(vulns_found)}
- Tools run: {tools_run[-5:] if tools_run else "none"}

PHASES: 1=Recon, 2=Scanning, 3=VulnAssess, 4=Exploit, 5=PostExploit, 6=Report

Return JSON: {{"phase": N, "reason": "explanation"}}"""

            response = llm.generate(prompt, timeout=20, stream=False)
            match = re.search(r'\{[^}]+\}', response)
            if match:
                result = json.loads(match.group())
                return {
                    "phase": int(result.get("phase", 1)),
                    "reason": result.get("reason", "LLM inference")
                }
        except Exception:
            pass
    
    return {"phase": 1, "reason": "Default reconnaissance phase"}
