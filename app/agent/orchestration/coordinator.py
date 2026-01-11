"""
Agent Coordinator - LLM-Driven Agent Router (6-Phase PTES)
==========================================================

REDESIGNED: Pure LLM-based routing with no keyword matching.
The brain that decides which agent handles each query using
semantic understanding.

PTES Phases:
1. Reconnaissance - OSINT, subdomain, DNS
2. Scanning - Port scan, service enum
3. Vulnerability - CVE detection, vuln scan
4. Exploitation - SQLi, RCE, brute force
5. Post-Exploitation - Priv esc, lateral movement
6. Reporting - Generate reports
"""
from typing import Dict, Any, Optional, List
import json
import re

# Import agents from agents folder
from app.agent.agents import (
    BaseAgent,
    ReconAgent,
    ScanAgent,
    VulnAgent,
    ExploitAgent,
    PostExploitAgent,
    ReportAgent,
    SystemAgent,
)


# Phase names
PHASE_NAMES = {
    1: "Reconnaissance",
    2: "Scanning",
    3: "Vulnerability Assessment",
    4: "Exploitation",
    5: "Post-Exploitation",
    6: "Reporting"
}


class AgentCoordinator:
    """
    LLM-driven coordinator for specialized agents.
    
    REDESIGNED: No keyword matching. Pure LLM semantic routing.
    Routes queries based on:
    1. LLM understanding of intent and context
    2. Current accumulated findings
    3. Task progression logic
    """
    
    def __init__(self, llm=None):
        """Initialize coordinator with all specialized agents."""
        self.agents: Dict[str, BaseAgent] = {
            "recon": ReconAgent(llm),        # Phase 1
            "scan": ScanAgent(llm),          # Phase 2
            "vuln": VulnAgent(llm),          # Phase 3
            "exploit": ExploitAgent(llm),    # Phase 4
            "postexploit": PostExploitAgent(llm),  # Phase 5
            "report": ReportAgent(llm),      # Phase 6
            "system": SystemAgent(llm)       # System utilities
        }
        self._llm = llm
    
    @property
    def llm(self):
        """Lazy-load LLM."""
        if self._llm is None:
            from app.llm.client import OllamaClient
            self._llm = OllamaClient()
        return self._llm
    
    @property
    def shared_memory(self):
        """Get shared memory for agent communication."""
        from app.memory import get_shared_memory
        return get_shared_memory()
    
    def get_context_for_agent(self, agent_name: str) -> Dict[str, Any]:
        """Get context tailored for specific agent from shared memory."""
        return self.shared_memory.get_for_agent(agent_name)
    
    def update_shared_memory(self, context: Dict[str, Any]):
        """Update shared memory from context dict."""
        self.shared_memory.update_from_dict(context)
    
    def _summarize_context(self, context: Dict[str, Any]) -> str:
        """Create a concise context summary for LLM."""
        parts = []
        
        target = context.get("target_domain") or context.get("last_domain")
        if target:
            parts.append(f"Target: {target}")
        
        subdomain_count = len(context.get("subdomains", []))
        if subdomain_count > 0:
            parts.append(f"Subdomains: {subdomain_count}")
        
        ip_count = len(context.get("ips", []))
        if ip_count > 0:
            parts.append(f"IPs: {ip_count}")
        
        port_count = len(context.get("open_ports", []))
        if port_count > 0:
            parts.append(f"Open ports: {port_count}")
        
        vuln_count = len(context.get("vulns_found", []))
        if vuln_count > 0:
            parts.append(f"Vulnerabilities: {vuln_count}")
        
        if context.get("shell_obtained"):
            parts.append("Shell: obtained")
        
        tools_run = context.get("tools_run", [])
        if tools_run:
            parts.append(f"Tools run: {', '.join(tools_run[-5:])}")
        
        return "; ".join(parts) if parts else "No data gathered yet"
    
    def route(self, query: str, context: Dict[str, Any]) -> BaseAgent:
        """
        Route query to best agent using PURE LLM intelligence.
        
        NO HARDCODED KEYWORDS - LLM decides based on semantic understanding.
        
        Args:
            query: User's query/task
            context: Current session context
            
        Returns:
            The most appropriate agent for this query
        """
        from app.llm.client import OllamaClient
        
        context_summary = self._summarize_context(context)
        
        prompt = f"""You are routing a pentest task to the best agent.

TASK: {query}
CONTEXT: {context_summary}

AVAILABLE AGENTS:
- recon: Subdomain enumeration, OSINT, DNS lookup, WHOIS (tools: amass, subfinder, whois, clatscope, bbot)
- scan: Port scanning, service detection, web discovery (tools: nmap, masscan, httpx, gobuster, ffuf)
- vuln: Vulnerability scanning, CVE detection (tools: nuclei, nikto, wpscan, testssl)
- exploit: Exploitation, SQL injection, brute force (tools: sqlmap, hydra, metasploit, searchsploit)
- postexploit: Post-exploitation, privilege escalation (tools: linpeas, mimikatz, bloodhound)
- report: Generate reports and summaries

ROUTING LOGIC:
- If no data gathered yet → recon
- If subdomains/IPs found but no ports → scan
- If ports found but no vulnerabilities → vuln
- If vulnerabilities found → exploit
- If shell obtained → postexploit
- If asked for summary/report → report

Which agent should handle this task? Return ONLY the agent name (one word)."""

        try:
            llm = OllamaClient()
            response = llm.generate(prompt, timeout=15, stream=False).strip().lower()
            
            # Extract agent name - find first valid agent in response
            valid_agents = ["recon", "scan", "vuln", "exploit", "postexploit", "report", "system"]
            
            for agent in valid_agents:
                if agent in response:
                    return self.agents[agent]
            
        except Exception as e:
            print(f"  ⚠️ LLM routing error: {e}")
        
        # Fallback: use context-based inference
        return self._fallback_route(context)
    
    def _fallback_route(self, context: Dict[str, Any]) -> BaseAgent:
        """Fallback routing when LLM fails - based on context state."""
        # Check what data we have
        has_subdomains = bool(context.get("subdomains")) or context.get("has_subdomains")
        has_ports = bool(context.get("open_ports")) or context.get("has_ports")
        has_vulns = bool(context.get("vulns_found"))
        has_shell = context.get("shell_obtained", False)
        
        if has_shell:
            return self.agents["postexploit"]
        if has_vulns:
            return self.agents["exploit"]
        if has_ports:
            return self.agents["vuln"]
        if has_subdomains:
            return self.agents["scan"]
        
        return self.agents["recon"]
    
    def _infer_phase(self, context: Dict[str, Any]) -> int:
        """
        Infer current phase from context using LLM.
        
        Returns phase number (1-6) based on accumulated findings.
        """
        from app.agent.core import get_phase_manager
        pm = get_phase_manager()
        return pm.get_current_phase(context)
    
    def plan_with_agent(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route query and get plan from appropriate agent.
        
        PRIORITIZES USER-SPECIFIED TOOLS over agent's automatic selection.
        
        Returns:
            Dict with agent name, tools, commands, and reasoning.
        """
        # Select agent using LLM
        agent = self.route(query, context)
        
        # Get agent's plan - with user tool priority
        plan = agent.plan_with_user_priority(query, context)
        
        # Add routing info
        plan["routed_by"] = "llm_coordinator"
        plan["phase"] = self._infer_phase(context)
        
        return plan
    
    def execute_with_agent(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route, plan, and execute tools with appropriate agent.
        
        Returns execution results.
        """
        # Get plan
        plan = self.plan_with_agent(query, context)
        
        agent = self.agents[plan["agent"]]
        tools = plan.get("tools", [])
        commands = plan.get("commands", {})
        
        # Get all available targets
        targets = self._get_all_targets(context)
        
        # Execute each tool
        results = {}
        for tool in tools:
            command = commands.get(tool)
            if not command:
                # Get first available command for tool
                spec = agent.registry.tools.get(tool)
                if spec and spec.commands:
                    command = list(spec.commands.keys())[0]
            
            if command:
                # Get params from context - use all discovered targets
                primary_target = targets[0] if targets else context.get("last_domain", "")
                params = {
                    "domain": primary_target,
                    "target": primary_target,
                    "url": f"https://{primary_target}" if primary_target else "",
                    "targets": targets[:20]  # For batch operations
                }
                
                print(f"  🤖 Agent '{agent.AGENT_NAME}' executing {tool}...")
                results[tool] = agent.execute_tool(tool, command, params)
        
        return {
            "agent": plan["agent"],
            "tools_run": tools,
            "results": results,
            "reasoning": plan.get("reasoning", "")
        }
    
    def _get_all_targets(self, context: Dict[str, Any]) -> List[str]:
        """Get all targets for execution from context."""
        targets = []
        
        # Main domain
        if context.get("target_domain"):
            targets.append(context["target_domain"])
        elif context.get("last_domain"):
            targets.append(context["last_domain"])
        
        # Discovered subdomains
        if context.get("subdomains"):
            targets.extend(context["subdomains"][:50])
        
        # Discovered IPs
        if context.get("ips"):
            targets.extend(context["ips"][:20])
        
        return list(set(targets))
    
    def get_all_agents(self) -> List[Dict[str, Any]]:
        """Get info about all available agents."""
        return [agent.get_agent_info() for agent in self.agents.values()]
    
    def get_agent(self, name: str) -> Optional[BaseAgent]:
        """Get a specific agent by name."""
        return self.agents.get(name)
    
    def _get_agent_for_phase(self, phase: int) -> BaseAgent:
        """Get the agent responsible for a specific phase."""
        phase_agent_map = {
            1: "recon",
            2: "scan",
            3: "vuln",
            4: "exploit",
            5: "postexploit",
            6: "report"
        }
        return self.agents.get(phase_agent_map.get(phase, "recon"))
    
    def evaluate_phase_completion(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use LLM-driven PhaseAnalyzer to evaluate if phase is complete.
        
        Returns:
            Dict with phase info, completion status, and suggestions
        """
        from app.agent.core import analyze_phase_completion
        
        phase = self._infer_phase(context)
        
        print(f"  🔍 Evaluating {PHASE_NAMES.get(phase, 'Unknown')} phase completion...")
        
        # Use LLM-driven PhaseAnalyzer
        analysis = analyze_phase_completion(context)
        
        if analysis:
            result = {
                "phase": phase,
                "phase_name": PHASE_NAMES.get(phase, "Unknown"),
                "is_complete": analysis.phase_complete,
                "reason": analysis.summary,
                "next_action": analysis.suggested_action,
                "suggested_tools": analysis.suggested_tools,
                "confidence": analysis.confidence,
                "missing": analysis.missing
            }
            
            if analysis.phase_complete and analysis.next_phase > phase:
                result["next_phase"] = analysis.next_phase
                result["next_phase_name"] = analysis.next_phase_name
                result["next_agent"] = self._get_agent_for_phase(analysis.next_phase).AGENT_NAME
            
            # Don't print to_suggestion_message() here - auto_advance() handles output
            return result
        
        # Fallback to agent's is_complete method
        current_agent = self._get_agent_for_phase(phase)
        is_complete, reason, next_action = current_agent.is_complete(context)
        
        result = {
            "phase": phase,
            "phase_name": PHASE_NAMES.get(phase, "Unknown"),
            "is_complete": is_complete,
            "reason": reason,
            "next_action": next_action
        }
        
        if is_complete and phase < 6:
            result["next_phase"] = phase + 1
            result["next_phase_name"] = PHASE_NAMES.get(phase + 1, "Unknown")
            result["next_agent"] = self._get_agent_for_phase(phase + 1).AGENT_NAME
        
        return result
    
    def auto_advance(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if current phase is complete and automatically advance.
        
        AUTONOMOUS MODE: No user confirmation needed.
        
        Returns:
            Evaluation result with next phase info
        """
        evaluation = self.evaluate_phase_completion(context)
        
        if evaluation["is_complete"]:
            print(f"  ✅ {evaluation['phase_name']} phase COMPLETE: {evaluation['reason']}")
            if evaluation.get("next_phase"):
                print(f"  🔄 Auto-advancing to {evaluation['next_phase_name']} phase")
            return evaluation
        else:
            print(f"  ⏳ {evaluation['phase_name']} phase INCOMPLETE: {evaluation['reason']}")
            if evaluation.get("next_action"):
                print(f"  💡 Suggested: {evaluation['next_action']}")
            return None


# Singleton instance
_coordinator: Optional[AgentCoordinator] = None


def get_coordinator(llm=None) -> AgentCoordinator:
    """Get or create the coordinator singleton."""
    global _coordinator
    if _coordinator is None:
        _coordinator = AgentCoordinator(llm)
    return _coordinator
