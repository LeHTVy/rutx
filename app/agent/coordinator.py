"""
Agent Coordinator - Routes Queries to Specialized Agents (6-Phase PTES)
========================================================================

The brain that decides which agent handles each query.
Uses phase detection and query analysis to route appropriately.

PTES Phases:
1. Reconnaissance - OSINT, subdomain, DNS
2. Scanning - Port scan, service enum
3. Vulnerability - CVE detection, vuln scan
4. Exploitation - SQLi, RCE, brute force
5. Post-Exploitation - Priv esc, lateral movement
6. Reporting - Generate reports
"""
from typing import Dict, Any, Optional, List
from .base_agent import BaseAgent
from .recon_agent import ReconAgent
from .scan_agent import ScanAgent
from .vuln_agent import VulnAgent
from .exploit_agent import ExploitAgent
from .postexploit_agent import PostExploitAgent
from .report_agent import ReportAgent


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
    Coordinates between specialized agents for 6-phase pentest.
    
    Routes queries to the most appropriate agent based on:
    1. Current pentest phase (from context)
    2. Query keywords and intent
    3. Available data (subdomains, ports, vulns)
    """
    
    def __init__(self, llm=None):
        """Initialize coordinator with all specialized agents."""
        # Import system agent
        from .system_agent import SystemAgent
        
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
            from app.agent.graph import OllamaClient
            self._llm = OllamaClient()
        return self._llm
    
    @property
    def shared_memory(self):
        """Get shared memory for agent communication."""
        from app.agent.shared_memory import get_shared_memory
        return get_shared_memory()
    
    def get_context_for_agent(self, agent_name: str) -> Dict[str, Any]:
        """Get context tailored for specific agent from shared memory."""
        return self.shared_memory.get_for_agent(agent_name)
    
    def update_shared_memory(self, context: Dict[str, Any]):
        """Update shared memory from context dict."""
        self.shared_memory.update_from_dict(context)

    
    def route(self, query: str, context: Dict[str, Any]) -> BaseAgent:
        """
        Determine which agent should handle this query using LLM intelligence.
        
        NO HARDCODED KEYWORDS - LLM decides based on semantic understanding.
        """
        from app.agent.prompts import format_prompt
        from app.llm.client import OllamaClient
        
        # Infer current phase
        phase = self._infer_phase(context)
        
        # Build context for LLM
        has_subdomains = context.get("has_subdomains", False) or bool(context.get("subdomains"))
        has_ports = context.get("has_ports", False) or bool(context.get("open_ports"))
        has_vulns = bool(context.get("vulns_found"))
        target = context.get("target_domain") or context.get("last_domain") or "not set"
        
        # Use LLM to route
        try:
            prompt = format_prompt(
                "agent_router",
                query=query,
                current_phase=phase,
                target=target,
                has_subdomains=has_subdomains,
                has_ports=has_ports,
                has_vulns=has_vulns
            )
            
            llm = OllamaClient()
            response = llm.generate(prompt, timeout=15, stream=False).strip().lower()
            
            # Extract agent name from response (handle multi-word responses)
            valid_agents = ["recon", "scan", "vuln", "exploit", "postexploit", "report", "system"]
            agent_name = None
            
            for agent in valid_agents:
                if agent in response:
                    agent_name = agent
                    break
            
            if agent_name and agent_name in self.agents:
                return self.agents[agent_name]
            
        except Exception as e:
            # Fallback to phase-based routing on LLM error
            print(f"  ⚠️ LLM routing failed: {e}, using phase-based fallback")
        
        # Fall back to phase-based routing
        phase_agent_map = {
            1: "recon",
            2: "scan",
            3: "vuln",
            4: "exploit",
            5: "postexploit",
            6: "report"
        }
        
        return self.agents.get(phase_agent_map.get(phase, "recon"), self.agents["recon"])
    
    def _infer_phase(self, context: Dict[str, Any]) -> int:
        """
        Determine current pentest phase from context.
        
        Returns CURRENT phase based on what tools have been run:
        Phase 1: Reconnaissance - Running/completed recon tools
        Phase 2: Scanning - Running scanning tools (nmap, etc)
        Phase 3: Vulnerability - Running vuln scanners
        Phase 4: Exploitation - Running exploit tools
        Phase 5: Post-Exploitation - Shell obtained, running post-exploit
        Phase 6: Reporting - Documenting findings
        """
        # Check context state
        tools_run = context.get("tools_run", [])
        vulns_found = context.get("vulns_found", [])
        exploits_run = context.get("exploits_run", [])
        shell_obtained = context.get("shell_obtained", False)
        
        # Phase 6: Reporting - explicit request
        if context.get("generate_report"):
            return 6
        
        # Phase 5: Post-exploitation - shell obtained
        if shell_obtained or any(t in tools_run for t in ["mimikatz", "linpeas", "winpeas", "bloodhound"]):
            return 5
        
        # Phase 4: Exploitation
        if exploits_run or any(t in tools_run for t in ["sqlmap", "hydra", "msfconsole", "searchsploit"]):
            return 4
        
        # Phase 3: Vulnerability assessment
        if vulns_found or any(t in tools_run for t in ["nuclei", "nikto", "wpscan"]):
            return 3
        
        # Phase 2: Scanning - when scanning tools are run
        has_ports = context.get("has_ports", False) or context.get("open_ports")
        if has_ports or any(t in tools_run for t in ["nmap", "masscan", "rustscan", "httpx", "gobuster", "ffuf"]):
            return 2
        
        # Phase 1: Reconnaissance - default, or when recon tools are run
        # Having subdomains means recon is in progress, NOT that we're in phase 2
        return 1
    
    def plan_with_agent(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route query and get plan from appropriate agent.
        
        PRIORITIZES USER-SPECIFIED TOOLS over agent's automatic selection.
        
        Returns:
            Dict with agent name, tools, commands, and reasoning.
        """
        # Select agent
        agent = self.route(query, context)
        
        # Get agent's plan - with user tool priority
        plan = agent.plan_with_user_priority(query, context)
        
        # Add routing info
        plan["routed_by"] = "coordinator"
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
        
        # Execute each tool
        results = {}
        for tool in tools:
            command = commands.get(tool, list(agent.registry.tools.get(tool, {}).commands.keys())[0] if agent.registry.is_available(tool) else None)
            if command:
                # Get params from context
                params = {
                    "domain": context.get("last_domain", ""),
                    "target": context.get("last_domain", ""),
                    "url": f"https://{context.get('last_domain', '')}"
                }
                results[tool] = agent.execute_tool(tool, command, params)
        
        return {
            "agent": plan["agent"],
            "tools_run": tools,
            "results": results,
            "reasoning": plan.get("reasoning", "")
        }
    
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
        
        ENHANCED: Now uses dedicated phase_analyzer.md prompt for
        intelligent phase completion detection and transition suggestions.
        
        Returns:
            Dict with:
                - phase: current phase number
                - phase_name: current phase name
                - is_complete: bool
                - reason: LLM's explanation
                - next_action: recommended next step
                - next_phase: next phase number (if complete)
                - next_agent: next agent name (if complete)
                - suggested_tools: tools for next step
        """
        from app.agent.phase_analyzer import analyze_phase_completion
        
        phase = self._infer_phase(context)
        
        print(f"  🔍 Evaluating {PHASE_NAMES.get(phase, 'Unknown')} phase completion...")
        
        # Use our new LLM-driven PhaseAnalyzer
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
            
            # Print the suggestion message
            print(analysis.to_suggestion_message())
            
            return result
        
        # Fallback to agent's is_complete method if PhaseAnalyzer fails
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
        Check if current phase is complete and suggest advancing.
        
        Returns None if phase is not complete, otherwise returns
        suggestion for next phase.
        """
        evaluation = self.evaluate_phase_completion(context)
        
        if evaluation["is_complete"]:
            print(f"  ✅ {evaluation['phase_name']} phase COMPLETE: {evaluation['reason']}")
            if evaluation.get("next_phase"):
                print(f"  🔄 Ready to advance to {evaluation['next_phase_name']} phase")
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
