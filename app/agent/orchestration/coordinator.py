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
        # Build reverse mapping: tool_name -> agent_name for fast lookup
        self._tool_to_agent: Dict[str, str] = {}
        self._build_tool_agent_map()
    
    def _build_tool_agent_map(self):
        """
        Build mapping from tool names to agent names using SPECIALIZED_TOOLS.
        
        For tools in multiple agents, prioritize:
        1. Agent with lower phase number (more specialized)
        2. Agent with fewer phases (more focused)
        """
        # First pass: collect all tool->agent mappings
        tool_agents: Dict[str, List[tuple]] = {}  # tool -> [(agent_name, min_phase, phase_count), ...]
        
        for agent_name, agent in self.agents.items():
            # Get SPECIALIZED_TOOLS (class variable) or fallback to instance variable
            specialized_tools = getattr(agent, 'SPECIALIZED_TOOLS', None)
            if not specialized_tools:
                # Fallback for agents that use instance variable
                specialized_tools = getattr(agent, 'specialized_tools', [])
            
            # Get PENTEST_PHASES (class variable) or fallback to instance variable
            pentest_phases = getattr(agent, 'PENTEST_PHASES', None)
            if not pentest_phases:
                pentest_phases = getattr(agent, 'pentest_phases', [])
            
            min_phase = min(pentest_phases) if pentest_phases else 99
            phase_count = len(pentest_phases)
            
            for tool in specialized_tools:
                tool_lower = tool.lower()
                if tool_lower not in tool_agents:
                    tool_agents[tool_lower] = []
                tool_agents[tool_lower].append((agent_name, min_phase, phase_count))
        
        # Second pass: select best agent for each tool
        for tool_lower, candidates in tool_agents.items():
            # Sort by: 1) fewer phases (more specialized), 2) lower min_phase
            # This prioritizes agents that are more focused (e.g., vuln agent for nuclei)
            candidates.sort(key=lambda x: (x[2], x[1]))
            # Use the first (best) agent
            self._tool_to_agent[tool_lower] = candidates[0][0]
    
    def get_agent_by_tool(self, tool_name: str) -> Optional[BaseAgent]:
        """
        Get agent that handles a specific tool.
        
        Uses SPECIALIZED_TOOLS from agents instead of hardcoded mapping.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Agent instance or None if not found
        """
        agent_name = self._tool_to_agent.get(tool_name.lower())
        if agent_name:
            return self.agents.get(agent_name)
        
        # Fallback: search through agents (check both class and instance variables)
        for agent in self.agents.values():
            specialized_tools = getattr(agent, 'SPECIALIZED_TOOLS', None)
            if not specialized_tools:
                specialized_tools = getattr(agent, 'specialized_tools', [])
            
            if tool_name.lower() in [t.lower() for t in specialized_tools]:
                return agent
        
        return None
    
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
        
        analyzer_next_tool = context.get("analyzer_next_tool")
        context_summary = self._summarize_context(context)
        
        # Add analyzer recommendation to prompt if exists
        analyzer_note = ""
        if analyzer_next_tool:
            analyzer_note = f"\n\nIMPORTANT: Analyzer recommended next tool: {analyzer_next_tool}. User said '{query}' which likely means 'do the next step' - consider using this recommendation."
        
        prompt = f"""You are routing a pentest task to the best agent.

TASK: {query}
CONTEXT: {context_summary}{analyzer_note}

AVAILABLE AGENTS (FunctionGemma manages 7 agents, excluding report):
- recon: Subdomain enumeration, OSINT, DNS lookup, WHOIS (tools: amass, subfinder, whois, clatscope, bbot)
- scan: Port scanning, service detection, web discovery (tools: nmap, masscan, httpx, gobuster, ffuf)
- vuln: Vulnerability scanning, CVE detection (tools: nuclei, nikto, wpscan, testssl)
- exploit: Exploitation, SQL injection, brute force (tools: sqlmap, hydra, metasploit, searchsploit)
- postexploit: Post-exploitation, privilege escalation (tools: linpeas, mimikatz, bloodhound)
- system: System utilities and helpers

ROUTING LOGIC:
- If no data gathered yet → recon
- If subdomains/IPs found but no ports → scan
- If ports found but no vulnerabilities → vuln
- If vulnerabilities found → exploit
- If shell obtained → postexploit
- Report agent is called separately after 6 agents complete

Which agent should handle this task? Return ONLY the agent name (one word)."""

        try:
            # Use planner model for tool selection
            llm = OllamaClient(model="planner")
            response = llm.generate(prompt, timeout=15, stream=False).strip().lower()
            
            # Extract agent name - find first valid agent in response
            # FunctionGemma manages 7 agents (excluding report agent)
            # Report agent is only called after 6 agents complete
            valid_agents = ["recon", "scan", "vuln", "exploit", "postexploit", "system"]
            
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
        
        Supports FunctionGemma with function calling if planner model is FunctionGemma.
        
        Returns:
            Dict with agent name, tools, commands, and reasoning.
        """
        analyzer_next_tool = context.get("analyzer_next_tool")
        
        # Check if planner model is FunctionGemma - use function calling
        from app.llm.config import get_planner_model
        planner_model = get_planner_model()
        
        # Select agent using LLM (exclude report agent for FunctionGemma)
        agent = self.route(query, context)
        
        # Ensure report agent is not selected when using FunctionGemma
        if "functiongemma" in planner_model.lower() and agent.AGENT_NAME == "report":
            # Fallback to recon if report was selected (shouldn't happen with updated valid_agents)
            agent = self.agents["recon"]
        
        # If "do the next step" and analyzer has recommendation, pass it to agent
        query_lower = query.lower()
        if analyzer_next_tool and ("next step" in query_lower or "do the" in query_lower or ("suggest" in query_lower and "step" in query_lower)):
            context["user_requested_tool"] = analyzer_next_tool
            context["user_requested_target"] = context.get("analyzer_next_target")
        
        if "functiongemma" in planner_model.lower():
            # Use FunctionGemma with function calling (7 agents, excluding report)
            return self._plan_with_functiongemma(query, context, agent)
        
        # Get agent's plan - with user tool priority (regular method)
        plan = agent.plan_with_user_priority(query, context)
        
        # Add routing info
        plan["routed_by"] = "llm_coordinator"
        plan["phase"] = self._infer_phase(context)
        
        return plan
    
    def _plan_with_functiongemma(self, query: str, context: Dict[str, Any], agent) -> Dict[str, Any]:
        """
        Plan using FunctionGemma with function calling.
        
        Converts available tools to function definitions and lets FunctionGemma
        select tools via function calling.
        """
        from app.llm.client import OllamaClient
        from app.llm.function_calling import tools_to_function_definitions, parse_tool_calls
        from app.tools.registry import get_registry
        
        registry = get_registry()
        
        # Get available tools for this agent
        available_tools = []
        if hasattr(agent, 'SPECIALIZED_TOOLS') and agent.SPECIALIZED_TOOLS:
            available_tools = [t for t in agent.SPECIALIZED_TOOLS if registry.is_available(t)]
        else:
            # Fallback: get all available tools
            available_tools = [t for t in registry.list_tools() if registry.is_available(t)]
        
        # Filter out already-run tools
        tools_run = set(context.get("tools_run", []))
        available_tools = [t for t in available_tools if t not in tools_run]
        
        if not available_tools:
            return {
                "agent": agent.AGENT_NAME,
                "tools": [],
                "commands": {},
                "reasoning": "No available tools to run (all tools already executed)",
                "routed_by": "functiongemma",
                "phase": self._infer_phase(context)
            }
        
        # Convert tools to function definitions
        function_defs = tools_to_function_definitions(available_tools[:20], registry)  # Limit to 20 tools
        
        # Build prompt for FunctionGemma
        context_str = self._summarize_context(context)
        prompt = f"""Select the best security tools to run for this task.

TASK: {query}
CONTEXT: {context_str}

Available tools: {', '.join(available_tools[:10])}
Tools already run: {', '.join(list(tools_run)[:5]) if tools_run else 'None'}

Select 1-3 tools that best accomplish this task. Consider:
- What has already been run (don't repeat)
- What information we already have
- The most efficient path to the goal"""
        
        # Call FunctionGemma with function calling
        llm = OllamaClient(model="planner")
        result = llm.generate_with_tools(
            prompt=prompt,
            tools=function_defs,
            system="You are a penetration testing tool selector. Select tools using function calling.",
            timeout=30
        )
        
        # Parse tool calls
        tool_calls = parse_tool_calls(result.get("tool_calls", []))
        
        if not tool_calls:
            # Fallback to regular planning if no tool calls
            plan = agent.plan_with_user_priority(query, context)
            plan["routed_by"] = "functiongemma_fallback"
            plan["phase"] = self._infer_phase(context)
            return plan
        
        # Extract selected tools
        selected_tools = [tc["tool"] for tc in tool_calls]
        
        # Get commands for selected tools
        commands = {}
        for tool in selected_tools:
            spec = registry.tools.get(tool)
            if spec and spec.commands:
                commands[tool] = list(spec.commands.keys())[0]
        
        return {
            "agent": agent.AGENT_NAME,
            "tools": selected_tools,
            "commands": commands,
            "reasoning": f"FunctionGemma selected {len(selected_tools)} tools via function calling",
            "routed_by": "functiongemma",
            "phase": self._infer_phase(context)
        }
    
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
        """Get all targets for execution from context (domain, subdomains, IPs, interesting URLs)."""
        import re
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
        
        # Extract domains from interesting URLs
        interesting_urls = context.get("interesting_urls", [])
        if interesting_urls:
            for url in interesting_urls[:30]:  # Limit to 30 URLs
                # Extract domain from URL
                url = url.strip()
                if url.startswith(("http://", "https://")):
                    # Remove protocol
                    domain = re.sub(r'^https?://', '', url)
                    # Remove path and port
                    domain = domain.split('/')[0].split(':')[0]
                    if domain and domain not in targets:
                        targets.append(domain)
        
        # Also try to get from RAG if available
        domain = context.get("target_domain") or context.get("last_domain")
        if domain:
            try:
                from app.rag import get_unified_rag
                rag = get_unified_rag()
                # Get IPs
                rag_ips = rag.get_ips(domain, limit=50)
                if rag_ips:
                    targets.extend(rag_ips)
                # Get subdomains
                rag_subs = rag.get_subdomains(domain, limit=50)
                if rag_subs:
                    targets.extend(rag_subs)
            except Exception:
                pass
        
        return list(set(targets))  # Deduplicate
    
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
