"""
Base Agent - Shared Logic for All Specialized Agents
=====================================================

All specialized agents (Recon, Exploit, Report) inherit from this base.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import re


class BaseAgent(ABC):
    """Base class for all specialized agents."""
    
    # Override in subclasses
    AGENT_NAME = "base"
    AGENT_DESCRIPTION = "Base agent"
    SPECIALIZED_TOOLS: List[str] = []
    PENTEST_PHASES: List[int] = [1, 2, 3, 4]  # Phases this agent handles
    
    def __init__(self, llm=None):
        """Initialize agent with optional LLM client."""
        self._llm = llm
        self._tool_index = None
        self._registry = None
    
    @property
    def llm(self):
        """Lazy-load LLM client (avoid circular import with graph.py)."""
        if self._llm is None:
            try:
                from langchain_ollama import ChatOllama
                from app.llm import get_llm_config
                config = get_llm_config()
                self._llm = ChatOllama(model=config.model, base_url=config.host)
            except ImportError:
                # Fallback: try simple import
                from app.agent.graph import OllamaClient
                self._llm = OllamaClient()
        return self._llm
    
    @property
    def tool_index(self):
        """Lazy-load tool index."""
        if self._tool_index is None:
            from app.rag.tool_index import ToolIndex
            self._tool_index = ToolIndex()
        return self._tool_index
    
    @property
    def registry(self):
        """Lazy-load tool registry."""
        if self._registry is None:
            from app.tools.registry import get_registry
            self._registry = get_registry()
        return self._registry
    
    @abstractmethod
    def plan(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan tools and actions for the given query.
        
        Returns:
            Dict with keys:
                - tools: List[str] - Tools to execute
                - commands: Dict[str, str] - Command for each tool
                - reasoning: str - Why these tools were chosen
        """
        pass
    
    @abstractmethod
    def analyze_results(self, results: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Analyze execution results and provide insights."""
        pass
    
    def extract_user_tools(self, query: str) -> List[str]:
        """
        Extract tools explicitly mentioned by user in the query.
        
        PRIORITIZE USER CHOICE - if user says "use bbot and theHarvester",
        we should use those tools, not override with our selection.
        
        Returns:
            List of tool names mentioned in query (preserves original case)
        """
        # Get all registered tools
        all_tools = list(self.registry.tools.keys())
        
        # Normalize query for matching
        query_lower = query.lower()
        
        # Find tools mentioned in query (case-insensitive match)
        user_tools = []
        for tool in all_tools:
            # Case-insensitive matching with word boundaries
            pattern = rf'\b{re.escape(tool.lower())}\b'
            if re.search(pattern, query_lower, re.IGNORECASE):
                user_tools.append(tool)  # Keep original case from registry
        
        return user_tools
    
    def plan_with_user_priority(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan tools, prioritizing user-specified tools over agent selection.
        
        If user explicitly mentions tools, use those.
        Otherwise, fall back to agent's intelligent selection.
        """
        # First, check if user mentioned specific tools
        user_tools = self.extract_user_tools(query)
        
        if user_tools:
            # User specified tools - validate and use them
            valid_tools = [t for t in user_tools if self.registry.is_available(t)]
            unavailable = [t for t in user_tools if t not in valid_tools]
            
            # Warn about unavailable tools
            if unavailable:
                print(f"  ⚠️ Requested tools not available: {', '.join(unavailable)}")
            
            if valid_tools:
                # Get commands for user's tools
                commands = self._get_commands_for_tools(valid_tools, context)
                
                reasoning = f"Using your requested tools: {', '.join(valid_tools)}"
                if unavailable:
                    reasoning += f" (skipped unavailable: {', '.join(unavailable)})"
                
                return {
                    "agent": getattr(self, 'name', self.AGENT_NAME),
                    "tools": valid_tools,
                    "commands": commands,
                    "reasoning": reasoning,
                    "user_specified": True,
                    "unavailable_tools": unavailable
                }
        
        # No user-specified tools, use normal planning
        return self.plan(query, context)
    
    def _get_commands_for_tools(self, tools: List[str], context: Dict[str, Any]) -> Dict[str, str]:
        """Get recommended commands for a list of tools."""
        commands = {}
        for tool in tools:
            spec = self.registry.tools.get(tool)
            if spec and spec.commands:
                # Use first available command
                commands[tool] = list(spec.commands.keys())[0]
        return commands
    
    def is_complete(self, context: Dict[str, Any]) -> tuple:
        """
        Use LLM to determine if this phase has enough data to proceed.
        
        Returns: (is_complete: bool, reason: str, next_action: str)
        """
        from app.agent.prompts import PHASE_COMPLETION_PROMPTS
        from app.llm.client import OllamaClient
        
        # Get phase number for this agent
        phase = self.PENTEST_PHASES[0] if self.PENTEST_PHASES else 1
        
        # Build context for prompt
        prompt_template = PHASE_COMPLETION_PROMPTS.get(phase, PHASE_COMPLETION_PROMPTS[1])
        
        try:
            prompt = prompt_template.format(
                subdomain_count=context.get("subdomain_count", 0),
                ip_count=len(context.get("ips", [])),
                asn_count=context.get("asn_count", 0),
                tech_list=", ".join(context.get("detected_tech", [])[:5]) or "None",
                tools_run=", ".join(context.get("tools_run", [])[-5:]) or "None",
                port_count=context.get("port_count", 0),
                services=", ".join(s.get("service", "") for s in context.get("open_ports", [])[:5]) or "None",
                web_count=len([p for p in context.get("open_ports", []) if p.get("port") in [80, 443, 8080, 8443]]),
                dir_count=len(context.get("directories", [])),
                vuln_count=len(context.get("vulns_found", [])),
                critical_count=len([v for v in context.get("vulns_found", []) if v.get("severity") == "critical"]),
                high_count=len([v for v in context.get("vulns_found", []) if v.get("severity") == "high"]),
                cve_list=", ".join(v.get("cve_id", "") for v in context.get("vulns_found", [])[:3]) or "None",
                exploit_count=len(context.get("exploits_run", [])),
                success_count=len([e for e in context.get("exploits_run", []) if e.get("success")]),
                shell_obtained="Yes" if context.get("shell_obtained") else "No",
                access_level=context.get("access_level", "None"),
                privesc_done="Yes" if context.get("privesc_done") else "No",
                cred_count=len(context.get("credentials", [])),
                lateral_done="Yes" if context.get("lateral_done") else "No",
                data_collected=", ".join(context.get("loot", [])[:3]) or "None"
            )
        except KeyError:
            # If template has unmatched keys, use simpler approach
            prompt = prompt_template
        
        # Ask LLM
        llm = OllamaClient()
        response = llm.generate(prompt, timeout=30, stream=False)
        
        # Parse response
        is_complete = "COMPLETE" in response.upper() and "INCOMPLETE" not in response.upper()
        
        # Extract reason
        reason = "Phase analysis complete"
        if "REASON:" in response.upper():
            try:
                reason_start = response.upper().index("REASON:") + 7
                reason_end = response.find("\n", reason_start)
                reason = response[reason_start:reason_end if reason_end > 0 else len(response)].strip()
            except:
                pass
        
        # Extract next action
        next_action = ""
        if "NEXT_ACTION:" in response.upper():
            try:
                action_start = response.upper().index("NEXT_ACTION:") + 12
                next_action = response[action_start:].strip().split("\n")[0]
            except:
                pass
        
        return (is_complete, reason, next_action)
    
    def search_tools(self, query: str, n_results: int = 5) -> List[Dict]:
        """Search for relevant tools using semantic search."""
        return self.tool_index.search(query, n_results=n_results)
    
    def filter_by_specialty(self, tools: List[str]) -> List[str]:
        """Filter tools to only those in this agent's specialty."""
        if not self.SPECIALIZED_TOOLS:
            return tools  # No filter if not specified
        return [t for t in tools if t in self.SPECIALIZED_TOOLS]
    
    def execute_tool(self, tool_name: str, command: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single tool and return results."""
        if not self.registry.is_available(tool_name):
            return {
                "success": False,
                "error": f"Tool not available: {tool_name}"
            }
        
        result = self.registry.execute(tool_name, command, params)
        return {
            "success": result.success,
            "output": result.output if result.success else result.error,
            "error": result.error if not result.success else None
        }
    
    def execute_tool_chain(self, chain: List[Dict[str, Any]], stop_on_failure: bool = False) -> List[Dict[str, Any]]:
        """
        Execute multiple tools in sequence.
        
        Merged from specialized/base.py - useful for multi-step operations.
        
        Args:
            chain: List of dicts with keys: tool, command, params
            stop_on_failure: If True, stop chain on first failure
            
        Returns:
            List of results for each tool
        """
        results = []
        for item in chain:
            tool = item.get('tool')
            command = item.get('command', 'default')
            params = item.get('params', {})
            
            result = self.execute_tool(tool, command, params)
            results.append({
                "tool": tool,
                **result
            })
            
            # Stop chain on failure if configured
            if not result.get("success") and (stop_on_failure or item.get('stop_on_failure', False)):
                break
        
        return results
    
    def generate_response(self, prompt: str, timeout: int = 60) -> str:
        """Generate LLM response."""
        return self.llm.generate(prompt, timeout=timeout)
    
    def get_agent_info(self) -> Dict[str, Any]:
        """Return agent metadata."""
        return {
            "name": self.AGENT_NAME,
            "description": self.AGENT_DESCRIPTION,
            "specialized_tools": self.SPECIALIZED_TOOLS,
            "phases": self.PENTEST_PHASES
        }
    
    def can_handle(self, phase: int, query: str) -> bool:
        """
        Check if this agent can handle the given phase/query.
        
        Override in subclasses for more specific logic.
        """
        return phase in self.PENTEST_PHASES
    
    def suggest_next_agent(self, context: Dict[str, Any]) -> Optional[str]:
        """
        Suggest next agent based on current findings.
        
        Merged from specialized/base.py - enables agent handoff.
        Override in subclasses for specific handoff logic.
        
        Returns:
            Agent name to hand off to, or None to continue with current
        """
        # Default handoff based on phase progression
        from app.agent.core import get_phase_manager
        
        phase_mgr = get_phase_manager()
        current_phase = phase_mgr.get_current_phase(context)
        
        # Suggest next phase agent if current phase is complete
        is_complete, _, _ = self.is_complete(context)
        
        if is_complete and current_phase < 6:
            next_agents = {
                1: "scan",      # Recon → Scan
                2: "vuln",      # Scan → Vuln
                3: "exploit",   # Vuln → Exploit
                4: "postexploit",  # Exploit → Post-Exploit
                5: "report",    # Post-Exploit → Report
            }
            return next_agents.get(current_phase)
        
        return None
    
    def __repr__(self):
        return f"<{self.__class__.__name__} tools={len(self.SPECIALIZED_TOOLS)}>"

