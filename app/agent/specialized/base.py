"""
Base Specialized Agent
======================

Abstract base class for all specialized agents.
Each agent has a specific role with associated prompts and tools.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import logging

from app.agent.roles import get_role_manager, AgentRole
from app.tools.registry import get_registry, ToolResult
from app.prompts import get_prompt_loader

logger = logging.getLogger(__name__)


@dataclass
class AgentResult:
    """Result from agent execution"""
    agent_name: str
    success: bool
    output: str
    findings: Dict[str, Any]
    tool_results: List[ToolResult]
    next_action: Optional[str] = None
    suggested_agents: List[str] = None
    
    def __post_init__(self):
        if self.suggested_agents is None:
            self.suggested_agents = []


class BaseSpecializedAgent(ABC):
    """
    Base class for specialized pentest agents.
    
    Each agent:
    - Has a specific role loaded from prompts/roles/
    - Has access to a subset of tools
    - Can execute tool chains
    - Can suggest next agents
    """
    
    # Override in subclass
    ROLE_NAME: str = ""
    
    def __init__(self, llm_client=None, config: Dict = None):
        self.role_manager = get_role_manager()
        self.registry = get_registry()
        self.prompt_loader = get_prompt_loader()
        self.llm = llm_client
        self.config = config or {}
        
        # Load role
        self.role: Optional[AgentRole] = None
        if self.ROLE_NAME:
            self.role = self.role_manager.load_role(self.ROLE_NAME)
            if self.role:
                logger.info(f"Loaded agent role: {self.role.name}")
            else:
                logger.warning(f"Role not found: {self.ROLE_NAME}")
    
    @property
    def name(self) -> str:
        """Agent display name"""
        return self.role.name if self.role else self.ROLE_NAME
    
    @property
    def description(self) -> str:
        """Agent description"""
        return self.role.description if self.role else ""
    
    @property
    def allowed_tools(self) -> List[str]:
        """List of tools this agent can use"""
        return self.role.tools_allowed if self.role else []
    
    @property
    def system_prompt(self) -> str:
        """System prompt for LLM"""
        return self.role.system_prompt if self.role else ""
    
    def get_user_prompt(self, context: Dict) -> str:
        """Format user prompt with context"""
        if not self.role:
            return context.get('user_input', '')
        return self.prompt_loader.format_prompt(
            self.role.user_prompt_template, 
            context
        )
    
    def can_use_tool(self, tool_name: str) -> bool:
        """Check if this agent is allowed to use a tool"""
        return tool_name in self.allowed_tools
    
    def execute_tool(
        self, 
        tool: str, 
        command: str, 
        params: Dict[str, Any]
    ) -> ToolResult:
        """Execute a single tool if allowed"""
        if not self.can_use_tool(tool):
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"Tool '{tool}' not allowed for {self.name}"
            )
        return self.registry.execute(tool, command, params)
    
    def execute_tool_chain(
        self, 
        chain: List[Dict[str, Any]]
    ) -> List[ToolResult]:
        """Execute multiple tools in sequence"""
        results = []
        for item in chain:
            tool = item.get('tool')
            command = item.get('command', 'default')
            params = item.get('params', {})
            
            result = self.execute_tool(tool, command, params)
            results.append(result)
            
            # Stop chain on failure if configured
            if not result.success and item.get('stop_on_failure', False):
                break
        
        return results
    
    @abstractmethod
    def execute(self, task: str, context: Dict = None) -> AgentResult:
        """
        Execute agent task.
        
        Args:
            task: User task/query
            context: Additional context (previous findings, targets, etc.)
            
        Returns:
            AgentResult with findings and suggestions
        """
        pass
    
    def _generate_llm_response(
        self, 
        user_prompt: str, 
        system_prompt: str = None
    ) -> str:
        """Generate LLM response using configured client"""
        if not self.llm:
            logger.warning("No LLM client configured for agent")
            return ""
        
        sys_prompt = system_prompt or self.system_prompt
        return self.llm.generate(user_prompt, system=sys_prompt)
    
    def suggest_next_agent(self, findings: Dict) -> Optional[str]:
        """Suggest next agent based on findings (override in subclass)"""
        return None
