"""
Superior-Subordinate Agent Hierarchy for SNODE
==============================================

Enables hierarchical agent communication where:
- Superior agents delegate tasks to subordinates
- Subordinate agents report back to superiors
- Each subordinate has isolated context
"""
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime

from app.agent.agents.base_agent import BaseAgent
from app.agent.orchestration import get_coordinator


@dataclass
class SubordinateAgent:
    """Represents a subordinate agent in the hierarchy."""
    agent: BaseAgent
    task: str
    superior_agent: BaseAgent
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[str] = None


class HierarchicalAgentMixin:
    """
    Mixin for agents to support hierarchical communication.
    
    Adds methods for creating and managing subordinate agents.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._subordinates: List[SubordinateAgent] = []
    
    def create_subordinate(
        self,
        task: str,
        specialized_agent: str = None,
        context: Dict[str, Any] = None
    ) -> SubordinateAgent:
        """
        Create a subordinate agent to handle a subtask.
        
        Args:
            task: The task to delegate
            specialized_agent: Optional agent name (recon, scan, vuln, etc.)
            context: Optional context to pass to subordinate
            
        Returns:
            SubordinateAgent instance
        """
        coordinator = get_coordinator()
        
        # Get appropriate agent
        if specialized_agent:
            agent = coordinator.get_agent(specialized_agent)
        else:
            # Let coordinator route based on task
            agent = coordinator.route(task, context or {})
        
        # Create subordinate with isolated context
        subordinate = SubordinateAgent(
            agent=agent,
            task=task,
            superior_agent=self,
            context=context or {}
        )
        
        self._subordinates.append(subordinate)
        return subordinate
    
    async def delegate_to_subordinate(
        self,
        subordinate: SubordinateAgent,
        wait_for_result: bool = True
    ) -> Optional[str]:
        """
        Delegate a task to a subordinate agent.
        
        Args:
            subordinate: The subordinate agent to delegate to
            wait_for_result: If True, wait for result; if False, return immediately
            
        Returns:
            Result from subordinate if wait_for_result=True, else None
        """
        subordinate.status = "running"
        
        try:
            # Execute task using subordinate agent
            plan = subordinate.agent.plan_with_user_priority(
                subordinate.task,
                subordinate.context
            )
            
            if wait_for_result:
                # Execute and get result
                # This would integrate with the executor
                result = f"Subordinate {subordinate.agent.AGENT_NAME} completed: {subordinate.task}"
                subordinate.status = "completed"
                subordinate.result = result
                return result
            else:
                # Start async execution
                subordinate.status = "running"
                return None
                
        except Exception as e:
            subordinate.status = "failed"
            subordinate.result = f"Error: {str(e)}"
            if wait_for_result:
                raise
            return None
    
    def get_subordinates(self) -> List[SubordinateAgent]:
        """Get all subordinate agents."""
        return self._subordinates.copy()
    
    def get_subordinate_by_task(self, task: str) -> Optional[SubordinateAgent]:
        """Get subordinate by task."""
        return next((s for s in self._subordinates if s.task == task), None)


def add_hierarchy_support(agent_class):
    """
    Decorator to add hierarchical support to an agent class.
    
    Usage:
        @add_hierarchy_support
        class MyAgent(BaseAgent):
            ...
    """
    # Add mixin methods to the class
    for name, method in HierarchicalAgentMixin.__dict__.items():
        if not name.startswith('_') and callable(method):
            setattr(agent_class, name, method)
    
    # Initialize subordinates list in __init__
    original_init = agent_class.__init__
    
    def new_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._subordinates = []
    
    agent_class.__init__ = new_init
    
    return agent_class
