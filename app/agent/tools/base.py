"""
Base Agent Tool Class

Base class for all agent operation tools.
Follows agent-zero pattern where each operation is a tool.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from app.agent.graph import AgentState


class AgentTool(ABC):
    """
    Base class for agent operation tools.
    
    Each tool encapsulates logic from a graph node operation,
    making the graph a lightweight orchestrator.
    """
    
    def __init__(self, state: Optional[AgentState] = None):
        """
        Initialize the tool with optional state.
        
        Args:
            state: Current agent state (optional, can be passed to execute)
        """
        self.state = state
    
    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the tool operation.
        
        Args:
            **kwargs: Tool-specific parameters
            
        Returns:
            Dictionary with state updates to merge into AgentState
        """
        pass
    
    def get_state(self) -> Optional[AgentState]:
        """Get the current state."""
        return self.state
    
    def set_state(self, state: AgentState):
        """Update the state."""
        self.state = state
