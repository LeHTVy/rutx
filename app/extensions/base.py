"""
Base Extension Class for SNODE
==============================
"""
from abc import ABC, abstractmethod
from typing import Any, Optional


class Extension(ABC):
    """
    Base class for SNODE extensions.
    
    Extensions are plugins that can hook into agent behavior at key points.
    """
    
    def __init__(self, agent=None, **kwargs):
        """
        Initialize extension.
        
        Args:
            agent: Optional agent instance
            **kwargs: Additional configuration
        """
        self.agent = agent
        self.kwargs = kwargs
    
    @abstractmethod
    async def execute(self, **kwargs) -> Any:
        """
        Execute the extension.
        
        Args:
            **kwargs: Context-specific arguments
            
        Returns:
            Optional result
        """
        pass
