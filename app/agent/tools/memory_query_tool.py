"""
Memory Query Tool

Extracts and encapsulates logic from memory_query_node().
Retrieves and displays stored data from memory/context.
"""
from typing import Dict, Any, Optional
from app.agent.tools.base import AgentTool
from app.ui import get_logger

logger = get_logger()


class MemoryQueryTool(AgentTool):
    """Tool for querying and displaying memory data."""
    
    def execute(self, context: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """
        Retrieve and display stored data from memory/context.
        
        Args:
            context: Current context dictionary
            
        Returns:
            Dictionary with formatted memory display response
        """
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        
        # Get domain - handle None case
        domain = context.get("last_domain") or context.get("target_domain") or "Unknown target"
        if domain == "None" or domain is None:
            domain = "Unknown target"
        
        # Use MemoryDisplayService to format response
        try:
            from app.agent.utils.memory_display import get_memory_display
            display_service = get_memory_display()
            response = display_service.format_memory_query(context, domain)
        except Exception as e:
            # Fallback if service fails
            logger.warning(f"Memory display service error: {e}", icon="")
            response = f"## 📊 Stored Data for {domain}\n\nError formatting memory data. Please try again."
        
        return {
            "response": response,
            "next_action": "end"
        }
