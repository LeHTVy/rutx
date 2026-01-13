"""
Tool Loader - Auto-load agent tools from directory.

Similar to agent-zero's tool loading system.
"""
import importlib
import os
from pathlib import Path
from typing import Dict, Type, Optional
from app.agent.tools.base import AgentTool
from app.agent.graph import AgentState


# Cache for loaded tool classes
_TOOL_CLASSES: Dict[str, Type[AgentTool]] = {}


def _load_tool_classes():
    """Load all tool classes from the tools directory."""
    global _TOOL_CLASSES
    
    if _TOOL_CLASSES:
        return _TOOL_CLASSES
    
    tools_dir = Path(__file__).parent
    tools_package = "app.agent.tools"
    
    # Get all Python files in tools directory
    for file_path in tools_dir.glob("*.py"):
        if file_path.name.startswith("_") or file_path.name == "loader.py" or file_path.name == "base.py":
            continue
        
        module_name = file_path.stem
        try:
            # Import the module
            module = importlib.import_module(f"{tools_package}.{module_name}")
            
            # Find all AgentTool subclasses
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, AgentTool) and 
                    attr != AgentTool):
                    # Use class name (lowercase) as tool name
                    tool_name = attr_name.lower().replace("tool", "")
                    _TOOL_CLASSES[tool_name] = attr
        except Exception as e:
            # Skip modules that can't be imported
            print(f"⚠️ Could not load tool from {module_name}: {e}")
            continue
    
    return _TOOL_CLASSES


def get_tool(tool_name: str, state: Optional[AgentState] = None) -> Optional[AgentTool]:
    """
    Load and instantiate an agent tool.
    
    Args:
        tool_name: Name of the tool (e.g., "intent_classifier", "planner")
        state: Optional agent state to pass to tool
        
    Returns:
        Tool instance or None if not found
    """
    classes = _load_tool_classes()
    
    # Try exact match first
    tool_class = classes.get(tool_name)
    
    # Try with common variations
    if not tool_class:
        for name, cls in classes.items():
            if tool_name in name or name in tool_name:
                tool_class = cls
                break
    
    if tool_class:
        return tool_class(state)
    
    return None


def list_tools() -> list[str]:
    """
    List all available tool names.
    
    Returns:
        List of tool names
    """
    classes = _load_tool_classes()
    return list(classes.keys())
