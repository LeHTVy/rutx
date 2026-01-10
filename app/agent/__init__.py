"""
Agent Module - LangGraph State Machine
======================================

Clean architecture:
- LLM plans (suggests tools)
- User confirms
- Code executes (registry)
- LLM analyzes results
"""
# Main agent (lazy import to avoid langgraph requirement at module level)
def create_langgraph_agent(*args, **kwargs):
    from .graph import create_langgraph_agent as _create
    return _create(*args, **kwargs)

def get_langgraph_agent_class():
    from .graph import LangGraphAgent
    return LangGraphAgent

# Role Manager (no langgraph dependency)
from .roles import RoleManager, AgentRole, get_role_manager

# Memory (used by graph.py and memory_tools.py)
from .memory import AttackMemory, Fact, Hypothesis

# Intelligence layer
from .intelligence import get_intelligence, infer_phase

__all__ = [
    # Core Agent
    "create_langgraph_agent",
    "get_langgraph_agent_class",
    
    # Roles
    "RoleManager",
    "AgentRole", 
    "get_role_manager",
    
    # Memory
    "AttackMemory",
    "Fact",
    "Hypothesis",
    
    # Intelligence
    "get_intelligence",
    "infer_phase",
]

