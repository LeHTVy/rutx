"""
Agent Module - LangGraph State Machine
======================================

Clean architecture:
- LLM plans (suggests tools)
- User confirms
- Code executes (registry)
- LLM analyzes results

Multi-Agent Support:
- Specialized agents for different phases
- Agent orchestrator for routing
- Role-based prompt system
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

# Orchestrator (uses specialized agents)
from .orchestrator import AgentOrchestrator, get_orchestrator

# Memory and Evidence
from .memory import AttackMemory, Fact, Hypothesis
from .evidence import EvidenceStore, Evidence, Finding

# Analyzer (used by graph)
from .analyzer import Analyzer, AnalyzerDecision, DecisionType

__all__ = [
    # Core Agent
    "create_langgraph_agent",
    "get_langgraph_agent_class",
    
    # Multi-Agent
    "RoleManager",
    "AgentRole", 
    "get_role_manager",
    "AgentOrchestrator",
    "get_orchestrator",
    
    # Analyzer
    "Analyzer",
    "AnalyzerDecision",
    "DecisionType",
    
    # Memory
    "AttackMemory",
    "Fact",
    "Hypothesis",
    
    # Evidence
    "EvidenceStore",
    "Evidence",
    "Finding",
]

