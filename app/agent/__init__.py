"""
Agent Module - LangGraph State Machine
======================================

Organized structure:
- agents/     - Specialized phase agents (recon, scan, vuln, etc.)
- core/       - Core infrastructure (phase, memory, context)
- orchestration/ - Agent coordination and autonomous mode
- utils/      - Utilities (parser, validation, fallback)
- prompts/    - Prompt templates

Key principle: LLM plans, CODE executes, LLM analyzes.
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

# Memory - now in app.memory (re-export for backward compat)
from app.memory import (
    SessionMemory as AttackMemory,  # Renamed
    Fact,
    Hypothesis,
    get_session_memory,
    get_shared_memory,
)

# Intelligence layer (stays in root - used everywhere)
from .intelligence import get_intelligence, infer_phase

# Re-export from subpackages for convenience
from .agents import (
    BaseAgent,
    ReconAgent, 
    ScanAgent,
    VulnAgent,
    ExploitAgent,
    PostExploitAgent,
    ReportAgent,
    SystemAgent,
)
from .core import (
    get_phase_manager,
    get_shared_memory,
    get_context_manager,
    get_context_aggregator,
    analyze_phase_completion,
    PHASE_NAMES,
)
from .orchestration import (
    get_coordinator,
    AutonomousOrchestrator,
    get_orchestrator,
)
from .utils import (
    OutputParser,
    get_fallback_manager,
    get_plan_validator,
    get_tool_validator,
)

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
    
    # Agents
    "BaseAgent",
    "ReconAgent",
    "ScanAgent",
    "VulnAgent",
    "ExploitAgent",
    "PostExploitAgent",
    "ReportAgent",
    "SystemAgent",
    
    # Core
    "get_phase_manager",
    "get_shared_memory",
    "get_context_manager",
    "get_context_aggregator",
    "analyze_phase_completion",
    "PHASE_NAMES",
    
    # Orchestration
    "get_coordinator",
    "AutonomousOrchestrator",
    "get_orchestrator",
    
    # Utils
    "OutputParser",
    "get_fallback_manager",
    "get_plan_validator",
    "get_tool_validator",
]
