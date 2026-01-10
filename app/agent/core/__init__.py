"""
Core Agent Infrastructure
=========================

Core components for agent operation:
- PhaseManager: LLM-driven phase evaluation
- PhaseAnalyzer: Phase completion analysis
- ContextManager: Session context handling
- ContextAggregator: Multi-source context

NOTE: Memory has been moved to app.memory module.
Use `from app.memory import get_shared_memory, get_session_memory` instead.
"""
from .phase_manager import (
    PhaseManager,
    get_phase_manager,
    get_tool_phase,
    PHASE_NAMES,
)
from .phase_analyzer import (
    PhaseAnalyzer,
    get_phase_analyzer,
    analyze_phase_completion,
    PhaseAnalysisResult,
)
from .context_manager import (
    get_context_manager,
    SessionContext,
)
from .context_aggregator import (
    get_context_aggregator,
    AggregatedContext,
)

# Re-export from app.memory for backward compatibility
from app.memory import (
    AgentContext as AgentMemory,  # Renamed for clarity
    get_shared_memory,
    reset_session_memory as reset_shared_memory,
)

__all__ = [
    # Phase Management
    "PhaseManager",
    "get_phase_manager",
    "get_tool_phase",
    "PHASE_NAMES",
    
    # Phase Analysis
    "PhaseAnalyzer",
    "get_phase_analyzer",
    "analyze_phase_completion",
    "PhaseAnalysisResult",
    
    # Context
    "get_context_manager",
    "SessionContext",
    "get_context_aggregator",
    "AggregatedContext",
    
    # Memory (backward compat - prefer app.memory)
    "AgentMemory",
    "get_shared_memory",
    "reset_shared_memory",
]
