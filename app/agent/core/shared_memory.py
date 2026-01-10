"""
SNODE Shared Agent Memory
=========================

⚠️ DEPRECATED: This module has been moved to app.memory.session
Please use:
    from app.memory import get_shared_memory, AgentContext

This file is kept for backward compatibility only.
"""
import warnings
warnings.warn(
    "app.agent.core.shared_memory is deprecated. Use app.memory instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export from new location for backward compat
from app.memory.session import (
    AgentContext as AgentMemory,
    get_shared_memory,
    reset_session_memory as reset_shared_memory,
)

__all__ = ["AgentMemory", "get_shared_memory", "reset_shared_memory"]
