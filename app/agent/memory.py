"""
Attack Memory - Structured Fact Memory for Pentest Agent
=========================================================

⚠️ DEPRECATED: This module has been moved to app.memory.session
Please use:
    from app.memory import get_session_memory, Fact, Hypothesis

This file is kept for backward compatibility only.
"""
import warnings
warnings.warn(
    "app.agent.memory is deprecated. Use app.memory instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export from new location for backward compat
from app.memory.session import (
    SessionMemory as AttackMemory,
    Fact,
    Hypothesis,
    get_session_memory as get_attack_memory,
)

# Keep the old exports working
__all__ = ["AttackMemory", "Fact", "Hypothesis", "get_attack_memory"]

# Note: Deprecated code (900+ lines) has been removed.
# All functionality has been moved to app.memory.session
