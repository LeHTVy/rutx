"""
Memory Module for SNODE
=======================

Two-tier memory architecture:

1. SESSION MEMORY (volatile) - session.py
   - In-session context for LLM
   - Shared findings between agents
   - Attack facts and hypotheses
   - Cleared when session ends

2. CONVERSATION HISTORY (persistent) - postgres.py + vector.py
   - PostgreSQL: Exact conversation history, sessions, findings
   - Vector DB: Semantic search for relevant context
   - Persists across sessions for user to review

Usage:
    # Session memory (in-session, volatile)
    from app.memory import get_session_memory
    session = get_session_memory()
    session.set_target("example.com")
    session.add_fact("subdomain", "example.com", {"subdomain": "api.example.com"}, "subfinder")
    
    # Conversation history (persistent)
    from app.memory import get_memory_manager
    history = get_memory_manager()
    history.save_turn(user_msg, assistant_msg, tools_used, context)
"""

# Session Memory (volatile, in-session)
from .session import (
    SessionMemory,
    AgentContext,
    Fact,
    Hypothesis,
    get_session_memory,
    reset_session_memory,
    get_shared_memory,      # Alias for backward compat
    get_attack_memory,      # Alias for backward compat
)

# Conversation History (persistent)
from .postgres import PostgresMemory, get_postgres
from .vector import VectorMemory, get_vector
from .manager import MemoryManager, get_memory_manager

__all__ = [
    # Session Memory
    "SessionMemory",
    "AgentContext", 
    "Fact",
    "Hypothesis",
    "get_session_memory",
    "reset_session_memory",
    "get_shared_memory",
    "get_attack_memory",
    
    # Conversation History
    "PostgresMemory",
    "get_postgres",
    "VectorMemory",
    "get_vector",
    "MemoryManager",
    "get_memory_manager",
]
