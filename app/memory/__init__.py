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
try:
    from .postgres import PostgresMemory, get_postgres
except ImportError:
    # Postgres not available - create dummy classes
    class PostgresMemory:
        def __init__(self, *args, **kwargs):
            raise ImportError("psycopg2 not installed. Install with: pip install psycopg2-binary")
    
    def get_postgres():
        raise ImportError("psycopg2 not installed")

try:
    from .vector import VectorMemory, get_vector
except ImportError:
    class VectorMemory:
        def __init__(self, *args, **kwargs):
            raise ImportError("Vector memory dependencies not installed")
    
    def get_vector():
        raise ImportError("Vector memory not available")

# ============== NEW PRODUCTION STORES (firestarter pattern) ==============

# pgvector store (replaces ChromaDB for production)
try:
    from .pgvector_store import PgVectorStore, get_pgvector_store
except ImportError:
    PgVectorStore = None
    def get_pgvector_store(*args, **kwargs):
        raise ImportError("pgvector not available: pip install psycopg2-binary pgvector")

# Redis buffer (short-term memory)
try:
    from .redis_buffer import RedisBuffer, get_redis_buffer
except ImportError:
    RedisBuffer = None
    def get_redis_buffer(*args, **kwargs):
        raise ImportError("Redis not available: pip install redis")

# Conversation store (PostgreSQL persistence)
try:
    from .conversation_store import ConversationStore, get_conversation_store
except ImportError:
    ConversationStore = None
    def get_conversation_store(*args, **kwargs):
        raise ImportError("ConversationStore not available: pip install psycopg2-binary")

# ==========================================================================

try:
    from .manager import MemoryManager, get_memory_manager
except ImportError:
    class MemoryManager:
        def __init__(self, *args, **kwargs):
            raise ImportError("Memory manager dependencies not installed")
    
    def get_memory_manager():
        raise ImportError("Memory manager not available")

# Memory Areas
from .areas import MemoryArea, classify_memory_area

# Memory Consolidation
try:
    from .consolidation import (
        MemoryConsolidator,
        ConsolidationConfig,
        ConsolidationAction,
        get_memory_consolidator,
    )
except ImportError:
    # Consolidation optional
    MemoryConsolidator = None
    ConsolidationConfig = None
    ConsolidationAction = None
    def get_memory_consolidator(*args, **kwargs):
        raise ImportError("Memory consolidation not available")

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
