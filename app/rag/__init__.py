"""
RAG Module - Retrieval-Augmented Generation
============================================

ChromaDB-based tool retrieval for intelligent tool selection.
Includes unified memory system for conversations and CVE integration.
"""
from .tool_index import ToolIndex
from .unified_memory import UnifiedRAG, get_unified_rag
from .tool_metadata import TOOL_METADATA, get_all_tools, get_tool_commands

__all__ = [
    "ToolIndex",
    "UnifiedRAG",
    "get_unified_rag",
    "TOOL_METADATA",
    "get_all_tools",
    "get_tool_commands",
]
