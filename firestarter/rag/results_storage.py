"""Tool results storage with namespace isolation."""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from rag.pgvector_store import PgVectorStore
from memory.namespace_manager import NamespaceManager
import uuid


class ToolResultsStorage:
    """Storage for tool execution results with namespace isolation."""
    
    def __init__(self, collection_name: str = "tool_results"):
        """Initialize tool results storage.
        
        Args:
            collection_name: Collection name (base name, will be namespaced per conversation)
        """
        self.base_collection_name = collection_name
        self.namespace_manager = NamespaceManager()
        # Default vectorstore (for backward compatibility)
        self.vectorstore = PgVectorStore(collection_name=collection_name)
    
    def _get_collection_for_conversation(self, conversation_id: Optional[str] = None) -> PgVectorStore:
        """Get vectorstore for specific conversation (namespace isolation).
        
        Args:
            conversation_id: Conversation UUID (None for default/legacy)
            
        Returns:
            PgVectorStore instance for this conversation
        """
        if conversation_id:
            # Use conversation-specific collection for namespace isolation
            namespace = self.namespace_manager.get_vector_namespace(conversation_id)
            # Append "_results" to namespace for tool results
            results_namespace = f"{namespace}_results"
            return PgVectorStore(collection_name=results_namespace)
        else:
            # Legacy: use default collection
            return self.vectorstore
    
    def store_result(self,
                    tool_name: str,
                    parameters: Dict[str, Any],
                    results: Any,
                    agent: Optional[str] = None,
                    session_id: Optional[str] = None,
                    conversation_id: Optional[str] = None,
                    execution_id: Optional[str] = None) -> str:
        """Store tool execution result.
        
        Args:
            tool_name: Tool name
            parameters: Tool parameters
            results: Execution results
            agent: Agent name
            session_id: Session identifier (legacy)
            conversation_id: Conversation identifier (preferred)
            execution_id: Execution ID
            
        Returns:
            Stored document ID
        """
        # Prefer conversation_id over session_id
        conv_id = conversation_id or session_id
        
        doc_id = execution_id or str(uuid.uuid4())
        
        # Format result text
        result_text = json.dumps(results, indent=2) if isinstance(results, dict) else str(results)
        
        # Create document text
        doc_text = f"Tool: {tool_name}\nParameters: {json.dumps(parameters)}\nResults: {result_text}"
        
        # Create metadata
        metadata = {
            "tool_name": tool_name,
            "timestamp": datetime.utcnow().isoformat(),
            "agent": agent or "",
            "type": "tool_result",
            "execution_id": doc_id
        }
        
        # Add both for migration compatibility
        if conversation_id:
            metadata["conversation_id"] = conversation_id
        if session_id:
            metadata["session_id"] = session_id
        
        # Get conversation-specific vectorstore
        vectorstore = self._get_collection_for_conversation(conv_id)
        
        # Store in vector DB
        vectorstore.add_documents(
            texts=[doc_text],
            metadatas=[metadata],
            ids=[doc_id]
        )
        
        return doc_id
    
    def retrieve_results(self,
                        query: str,
                        k: int = 5,
                        tool_name: Optional[str] = None,
                        agent: Optional[str] = None,
                        session_id: Optional[str] = None,
                        conversation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve tool results with namespace isolation.
        
        Args:
            query: Search query
            k: Number of results
            tool_name: Filter by tool name
            agent: Filter by agent
            session_id: Filter by session ID (legacy)
            conversation_id: Filter by conversation ID (preferred)
            
        Returns:
            Retrieved results
        """
        # Prefer conversation_id over session_id
        conv_id = conversation_id or session_id
        
        # Get conversation-specific vectorstore
        vectorstore = self._get_collection_for_conversation(conv_id)
        
        filter_dict = {"type": "tool_result"}
        
        if tool_name:
            filter_dict["tool_name"] = tool_name
        if agent:
            filter_dict["agent"] = agent
        if conversation_id:
            filter_dict["conversation_id"] = conversation_id
        elif session_id:
            filter_dict["session_id"] = session_id
        
        return vectorstore.similarity_search(query, k=k, filter=filter_dict)
