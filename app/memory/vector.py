"""
Vector Memory Storage for SNODE.

Uses ChromaDB for semantic search over conversation history.
"""
import chromadb
from chromadb.config import Settings
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


class VectorMemory:
    """ChromaDB-based semantic memory."""
    
    def __init__(
        self,
        persist_dir: str = None,
        collection_name: str = "snode_memory"
    ):
        if persist_dir is None:
            persist_dir = str(Path.home() / ".snode" / "vector_db")
        
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"}
        )
        self._embedding_model = None
    
    def _get_embedding(self, text: str) -> List[float]:
        """Generate embedding using Ollama."""
        try:
            import requests
            
            response = requests.post(
                "http://localhost:11434/api/embeddings",
                json={
                    "model": "nomic-embed-text",  # or "all-minilm"
                    "prompt": text
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json().get("embedding", [])
            
            # Fallback to simple embedding
            return self._simple_embedding(text)
            
        except Exception as e:
            print(f"⚠️ Embedding error: {e}")
            return self._simple_embedding(text)
    
    def _simple_embedding(self, text: str) -> List[float]:
        """Simple fallback embedding (word frequency based)."""
        # Very simple - just for fallback
        import hashlib
        
        # Create deterministic pseudo-embedding
        words = text.lower().split()[:100]
        embedding = [0.0] * 384  # Match nomic-embed-text dimension
        
        for i, word in enumerate(words):
            hash_val = int(hashlib.md5(word.encode()).hexdigest()[:8], 16)
            idx = hash_val % 384
            embedding[idx] += 1.0 / (i + 1)
        
        # Normalize
        total = sum(embedding) or 1
        embedding = [x / total for x in embedding]
        
        return embedding
    
    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        domain: str = None,
        tools: List[str] = None,
        metadata: Dict = None
    ) -> str:
        """Add a message to vector memory."""
        doc_id = str(uuid.uuid4())
        
        # Build metadata
        meta = {
            "session_id": session_id,
            "role": role,
            "timestamp": datetime.now().isoformat(),
            "type": "conversation",
        }
        if domain:
            meta["domain"] = domain
        if tools:
            meta["tools"] = ",".join(tools)
        if metadata:
            meta.update(metadata)
        
        # Generate embedding
        embedding = self._get_embedding(content)
        
        # Add to collection
        self.collection.add(
            ids=[doc_id],
            embeddings=[embedding],
            documents=[content],
            metadatas=[meta]
        )
        
        # Also index in UnifiedRAG for cross-collection search
        if tools:
            try:
                from app.rag.unified_memory import get_unified_rag
                rag = get_unified_rag()
                rag.add_conversation_turn(
                    user_msg=content if role == "user" else "",
                    ai_msg=content if role == "assistant" else "",
                    tools_used=tools,
                    domain=domain,
                    session_id=session_id
                )
            except Exception:
                pass  # Don't fail if UnifiedRAG is unavailable
        
        return doc_id
    
    def add_tool_execution(
        self,
        session_id: str,
        tool_name: str,
        command: str,
        output_summary: str,
        domain: str = None,
        metadata: Dict = None
    ) -> str:
        """
        Add tool execution result to vector memory.
        
        Enables semantic search over past tool outputs for queries like:
        "what did we find on example.com" or "show me the nmap results"
        """
        doc_id = str(uuid.uuid4())
        
        # Create searchable document
        doc = f"Tool: {tool_name}. Command: {command}. Domain: {domain or 'unknown'}. Results: {output_summary[:1000]}"
        
        meta = {
            "session_id": session_id,
            "type": "tool_execution",
            "tool": tool_name,
            "command": command,
            "timestamp": datetime.now().isoformat(),
        }
        if domain:
            meta["domain"] = domain
        if metadata:
            meta.update(metadata)
        
        embedding = self._get_embedding(doc)
        
        self.collection.add(
            ids=[doc_id],
            embeddings=[embedding],
            documents=[doc],
            metadatas=[meta]
        )
        
        # Also index in UnifiedRAG
        try:
            from app.rag.unified_memory import get_unified_rag
            rag = get_unified_rag()
            rag.add_tool_execution(
                tool_name=tool_name,
                command=command,
                output_summary=output_summary,
                domain=domain,
                session_id=session_id
            )
        except Exception:
            pass
        
        return doc_id

    
    def search(
        self,
        query: str,
        n_results: int = 5,
        domain: str = None,
        role: str = None
    ) -> List[Dict]:
        """Search for similar messages."""
        # Build filter
        where = {}
        if domain:
            where["domain"] = domain
        if role:
            where["role"] = role
        
        # Generate query embedding
        query_embedding = self._get_embedding(query)
        
        # Search
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=where if where else None
        )
        
        # Format results
        formatted = []
        if results and results.get("documents"):
            for i, doc in enumerate(results["documents"][0]):
                formatted.append({
                    "content": doc,
                    "metadata": results["metadatas"][0][i] if results.get("metadatas") else {},
                    "distance": results["distances"][0][i] if results.get("distances") else 0
                })
        
        return formatted
    
    def search_similar_context(
        self,
        query: str,
        domain: str = None,
        n_results: int = 3
    ) -> str:
        """Search for similar past conversations and format as context."""
        results = self.search(query, n_results=n_results, domain=domain)
        
        if not results:
            return ""
        
        context_parts = []
        for r in results:
            meta = r.get("metadata", {})
            role = meta.get("role", "unknown")
            content = r.get("content", "")[:500]
            context_parts.append(f"{role}: {content}")
        
        return "\n".join(context_parts)
    
    def get_domain_knowledge(self, domain: str) -> List[Dict]:
        """Get all knowledge about a specific domain."""
        results = self.collection.get(
            where={"domain": domain},
            limit=50
        )
        
        formatted = []
        if results and results.get("documents"):
            for i, doc in enumerate(results["documents"]):
                formatted.append({
                    "content": doc,
                    "metadata": results["metadatas"][i] if results.get("metadatas") else {}
                })
        
        return formatted
    
    def count(self) -> int:
        """Get total count of stored memories."""
        return self.collection.count()
    
    def clear_old(self, days: int = 30):
        """Clear memories older than specified days."""
        # ChromaDB doesn't support timestamp comparison well
        # For now, just return 0 - cleanup handled by PostgreSQL
        # Vector DB will naturally stay small with document limit
        return 0


# Singleton
_vector_instance = None

def get_vector() -> VectorMemory:
    """Get or create vector memory instance."""
    global _vector_instance
    if _vector_instance is None:
        _vector_instance = VectorMemory()
    return _vector_instance
