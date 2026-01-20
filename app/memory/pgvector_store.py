"""
PostgreSQL vector store using pgvector extension.

This replaces ChromaDB with native PostgreSQL + pgvector for production-grade
semantic memory storage.
"""

import os
import uuid
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False


class NomicEmbeddings:
    """Embedding generator using Ollama's nomic-embed-text model."""
    
    def __init__(self, model: str = "nomic-embed-text"):
        self.model = model
        self._ollama = None
    
    def _get_ollama(self):
        """Lazy load ollama client."""
        if self._ollama is None:
            try:
                import ollama
                self._ollama = ollama
            except ImportError:
                raise ImportError("ollama package required for embeddings")
        return self._ollama
    
    def embed(self, text: str) -> List[float]:
        """Generate embedding for text."""
        ollama = self._get_ollama()
        response = ollama.embeddings(model=self.model, prompt=text)
        return response.get("embedding", [])
    
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts."""
        return [self.embed(text) for text in texts]


class PgVectorStore:
    """PostgreSQL vector store using pgvector extension.
    
    This implementation uses PostgreSQL directly with pgvector extension,
    eliminating the need for Chroma Server.
    """
    
    def __init__(self, 
                 collection_name: str = "default",
                 embedding_dimension: int = 768):
        """Initialize PostgreSQL vector store.
        
        Args:
            collection_name: Collection/namespace name for organizing embeddings
            embedding_dimension: Dimension of embedding vectors (default: 768 for nomic-embed-text)
        """
        if not PSYCOPG2_AVAILABLE:
            raise ImportError("psycopg2-binary required: pip install psycopg2-binary")
        
        self.collection_name = collection_name
        self.embedding_dimension = embedding_dimension
        self.embeddings = NomicEmbeddings()
        
        # Database connection parameters from environment
        self.db_config = {
            "host": os.getenv("POSTGRES_HOST", "localhost"),
            "port": int(os.getenv("POSTGRES_PORT", 5432)),
            "database": os.getenv("POSTGRES_DATABASE", "snode_db"),
            "user": os.getenv("POSTGRES_USER", "snode"),
            "password": os.getenv("POSTGRES_PASSWORD", ""),
        }
    
    def _get_connection(self):
        """Get PostgreSQL connection."""
        return psycopg2.connect(**self.db_config)
    
    def health_check(self) -> bool:
        """Check if PostgreSQL connection is healthy.
        
        Returns:
            True if connection is accessible, False otherwise
        """
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    return True
        except Exception:
            return False
    
    def add_documents(self, 
                     texts: List[str],
                     metadatas: Optional[List[Dict[str, Any]]] = None,
                     ids: Optional[List[str]] = None,
                     conversation_id: Optional[str] = None) -> List[str]:
        """Add documents to vector store.
        
        Args:
            texts: List of texts to embed and store
            metadatas: List of metadata dicts (one per text)
            ids: List of document IDs (auto-generated if not provided)
            conversation_id: Optional conversation UUID to associate with
            
        Returns:
            List of document IDs
        """
        if not texts:
            return []
        
        # Generate IDs if not provided
        if ids is None:
            ids = [str(uuid.uuid4()) for _ in texts]
        
        # Ensure metadatas list matches texts
        if metadatas is None:
            metadatas = [{} for _ in texts]
        
        # Generate embeddings
        embeddings = self.embeddings.embed_batch(texts)
        
        # Insert into database
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                for doc_id, text, embedding, metadata in zip(ids, texts, embeddings, metadatas):
                    # Format embedding as PostgreSQL vector
                    embedding_str = f"[{','.join(map(str, embedding))}]"
                    
                    cur.execute("""
                        INSERT INTO vector_embeddings 
                        (id, conversation_id, collection_name, text, embedding, metadata)
                        VALUES (%s, %s, %s, %s, %s::vector, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            text = EXCLUDED.text,
                            embedding = EXCLUDED.embedding,
                            metadata = EXCLUDED.metadata
                    """, (
                        doc_id,
                        conversation_id,
                        self.collection_name,
                        text,
                        embedding_str,
                        json.dumps(metadata)
                    ))
                
                conn.commit()
        
        return ids
    
    def similarity_search(self, 
                         query: str,
                         k: int = 5,
                         filter: Optional[Dict[str, Any]] = None,
                         conversation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Perform similarity search.
        
        Args:
            query: Search query text
            k: Number of results to return
            filter: Metadata filter dict
            conversation_id: Optional conversation UUID to filter by
            
        Returns:
            List of similar documents with metadata and distance scores
        """
        # Generate query embedding
        query_embedding = self.embeddings.embed(query)
        embedding_str = f"[{','.join(map(str, query_embedding))}]"
        
        # Build query with filters
        where_clauses = ["collection_name = %s"]
        params = [self.collection_name]
        
        if conversation_id:
            where_clauses.append("conversation_id = %s")
            params.append(conversation_id)
        
        if filter:
            for key, value in filter.items():
                where_clauses.append(f"metadata->>%s = %s")
                params.extend([key, str(value)])
        
        where_sql = " AND ".join(where_clauses)
        
        # Execute similarity search using cosine distance
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(f"""
                    SELECT 
                        id,
                        text,
                        metadata,
                        1 - (embedding <=> %s::vector) as similarity
                    FROM vector_embeddings
                    WHERE {where_sql}
                    ORDER BY embedding <=> %s::vector
                    LIMIT %s
                """, [embedding_str] + params + [embedding_str, k])
                
                results = cur.fetchall()
        
        # Format results
        return [
            {
                "id": str(row["id"]),
                "text": row["text"],
                "metadata": row["metadata"] if isinstance(row["metadata"], dict) else json.loads(row["metadata"] or "{}"),
                "similarity": float(row["similarity"])
            }
            for row in results
        ]
    
    def delete_by_ids(self, ids: List[str]) -> int:
        """Delete documents by IDs.
        
        Args:
            ids: List of document IDs to delete
            
        Returns:
            Number of documents deleted
        """
        if not ids:
            return 0
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM vector_embeddings
                    WHERE id = ANY(%s) AND collection_name = %s
                """, (ids, self.collection_name))
                deleted = cur.rowcount
                conn.commit()
        
        return deleted
    
    def delete_collection(self) -> int:
        """Delete all embeddings in this collection.
        
        Returns:
            Number of documents deleted
        """
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM vector_embeddings
                    WHERE collection_name = %s
                """, (self.collection_name,))
                deleted = cur.rowcount
                conn.commit()
        
        return deleted
    
    def count(self) -> int:
        """Get count of documents in collection.
        
        Returns:
            Number of documents
        """
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM vector_embeddings
                    WHERE collection_name = %s
                """, (self.collection_name,))
                return cur.fetchone()[0]


# Singleton instance
_pgvector_instance: Optional[PgVectorStore] = None


def get_pgvector_store(collection_name: str = "snode_memory") -> PgVectorStore:
    """Get or create pgvector store instance.
    
    Args:
        collection_name: Collection name for organizing embeddings
        
    Returns:
        PgVectorStore instance
    """
    global _pgvector_instance
    if _pgvector_instance is None or _pgvector_instance.collection_name != collection_name:
        _pgvector_instance = PgVectorStore(collection_name=collection_name)
    return _pgvector_instance
