"""PostgreSQL vector store using pgvector extension.

This replaces ChromaDB with native PostgreSQL + pgvector for production-grade
semantic memory storage.
"""

import os
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Dict, Any, Optional
import json
from rag.embeddings import NemotronEmbeddings


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
        self.collection_name = collection_name
        self.embedding_dimension = embedding_dimension
        self.embeddings = NemotronEmbeddings()
        
        # PostgreSQL connection settings
        self.postgres_host = os.getenv("POSTGRES_HOST", "localhost")
        self.postgres_port = int(os.getenv("POSTGRES_PORT", "5432"))
        self.postgres_database = os.getenv("POSTGRES_DATABASE", "firestarter_pg")
        self.postgres_user = os.getenv("POSTGRES_USER", "firestarter_ad")
        self.postgres_password = os.getenv("POSTGRES_PASSWORD", "")
    
    def _get_connection(self):
        """Get PostgreSQL connection."""
        return psycopg2.connect(
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_database,
            user=self.postgres_user,
            password=self.postgres_password
        )
    
    def health_check(self) -> bool:
        """Check if PostgreSQL connection is healthy.
        
        Returns:
            True if connection is accessible, False otherwise
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            conn.close()
            return True
        except Exception:
            return False
    
    def add_documents(self, 
                     texts: List[str],
                     metadatas: Optional[List[Dict[str, Any]]] = None,
                     ids: Optional[List[str]] = None):
        """Add documents to vector store.
        
        Args:
            texts: List of texts to embed and store
            metadatas: List of metadata dicts (one per text)
            ids: List of document IDs (auto-generated if not provided)
        """
        if not texts:
            return
        
        # Generate embeddings
        embeddings = self.embeddings.embed_documents(texts)
        
        # Validate embeddings
        if not embeddings or len(embeddings) == 0:
            # Try fallback embedding model
            try:
                import ollama
                embeddings = []
                for text in texts:
                    try:
                        result = ollama.embeddings(
                            model="nomic-embed-text",
                            prompt=text
                        )
                        embedding = result.get('embedding', [])
                        if embedding:
                            embeddings.append(embedding)
                        else:
                            return
                    except Exception:
                        return
            except Exception:
                return
        
        # Filter out empty embeddings
        valid_embeddings = []
        valid_texts = []
        valid_metadatas = []
        valid_ids = []
        
        for i, emb in enumerate(embeddings):
            if emb and len(emb) > 0:
                valid_embeddings.append(emb)
                valid_texts.append(texts[i])
                valid_metadatas.append((metadatas or [{}] * len(texts))[i])
                if ids:
                    valid_ids.append(ids[i])
        
        if not valid_embeddings:
            return
        
        # Generate IDs if not provided
        if not valid_ids:
            valid_ids = [str(uuid.uuid4()) for _ in valid_texts]
        
        # Insert into PostgreSQL
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            for i, (text, embedding, metadata, doc_id) in enumerate(
                zip(valid_texts, valid_embeddings, valid_metadatas, valid_ids)
            ):
                # Extract conversation_id from metadata if present
                conversation_id = metadata.get('conversation_id')
                
                # Convert embedding to PostgreSQL vector format
                embedding_str = '[' + ','.join(map(str, embedding)) + ']'
                
                cursor.execute("""
                    INSERT INTO vector_embeddings 
                    (id, conversation_id, collection_name, text, embedding, metadata)
                    VALUES (%s, %s, %s, %s, %s::vector, %s::jsonb)
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
            cursor.close()
        except Exception as e:
            conn.rollback()
            import warnings
            warnings.warn(f"Failed to add documents to vector store: {str(e)}")
        finally:
            conn.close()
    
    def similarity_search(self, 
                         query: str,
                         k: int = 5,
                         filter: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Perform similarity search.
        
        Args:
            query: Search query text
            k: Number of results to return
            filter: Metadata filter dict (e.g., {"conversation_id": "...", "type": "..."})
            
        Returns:
            List of similar documents with metadata and distance scores
        """
        # Generate query embedding
        query_embedding = self.embeddings.embed_query(query)
        
        # Validate query embedding
        if not query_embedding or len(query_embedding) == 0:
            # Try fallback
            try:
                import ollama
                result = ollama.embeddings(
                    model="nomic-embed-text",
                    prompt=query
                )
                query_embedding = result.get('embedding', [])
            except Exception:
                return []
        
        if not query_embedding or len(query_embedding) == 0:
            return []
        
        # Build query with filters
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Convert embedding to PostgreSQL vector format
            embedding_str = '[' + ','.join(map(str, query_embedding)) + ']'
            
            # Build WHERE clause for filters
            where_clauses = ["collection_name = %s"]
            params = [self.collection_name]
            
            if filter:
                for key, value in filter.items():
                    if key == 'conversation_id':
                        where_clauses.append("conversation_id = %s")
                        params.append(value)
                    else:
                        # Use JSONB path query for metadata fields
                        where_clauses.append(f"metadata->>%s = %s")
                        params.extend([key, str(value)])
            
            where_sql = " AND ".join(where_clauses)
            
            # Perform cosine similarity search using pgvector
            query_sql = f"""
                SELECT 
                    id,
                    conversation_id,
                    text,
                    metadata,
                    1 - (embedding <=> %s::vector) as distance
                FROM vector_embeddings
                WHERE {where_sql}
                ORDER BY embedding <=> %s::vector
                LIMIT %s
            """
            
            params.extend([embedding_str, embedding_str, k])
            
            cursor.execute(query_sql, params)
            rows = cursor.fetchall()
            cursor.close()
            
            # Format results
            formatted_results = []
            for row in rows:
                formatted_results.append({
                    "document": row['text'],
                    "metadata": dict(row['metadata']) if row['metadata'] else {},
                    "distance": float(row['distance']) if row['distance'] is not None else None,
                    "id": str(row['id'])
                })
            
            return formatted_results
        except Exception as e:
            import warnings
            warnings.warn(f"Similarity search failed: {str(e)}")
            return []
        finally:
            conn.close()
    
    def delete_collection(self):
        """Delete all embeddings in this collection.
        
        Note: This deletes embeddings, not the collection itself (collections are logical).
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM vector_embeddings WHERE collection_name = %s",
                (self.collection_name,)
            )
            conn.commit()
            cursor.close()
        except Exception as e:
            conn.rollback()
            import warnings
            warnings.warn(f"Failed to delete collection: {str(e)}")
        finally:
            conn.close()
