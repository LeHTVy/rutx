"""Embedding wrapper for Nemotron."""

from models.nemotron_agent import NemotronAgent
from typing import List


class NemotronEmbeddings:
    """Wrapper for Nemotron embeddings."""
    
    def __init__(self):
        """Initialize embeddings."""
        self.agent = NemotronAgent()
    
    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """Embed documents.
        
        Args:
            texts: List of texts to embed
            
        Returns:
            List of embeddings
        """
        result = self.agent.generate_embeddings(texts)
        if result.get("success"):
            return result.get("embeddings", [])
        return []
    
    def embed_query(self, text: str) -> List[float]:
        """Embed query.
        
        Args:
            text: Query text
            
        Returns:
            Embedding vector
        """
        result = self.agent.embed_text(text)
        if result.get("success"):
            return result.get("embedding", [])
        return []
