"""Neural ranking for search results using embeddings."""

from typing import Dict, Any, List
import numpy as np
from app.llm.client import OllamaClient


class NeuralRanker:
    """Neural ranker using embeddings for semantic similarity.
    
    Re-ranks search results based on query relevance using
    embedding cosine similarity.
    """
    
    def __init__(self):
        """Initialize neural ranker."""
        self._client = None
    
    @property
    def client(self) -> OllamaClient:
        """Lazy load Ollama client."""
        if self._client is None:
            self._client = OllamaClient()
        return self._client
    
    def _get_embedding(self, text: str) -> List[float]:
        """Generate embedding for text using Ollama."""
        try:
            import ollama
            response = ollama.embeddings(
                model="nomic-embed-text",
                prompt=text[:2000]  # Limit text length
            )
            return response.get("embedding", [])
        except Exception:
            return []
    
    def rank_results(self, 
                    query: str,
                    results: List[Dict[str, Any]],
                    top_k: int = 10) -> List[Dict[str, Any]]:
        """Rank search results by semantic similarity.
        
        Args:
            query: Search query
            results: List of search results with 'title' and 'snippet' keys
            top_k: Number of top results to return
            
        Returns:
            Ranked results with similarity scores
        """
        if not results:
            return []
        
        try:
            # Generate query embedding
            query_embedding = self._get_embedding(query)
            if not query_embedding:
                return results[:top_k]
            
            query_embedding = np.array(query_embedding)
            
            # Generate embeddings for results
            result_embeddings = []
            valid_results = []
            
            for result in results:
                # Combine title and snippet for embedding
                text = f"{result.get('title', '')} {result.get('snippet', '')}"
                embedding = self._get_embedding(text)
                
                if embedding:
                    result_embeddings.append(np.array(embedding))
                    valid_results.append(result)
            
            if not result_embeddings:
                return results[:top_k]
            
            # Calculate cosine similarity
            similarities = []
            for emb in result_embeddings:
                norm_product = np.linalg.norm(query_embedding) * np.linalg.norm(emb)
                if norm_product > 0:
                    similarity = np.dot(query_embedding, emb) / norm_product
                else:
                    similarity = 0.0
                similarities.append(similarity)
            
            # Sort by similarity
            ranked_indices = np.argsort(similarities)[::-1]
            ranked_results = [valid_results[i] for i in ranked_indices[:top_k]]
            
            # Add similarity scores
            for i, result in enumerate(ranked_results):
                result["similarity_score"] = float(similarities[ranked_indices[i]])
            
            return ranked_results
            
        except Exception as e:
            # Fallback to original order
            return results[:top_k]


class ResultVerifier:
    """Verify and score search result credibility."""
    
    def __init__(self):
        """Initialize result verifier."""
        # Known trusted domains for security content
        self.trusted_domains = {
            "github.com", "exploit-db.com", "cve.mitre.org", "nvd.nist.gov",
            "owasp.org", "hackerone.com", "bugcrowd.com", "portswigger.net",
            "pentesterlab.com", "offensive-security.com", "rapid7.com",
            "tenable.com", "qualys.com", "cvedetails.com", "securityfocus.com"
        }
    
    def verify_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Verify search results and assign confidence scores.
        
        Args:
            results: List of search results
            
        Returns:
            Dict with verified_results and summary
        """
        verified_results = []
        
        for result in results:
            url = result.get("link", "")
            domain = self._extract_domain(url)
            
            # Calculate confidence based on multiple factors
            confidence = 0.5  # Base confidence
            verification_status = "unverified"
            
            # Trusted domain bonus
            if domain in self.trusted_domains:
                confidence += 0.3
                verification_status = "trusted_source"
            
            # Has full content bonus
            if result.get("full_content"):
                confidence += 0.1
            
            # Has publish date bonus
            if result.get("publish_date"):
                confidence += 0.05
            
            # Existing similarity score bonus
            if result.get("similarity_score", 0) > 0.7:
                confidence += 0.1
            
            confidence = min(confidence, 1.0)
            
            verified_results.append({
                "confidence": confidence,
                "verification_status": verification_status,
                "domain": domain,
            })
        
        return {
            "verified_results": verified_results,
            "num_trusted": sum(1 for v in verified_results if v["verification_status"] == "trusted_source"),
            "avg_confidence": sum(v["confidence"] for v in verified_results) / len(verified_results) if verified_results else 0
        }
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove www. prefix
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return ""


# Module-level instances
_neural_ranker = None
_result_verifier = None


def get_neural_ranker() -> NeuralRanker:
    """Get or create neural ranker instance."""
    global _neural_ranker
    if _neural_ranker is None:
        _neural_ranker = NeuralRanker()
    return _neural_ranker


def get_result_verifier() -> ResultVerifier:
    """Get or create result verifier instance."""
    global _result_verifier
    if _result_verifier is None:
        _result_verifier = ResultVerifier()
    return _result_verifier
