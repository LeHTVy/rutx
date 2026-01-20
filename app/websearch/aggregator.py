"""
Web search aggregator (firestarter-inspired, rutx-native).

This module provides a stable interface for web search. Today it uses a
DuckDuckGo HTML client (no API key). It is intentionally minimal so that
callers (TargetVerification, web research, etc.) don't re-implement ad-hoc
search logic.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.websearch.duckduckgo_client import DuckDuckGoHtmlClient


class SearchAggregator:
    """Aggregator for web search providers (currently DuckDuckGo HTML)."""

    def __init__(self):
        self._ddg = DuckDuckGoHtmlClient()
        self._ranker = None
        self._verifier = None
    
    @property
    def ranker(self):
        """Lazy load neural ranker."""
        if self._ranker is None:
            try:
                from app.websearch.ranker import get_neural_ranker
                self._ranker = get_neural_ranker()
            except ImportError:
                pass
        return self._ranker
    
    @property
    def verifier(self):
        """Lazy load result verifier."""
        if self._verifier is None:
            try:
                from app.websearch.ranker import get_result_verifier
                self._verifier = get_result_verifier()
            except ImportError:
                pass
        return self._verifier

    def search(
        self,
        query: str,
        num_results: int = 5,
        timeout: int = 15,
        rank_results: bool = False,
        verify_results: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute a web search and return normalized results.
        
        Args:
            query: Search query string
            num_results: Number of results to return
            timeout: Request timeout in seconds
            rank_results: Whether to apply neural ranking
            verify_results: Whether to verify result credibility

        Return shape:
        {
          "success": bool,
          "query": str,
          "results": [{"title":..., "url":..., "snippet":...}, ...],
          "search_source": "duckduckgo_html",
          "error": optional str
        }
        """
        # Request more results for ranking/filtering
        fetch_count = num_results * 2 if rank_results else num_results
        
        res = self._ddg.search(query=query, num_results=max(fetch_count, 1), timeout=timeout)
        if not res.get("success"):
            return {
                "success": False,
                "query": res.get("query", query),
                "results": [],
                "search_source": "duckduckgo_html",
                "error": res.get("error", "search_failed"),
            }

        results: List[Dict[str, str]] = res.get("results", []) or []
        # Defensive normalization
        normalized: List[Dict[str, str]] = []
        for r in results:
            title = str(r.get("title", "")).strip()
            url = str(r.get("url", "")).strip()
            snippet = str(r.get("snippet", "")).strip()
            if title and url:
                normalized.append({"title": title, "url": url, "snippet": snippet, "link": url})
        
        # Apply neural ranking if requested
        if rank_results and self.ranker and normalized:
            try:
                normalized = self.ranker.rank_results(query, normalized, top_k=num_results)
            except Exception:
                pass  # Fall back to original order
        
        # Apply verification if requested
        if verify_results and self.verifier and normalized:
            try:
                verification = self.verifier.verify_results(normalized)
                for i, result in enumerate(normalized):
                    if i < len(verification.get("verified_results", [])):
                        verified = verification["verified_results"][i]
                        result["confidence"] = verified.get("confidence", 0.5)
                        result["verification_status"] = verified.get("verification_status", "unverified")
            except Exception:
                pass  # Continue without verification
        
        return {
            "success": True,
            "query": query,
            "results": normalized[:num_results],
            "search_source": "duckduckgo_html",
        }


_aggregator: Optional[SearchAggregator] = None


def get_search_aggregator() -> SearchAggregator:
    """Get a process-wide SearchAggregator instance."""
    global _aggregator
    if _aggregator is None:
        _aggregator = SearchAggregator()
    return _aggregator

