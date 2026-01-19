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

    def search(
        self,
        query: str,
        num_results: int = 5,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        """
        Execute a web search and return normalized results.

        Return shape:
        {
          "success": bool,
          "query": str,
          "results": [{"title":..., "url":..., "snippet":...}, ...],
          "search_source": "duckduckgo_html",
          "error": optional str
        }
        """
        res = self._ddg.search(query=query, num_results=max(num_results, 1), timeout=timeout)
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
        for r in results[:num_results]:
            title = str(r.get("title", "")).strip()
            url = str(r.get("url", "")).strip()
            snippet = str(r.get("snippet", "")).strip()
            if title and url:
                normalized.append({"title": title, "url": url, "snippet": snippet})

        return {
            "success": True,
            "query": query,
            "results": normalized,
            "search_source": "duckduckgo_html",
        }


_aggregator: Optional[SearchAggregator] = None


def get_search_aggregator() -> SearchAggregator:
    """Get a process-wide SearchAggregator instance."""
    global _aggregator
    if _aggregator is None:
        _aggregator = SearchAggregator()
    return _aggregator

