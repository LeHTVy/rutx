"""
DuckDuckGo HTML search client.

Uses `https://html.duckduckgo.com/html/` which does not require an API key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str = ""


class DuckDuckGoHtmlClient:
    """Simple DuckDuckGo HTML search client (no API key)."""

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            }
        )

    def search(self, query: str, num_results: int = 10, timeout: int = 15) -> Dict[str, Any]:
        """
        Perform a DuckDuckGo HTML search.

        Returns a dict:
        {
          "success": bool,
          "query": str,
          "results": [{"title":..., "url":..., "snippet":...}, ...],
          "error": optional str
        }
        """
        if not query or not isinstance(query, str):
            return {"success": False, "query": str(query), "results": [], "error": "Empty query"}

        url = "https://html.duckduckgo.com/html/"
        try:
            resp = self.session.post(url, data={"q": query}, timeout=timeout)
            if resp.status_code != 200:
                return {
                    "success": False,
                    "query": query,
                    "results": [],
                    "error": f"HTTP {resp.status_code}",
                }

            results = self._parse_html(resp.text, limit=num_results)
            return {"success": True, "query": query, "results": results}
        except Exception as e:
            return {"success": False, "query": query, "results": [], "error": str(e)}

    def _parse_html(self, html: str, limit: int) -> List[Dict[str, str]]:
        """
        Parse DuckDuckGo HTML results.

        Uses BeautifulSoup when available; otherwise returns an empty list.
        """
        try:
            from bs4 import BeautifulSoup  # type: ignore
        except Exception:
            return []

        soup = BeautifulSoup(html, "html.parser")
        parsed: List[Dict[str, str]] = []

        for result in soup.select(".result__body")[: max(limit, 0)]:
            link = result.select_one(".result__a")
            snippet = result.select_one(".result__snippet")

            title = link.get_text(strip=True)[:200] if link else ""
            href = link.get("href", "") if link else ""
            text = snippet.get_text(strip=True)[:400] if snippet else ""

            if href and title:
                parsed.append({"title": title, "url": href, "snippet": text})

        return parsed

