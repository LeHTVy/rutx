"""
CVE Web Lookup - Fetch Latest CVEs from Internet
==================================================

Fetches CVE information from web sources for CVEs not in local database.
Useful for CVEs from 2026+ that haven't been indexed yet.
"""

import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.tools.custom.web_research import web_search, search_and_format
from app.llm.client import OllamaClient
from app.ui import get_logger

logger = get_logger()


class CVEWebLookup:
    """
    Lookup CVE information from web sources.
    
    Searches:
    - CVE.org official database
    - Security advisories
    - Vulnerability databases
    """
    
    def __init__(self):
        self.llm = OllamaClient()
    
    def lookup_cve_web(self, cve_id: str) -> Dict[str, Any]:
        """
        Lookup CVE from web sources.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2026-1234")
        
        Returns:
            Dict with CVE details or error
        """
        if not cve_id or not cve_id.startswith("CVE-"):
            return {
                "success": False,
                "error": "Invalid CVE ID format"
            }
        
        try:
            # Search for CVE on web
            search_query = f"{cve_id} vulnerability"
            logger.info(f"Searching web for {cve_id}...")
            
            research = web_search(search_query, max_results=5)
            
            if not research or not research.get("success"):
                return {
                    "success": False,
                    "error": "No web results found"
                }
            
            # Extract CVE information from search results
            snippets = research.get("snippets", [])
            sources = research.get("sources", [])
            
            # Combine all snippets
            combined_text = "\n\n".join([
                f"Source: {src.get('title', 'N/A')}\n{snippet}"
                for snippet, src in zip(snippets, sources)
            ])
            
            # Use LLM to extract structured CVE information
            extraction_prompt = f"""Extract CVE information from the following web search results for {cve_id}:

{combined_text}

Extract and return JSON with:
{{
    "cve_id": "{cve_id}",
    "title": "CVE title or summary",
    "description": "Detailed description",
    "severity": "critical|high|medium|low|unknown",
    "cvss_score": 0.0,
    "products": ["product1", "product2"],
    "vendors": ["vendor1", "vendor2"],
    "date_published": "YYYY-MM-DD",
    "affected_versions": ["version1", "version2"],
    "references": ["url1", "url2"]
}}

Return ONLY the JSON object."""

            response = self.llm.generate(extraction_prompt, timeout=30, stream=False, show_content=False).strip()
            
            # Parse JSON response
            try:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    cve_data = json.loads(json_match.group(), strict=False)
                    
                    return {
                        "success": True,
                        "cve": cve_data,
                        "source": "web"
                    }
            except Exception as e:
                # Fallback: return raw search results
                return {
                    "success": True,
                    "cve": {
                        "cve_id": cve_id,
                        "title": sources[0].get("title", "") if sources else "",
                        "description": "\n\n".join(snippets[:3]),
                        "severity": "unknown",
                        "cvss_score": 0.0,
                        "products": [],
                        "vendors": [],
                        "date_published": "",
                        "references": [src.get("url", "") for src in sources[:3]]
                    },
                    "source": "web",
                    "warning": f"LLM extraction failed: {e}, using raw results"
                }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Web lookup error: {e}"
            }
    
    def search_recent_cves(self, technology: str, year: int = None) -> Dict[str, Any]:
        """
        Search for recent CVEs related to a technology.
        
        Args:
            technology: Technology name (e.g., "MongoDB", "Apache")
            year: Optional year filter (default: current year)
        
        Returns:
            Dict with list of recent CVEs
        """
        if year is None:
            year = datetime.now().year
        
        try:
            # Search for recent CVEs
            search_query = f"{technology} CVE {year} vulnerability"
            logger.info(f"Searching for recent {technology} CVEs from {year}...")
            
            research = web_search(search_query, max_results=10)
            
            if not research or not research.get("success"):
                return {
                    "success": False,
                    "error": "No web results found"
                }
            
            # Extract CVE IDs from results
            snippets = research.get("snippets", [])
            sources = research.get("sources", [])
            
            # Find CVE IDs in text
            cve_ids = set()
            cve_pattern = r'CVE-\d{4}-\d{4,}'
            for snippet in snippets:
                matches = re.findall(cve_pattern, snippet, re.IGNORECASE)
                cve_ids.update(matches)
            
            # Lookup each CVE
            cves = []
            for cve_id in list(cve_ids)[:5]:  # Limit to 5 CVEs
                cve_info = self.lookup_cve_web(cve_id)
                if cve_info.get("success"):
                    cves.append(cve_info.get("cve"))
            
            return {
                "success": True,
                "technology": technology,
                "year": year,
                "cves": cves,
                "total_found": len(cves)
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Search error: {e}"
            }


# Singleton instance
_cve_web_lookup: Optional[CVEWebLookup] = None


def get_cve_web_lookup() -> CVEWebLookup:
    """Get singleton CVEWebLookup instance."""
    global _cve_web_lookup
    if _cve_web_lookup is None:
        _cve_web_lookup = CVEWebLookup()
    return _cve_web_lookup


def lookup_cve_with_fallback(cve_id: str) -> Dict[str, Any]:
    """
    Lookup CVE with fallback to web if not in local database.
    
    First tries local CVE database, then falls back to web lookup.
    """
    from app.rag.cve_rag import lookup_cve
    
    # Try local database first
    local_result = lookup_cve(cve_id)
    
    if local_result.get("success"):
        return {
            **local_result,
            "source": "local"
        }
    
    # Fallback to web lookup
    web_lookup = get_cve_web_lookup()
    web_result = web_lookup.lookup_cve_web(cve_id)
    
    if web_result.get("success"):
        return web_result
    
    # Both failed
    return {
        "success": False,
        "error": f"CVE {cve_id} not found in local database or web sources",
        "local_error": local_result.get("error"),
        "web_error": web_result.get("error")
    }


def search_cves_with_fallback(query: str, technology: str = None, year: int = None) -> Dict[str, Any]:
    """
    Search CVEs with fallback to web for recent CVEs.
    
    First searches local database, then supplements with web results for recent CVEs.
    """
    from app.rag.cve_rag import search_cves
    
    # Search local database
    local_results = search_cves(query, n_results=10)
    
    # If query mentions recent year (2026+) or "latest", also search web
    current_year = datetime.now().year
    needs_web_search = (
        year and year >= current_year - 1  # Last 2 years
        or "latest" in query.lower()
        or "recent" in query.lower()
        or "new" in query.lower()
        or str(current_year) in query
    )
    
    if needs_web_search and technology:
        web_lookup = get_cve_web_lookup()
        web_results = web_lookup.search_recent_cves(technology, year)
        
        if web_results.get("success"):
            # Merge results
            local_cves = local_results.get("cves", [])
            web_cves = web_results.get("cves", [])
            
            # Deduplicate by CVE ID
            seen_ids = {cve.get("cve_id") for cve in local_cves}
            for web_cve in web_cves:
                if web_cve.get("cve_id") not in seen_ids:
                    local_cves.append(web_cve)
                    seen_ids.add(web_cve.get("cve_id"))
            
            return {
                "success": True,
                "query": query,
                "total_results": len(local_cves),
                "cves": local_cves,
                "sources": {
                    "local": len(local_results.get("cves", [])),
                    "web": len(web_cves)
                }
            }
    
    return local_results
