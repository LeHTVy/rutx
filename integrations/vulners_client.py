import vulners
from typing import List, Dict, Optional

class VulnersClient:
    """
    Client for Vulners API

    Features:
    - 400M+ vulnerability documents
    - CVE, Exploit, Patch data
    - API key required (free tier: 10,000 requests/month)
    - Non-US data source

    Get API key: https://vulners.com/userinfo
    """

    def __init__(self, api_key: str):
        """Initialize Vulners client"""
        try:
            self.client = vulners.Vulners(api_key=api_key)
        except Exception as e:
            print(f"⚠️  Vulners initialization failed: {e}")
            self.client = None

    def get_cve_info(self, cve_id: str) -> Optional[Dict]:
        """
        Get comprehensive CVE information

        Args:
            cve_id: e.g., "CVE-2021-44228"

        Returns:
            {
                "cve_id": "CVE-2021-44228",
                "cvss_score": 10.0,
                "description": "...",
                "exploit_count": 5,
                "patch_available": true,
                "references": [...]
            }
        """
        if not self.client:
            return None

        try:
            # Query Vulners database
            results = self.client.document(cve_id)

            if not results:
                return None

            # Extract relevant fields
            data = results.get("data", {}).get("documents", {}).get(cve_id, {})

            return {
                "cve_id": cve_id,
                "cvss_score": data.get("cvss", {}).get("score"),
                "cvss_vector": data.get("cvss", {}).get("vector"),
                "description": data.get("description", "")[:500],
                "published": data.get("published"),
                "modified": data.get("modified"),
                "exploit_count": len(data.get("exploit", [])),
                "patch_available": len(data.get("fix", [])) > 0,
                "references": data.get("references", [])[:10],
                "cwe": data.get("cwe", []),
                "data_source": "vulners"
            }

        except Exception as e:
            print(f"Vulners API error for {cve_id}: {e}")
            return None

    def search_exploits(self, cve_id: str) -> List[Dict]:
        """Search for exploits related to CVE"""
        if not self.client:
            return []

        try:
            results = self.client.searchExploit(cve_id)

            exploits = []
            for exploit in results.get("search", []):
                exploits.append({
                    "id": exploit.get("id"),
                    "title": exploit.get("title"),
                    "href": exploit.get("href"),
                    "type": exploit.get("type"),
                    "published": exploit.get("published")
                })

            return exploits[:10]  # Limit to 10

        except Exception as e:
            print(f"Vulners exploit search error: {e}")
            return []

    def batch_query(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Batch query multiple CVEs"""
        results = {}

        for cve_id in cve_ids:
            cve_info = self.get_cve_info(cve_id)
            if cve_info:
                results[cve_id] = cve_info

        return results
