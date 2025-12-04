import vulners
from typing import List, Dict, Optional
from integrations.base_cve_client import BaseCVEClient


class VulnersClient(BaseCVEClient):
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
        # Note: Vulners uses its own SDK, not direct HTTP
        # We still inherit from BaseCVEClient for batch_query pattern
        super().__init__(base_url="https://vulners.com", timeout=10)

        try:
            self.client = vulners.Vulners(api_key=api_key)
        except Exception as e:
            print(f"⚠️  Vulners initialization failed: {e}")
            self.client = None

    def query_by_cve(self, cve_id: str) -> Optional[Dict]:
        """Alias for get_cve_info to match base class interface"""
        return self.get_cve_info(cve_id)

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

            # Use base class standardization
            return self._standardize_cve_data(
                cve_id=cve_id,
                description=data.get("description", ""),
                published_date=data.get("published"),
                modified_date=data.get("modified"),
                cvss_score=data.get("cvss", {}).get("score"),
                cvss_vector=data.get("cvss", {}).get("vector"),
                references=data.get("references", []),
                additional_data={
                    "exploit_count": len(data.get("exploit", [])),
                    "patch_available": len(data.get("fix", [])) > 0,
                    "cwe": data.get("cwe", [])
                }
            )

        except Exception as e:
            print(f"Vulners API error for {cve_id}: {e}")
            return None

    def _parse_vulnerability(self, vuln_data: Dict) -> Dict:
        """Parse Vulners vulnerability data (required by base class)"""
        # Vulners uses SDK, so this is handled in get_cve_info
        # This method is here to satisfy the abstract base class
        return vuln_data

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

    # Inherited batch_query from BaseCVEClient works fine
    # It will call our query_by_cve method for each CVE
