import requests
from typing import List, Dict, Optional
from datetime import datetime

class OSVClient:
    """
    Client for OSV (Open Source Vulnerabilities) database

    Free, no API key required
    Focuses on: Python, JavaScript, Go, Rust, C/C++, Java
    Maintained by: Google & Open Source Security Foundation
    """

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SNODE-AI-CVE-Scanner"
        })

    def query_by_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Query OSV by CVE ID

        Example:
            vuln = client.query_by_cve("CVE-2021-44228")

        Returns:
            {
                "id": "CVE-2021-44228",
                "summary": "Apache Log4j2 <=2.14.1 JNDI features...",
                "details": "...",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}],
                "affected": [...packages...],
                "references": [...],
                "database_specific": {...}
            }
        """
        try:
            url = f"{self.BASE_URL}/vulns/{cve_id}"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                return self._parse_osv_vuln(response.json())
            elif response.status_code == 404:
                return None
            else:
                response.raise_for_status()

        except requests.RequestException as e:
            print(f"OSV API error for {cve_id}: {e}")
            return None

    def query_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Batch query multiple CVEs (more efficient)

        Args:
            cve_ids: List of CVE IDs to query

        Returns:
            {
                "CVE-2021-44228": {...},
                "CVE-2022-26134": {...}
            }
        """
        results = {}

        # OSV batch endpoint
        url = f"{self.BASE_URL}/querybatch"

        # Build batch request
        queries = [{"id": cve_id} for cve_id in cve_ids]

        try:
            response = self.session.post(
                url,
                json={"queries": queries},
                timeout=30
            )
            response.raise_for_status()

            batch_results = response.json().get("results", [])

            for i, result in enumerate(batch_results):
                cve_id = cve_ids[i]
                vulns = result.get("vulns", [])

                if vulns:
                    results[cve_id] = self._parse_osv_vuln(vulns[0])

        except requests.RequestException as e:
            print(f"OSV batch query error: {e}")
            # Fallback to individual queries
            for cve_id in cve_ids:
                result = self.query_by_cve(cve_id)
                if result:
                    results[cve_id] = result

        return results

    def _parse_osv_vuln(self, vuln_data: Dict) -> Dict:
        """
        Parse OSV vulnerability data into standardized format

        Returns:
            {
                "cve_id": "CVE-2021-44228",
                "description": "...",
                "published_date": "2021-12-10T10:15:09.000Z",
                "cvss_v3_score": 10.0,
                "cvss_v3_severity": "CRITICAL",
                "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/...",
                "affected_packages": [...],
                "references": [...],
                "data_source": "osv",
                "last_synced": "2025-12-01T..."
            }
        """
        cve_id = vuln_data.get("id")

        # Extract CVSS from severity array
        severity_data = vuln_data.get("severity", [])
        cvss_v3_score = None
        cvss_v3_vector = None
        cvss_v3_severity = None

        for severity in severity_data:
            if severity.get("type") == "CVSS_V3":
                cvss_v3_vector = severity.get("score")

                # Parse CVSS score from vector string
                if cvss_v3_vector:
                    # Extract base score from vector or calculate
                    # For now, use simplified extraction
                    cvss_v3_score = self._extract_cvss_score(cvss_v3_vector)
                    cvss_v3_severity = self._cvss_to_severity(cvss_v3_score)

        # Extract affected packages
        affected = vuln_data.get("affected", [])
        affected_packages = []

        for pkg in affected:
            package_name = pkg.get("package", {}).get("name")
            ecosystem = pkg.get("package", {}).get("ecosystem")

            if package_name:
                affected_packages.append(f"{ecosystem}:{package_name}")

        # Extract references
        references = [ref.get("url") for ref in vuln_data.get("references", [])]

        return {
            "cve_id": cve_id,
            "description": vuln_data.get("summary", vuln_data.get("details", ""))[:500],
            "published_date": vuln_data.get("published"),
            "modified_date": vuln_data.get("modified"),
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_severity": cvss_v3_severity,
            "cvss_v3_vector": cvss_v3_vector,
            "affected_packages": affected_packages[:20],
            "references": references[:10],
            "data_source": "osv",
            "last_synced": datetime.now().isoformat()
        }

    def _extract_cvss_score(self, vector: str) -> Optional[float]:
        """Extract base score from CVSS vector string"""
        # CVSS vectors don't contain the score, need to calculate or fetch separately
        # For OSV, they should provide it in the severity field
        # Placeholder - real implementation would use cvss library
        return None

    def _cvss_to_severity(self, score: Optional[float]) -> Optional[str]:
        """Convert CVSS score to severity label"""
        if score is None:
            return None
        elif score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
