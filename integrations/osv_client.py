from typing import List, Dict, Optional
from integrations.base_cve_client import BaseCVEClient


class OSVClient(BaseCVEClient):
    """
    Client for OSV (Open Source Vulnerabilities) database

    Free, no API key required
    Focuses on: Python, JavaScript, Go, Rust, C/C++, Java
    Maintained by: Google & Open Source Security Foundation
    """

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self):
        super().__init__(base_url=self.BASE_URL, timeout=10)

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
        url = f"{self.base_url}/vulns/{cve_id}"
        result = self._make_http_request(url, method="GET", provider_name="OSV")

        if result.get("success"):
            return self._parse_vulnerability(result["data"])
        elif result.get("status_code") == 404:
            return None
        else:
            print(f"OSV API error for {cve_id}: {result.get('error')}")
            return None

    def batch_query(self, cve_ids: List[str]) -> Dict[str, Dict]:
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
        url = f"{self.base_url}/querybatch"

        # Build batch request
        queries = [{"id": cve_id} for cve_id in cve_ids]
        payload = {"queries": queries}

        # Use base class HTTP method
        result = self._make_http_request(
            url,
            method="POST",
            payload=payload,
            timeout=30,
            provider_name="OSV"
        )

        if result.get("success"):
            batch_results = result["data"].get("results", [])

            for i, batch_result in enumerate(batch_results):
                cve_id = cve_ids[i]
                vulns = batch_result.get("vulns", [])

                if vulns:
                    results[cve_id] = self._parse_vulnerability(vulns[0])
        else:
            print(f"OSV batch query error: {result.get('error')}")
            # Fallback to individual queries using base class method
            return super().batch_query(cve_ids)

        return results

    def _parse_vulnerability(self, vuln_data: Dict) -> Dict:
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

        # Use base class standardization method
        return self._standardize_cve_data(
            cve_id=cve_id,
            description=vuln_data.get("summary", vuln_data.get("details", "")),
            published_date=vuln_data.get("published"),
            modified_date=vuln_data.get("modified"),
            cvss_score=cvss_v3_score,
            cvss_vector=cvss_v3_vector,
            references=references,
            affected_packages=affected_packages
        )

