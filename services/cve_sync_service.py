from integrations.osv_client import OSVClient
from integrations.exploitdb_client import ExploitDBClient
from database.models_enhanced import CVEEnrichment
from database import get_session
from datetime import datetime
from typing import List, Dict
import os

class CVESyncService:
    """
    Service to enrich CVE data with OSV and ExploitDB

    Usage:
        syncer = CVESyncService()
        syncer.enrich_found_cves(["CVE-2021-44228", ...])
    """

    def __init__(self):
        self.osv_client = OSVClient()
        self.exploitdb_client = ExploitDBClient()

        # Optional: Vulners for enhanced coverage
        vulners_api_key = os.getenv("VULNERS_API_KEY")
        if vulners_api_key:
            try:
                from integrations.vulners_client import VulnersClient
                self.vulners_client = VulnersClient(vulners_api_key)
            except ImportError:
                print("⚠️  Vulners client not available (pip install vulners)")
                self.vulners_client = None
        else:
            self.vulners_client = None

        self.session = get_session()

    def enrich_found_cves(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        On-demand enrichment for CVEs found during scanning

        Args:
            cve_ids: List of CVE IDs to enrich

        Returns:
            {
                "CVE-2021-44228": {
                    "cvss_v3_score": 10.0,
                    "cvss_v3_severity": "CRITICAL",
                    "description": "...",
                    "exploit_available": true,
                    "exploit_count": 5,
                    "has_metasploit": true,
                    "public_exploits": [...]
                }
            }
        """
        enriched = {}

        # Step 1: Get CVE metadata from OSV
        print(f"  🔍 Querying OSV for {len(cve_ids)} CVEs...")
        osv_data = self.osv_client.query_batch(cve_ids)

        # Step 2: Check exploit availability via ExploitDB
        print(f"  💣 Checking exploit availability...")
        exploit_data = self.exploitdb_client.batch_check_exploits(cve_ids)

        # Step 3: Vulners (fallback for CVEs not found in OSV)
        if self.vulners_client:
            missing_cves = [cve for cve in cve_ids if cve not in osv_data]

            if missing_cves:
                print(f"  🌐 Querying Vulners for {len(missing_cves)} missing CVEs...")
                vulners_data = self.vulners_client.batch_query(missing_cves)

                # Merge Vulners data into osv_data
                osv_data.update(vulners_data)

        # Step 4: Merge data
        for cve_id in cve_ids:
            osv_info = osv_data.get(cve_id, {})
            exploit_info = exploit_data.get(cve_id, {})

            merged = {
                **osv_info,  # CVE metadata
                **exploit_info,  # Exploit availability
                "enrichment_timestamp": datetime.now().isoformat()
            }

            enriched[cve_id] = merged

            # Store in database cache
            self._cache_cve(cve_id, merged)

        # Commit cache updates
        self.session.commit()

        # Print summary
        exploitable_count = sum(1 for e in enriched.values() if e.get("exploit_available"))
        print(f"  ✅ Enriched {len(enriched)} CVEs ({exploitable_count} with public exploits)")

        return enriched

    def _cache_cve(self, cve_id: str, enrichment_data: Dict):
        """Store/update CVE in local cache"""
        try:
            existing = self.session.query(CVEEnrichment).filter_by(cve_id=cve_id).first()

            if existing:
                # Update existing record
                for key, value in enrichment_data.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)
            else:
                # Create new record
                new_cve = CVEEnrichment(
                    cve_id=cve_id,
                    description=enrichment_data.get("description"),
                    cvss_v3_score=enrichment_data.get("cvss_v3_score"),
                    cvss_v3_severity=enrichment_data.get("cvss_v3_severity"),
                    cvss_v3_vector=enrichment_data.get("cvss_v3_vector"),
                    exploit_available=enrichment_data.get("exploit_available", False),
                    data_source="osv+exploitdb",
                    last_synced=datetime.now()
                )
                self.session.add(new_cve)

        except Exception as e:
            print(f"  ⚠️  Cache error for {cve_id}: {e}")

    def close(self):
        """Cleanup resources"""
        if self.exploitdb_client:
            self.exploitdb_client.close()
