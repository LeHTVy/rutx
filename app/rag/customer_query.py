"""
Customer Query System
=====================

Query system for customer/client data across PostgreSQL and ChromaDB.
Supports queries like:
- "Which customers are using MongoDB and what versions?"
- "Find all customers with vulnerable software versions"
- "Show me all findings for customer X"
"""

import json
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from app.memory.postgres import get_postgres
from app.rag.unified_memory import UnifiedRAG
from app.rag.cve_rag import search_cves
from app.llm.client import OllamaClient


class CustomerQuerySystem:
    """
    Query system for customer/client data.
    
    Supports:
    - Query by customer/client ID
    - Query by technology/software
    - Query by version
    - Query by vulnerability/CVE
    - Cross-database queries (PostgreSQL + ChromaDB)
    """
    
    def __init__(self):
        self.postgres = get_postgres()
        self.rag = UnifiedRAG.get_instance()
        self.llm = OllamaClient()
    
    def query_customers_by_technology(
        self, 
        technology: str, 
        version: str = None,
        customer_id: str = None
    ) -> Dict[str, Any]:
        """
        Query customers using a specific technology.
        
        Args:
            technology: Technology name (e.g., "MongoDB", "Apache", "WordPress")
            version: Optional version filter
            customer_id: Optional customer filter
        
        Returns:
            Dict with customers, domains, versions, and findings
        """
        results = {
            "technology": technology,
            "version": version,
            "customers": [],
            "total_findings": 0
        }
        
        # 1. Query PostgreSQL findings table for technology mentions
        if self.postgres and self.postgres.conn:
            try:
                with self.postgres.conn.cursor() as cur:
                    # Search in findings.data JSONB for technology
                    query = """
                        SELECT DISTINCT 
                            s.customer_id,
                            s.target_domain,
                            f.finding_type,
                            f.data,
                            f.discovered_at,
                            s.session_id
                        FROM findings f
                        JOIN sessions s ON f.session_id = s.session_id
                        WHERE f.data::text ILIKE %s
                    """
                    params = [f'%{technology}%']
                    
                    if customer_id:
                        query += " AND s.customer_id = %s"
                        params.append(customer_id)
                    
                    query += " ORDER BY f.discovered_at DESC"
                    
                    cur.execute(query, params)
                    rows = cur.fetchall()
                    
                    # Group by customer/domain
                    customer_map = {}
                    for row in rows:
                        customer_id = row.get('customer_id') or 'default'
                        domain = row.get('target_domain') or 'unknown'
                        finding_data = row.get('data') or {}
                        
                        key = f"{customer_id}:{domain}"
                        if key not in customer_map:
                            customer_map[key] = {
                                "customer_id": customer_id,
                                "domain": domain,
                                "findings": [],
                                "versions": set(),
                                "technologies": set()
                            }
                        
                        # Extract version and technology info
                        finding_str = json.dumps(finding_data).lower()
                        if technology.lower() in finding_str:
                            customer_map[key]["findings"].append({
                                "type": row.get('finding_type'),
                                "data": finding_data,
                                "discovered_at": str(row.get('discovered_at'))
                            })
                            
                            # Try to extract version
                            version_match = re.search(
                                rf'{re.escape(technology.lower())}[:\s]+([\d.]+)',
                                finding_str,
                                re.IGNORECASE
                            )
                            if version_match:
                                customer_map[key]["versions"].add(version_match.group(1))
                            
                            # Extract technology mentions
                            if technology.lower() in finding_str:
                                customer_map[key]["technologies"].add(technology)
                    
                    # Convert to list format
                    for key, info in customer_map.items():
                        if version:
                            # Filter by version if specified
                            if not any(v.startswith(version) for v in info["versions"]):
                                continue
                        
                        results["customers"].append({
                            "customer_id": info["customer_id"],
                            "domain": info["domain"],
                            "versions": list(info["versions"]),
                            "technologies": list(info["technologies"]),
                            "findings_count": len(info["findings"]),
                            "findings": info["findings"][:5]  # Limit to 5 most recent
                        })
                        results["total_findings"] += len(info["findings"])
            
            except Exception as e:
                results["error"] = f"PostgreSQL query error: {e}"
        
        # 2. Query ChromaDB for semantic matches
        try:
            query_text = f"{technology}"
            if version:
                query_text += f" version {version}"
            
            # Search in findings collection
            findings_results = self.rag.findings_collection.query(
                query_texts=[query_text],
                n_results=20,
                where={"customer_id": customer_id} if customer_id else None
            )
            
            # Process ChromaDB results
            if findings_results.get("documents") and findings_results["documents"][0]:
                for i, doc in enumerate(findings_results["documents"][0]):
                    metadata = findings_results.get("metadatas", [[]])[0][i] if findings_results.get("metadatas") else {}
                    domain = metadata.get("domain", "unknown")
                    customer_id_from_meta = metadata.get("customer_id", "default")
                    
                    # Check if we already have this customer
                    existing = next(
                        (c for c in results["customers"] 
                         if c["domain"] == domain and c["customer_id"] == customer_id_from_meta),
                        None
                    )
                    
                    if not existing:
                        results["customers"].append({
                            "customer_id": customer_id_from_meta,
                            "domain": domain,
                            "versions": [],
                            "technologies": [technology],
                            "findings_count": 1,
                            "findings": [{"type": "semantic_match", "data": doc}]
                        })
                        results["total_findings"] += 1
        
        except Exception as e:
            if "error" not in results:
                results["error"] = ""
            results["error"] += f" ChromaDB query error: {e}"
        
        return results
    
    def query_customers_by_vulnerability(
        self,
        cve_id: str = None,
        vulnerability_name: str = None,
        technology: str = None
    ) -> Dict[str, Any]:
        """
        Query customers affected by a vulnerability.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2024-1234")
            vulnerability_name: Vulnerability name/keywords
            technology: Technology filter
        
        Returns:
            Dict with affected customers and details
        """
        results = {
            "cve_id": cve_id,
            "vulnerability": vulnerability_name,
            "technology": technology,
            "affected_customers": [],
            "cve_details": None
        }
        
        # 1. Get CVE details if CVE ID provided (with web fallback)
        if cve_id:
            try:
                from app.rag.cve_web_lookup import lookup_cve_with_fallback
                cve_result = lookup_cve_with_fallback(cve_id)
                
                if cve_result.get("success"):
                    cve_data = cve_result.get("cve") or cve_result.get("cves", [{}])[0] if isinstance(cve_result.get("cves"), list) else {}
                    results["cve_details"] = cve_data
                    results["cve_source"] = cve_result.get("source", "unknown")
                    
                    # Extract technology from CVE
                    cve_desc = cve_data.get("description", "").lower()
                    if not technology:
                        # Try to infer technology from CVE description
                        tech_keywords = ["mongodb", "apache", "wordpress", "nginx", "mysql", "redis"]
                        for tech in tech_keywords:
                            if tech in cve_desc:
                                technology = tech
                                results["technology"] = technology
                                break
                else:
                    results["cve_error"] = cve_result.get("error", "CVE lookup failed")
            except Exception as e:
                results["cve_error"] = f"CVE lookup error: {e}"
        
        # 2. Query customers using the affected technology
        if technology:
            tech_results = self.query_customers_by_technology(technology)
            results["affected_customers"] = tech_results.get("customers", [])
        
        # 3. Search for vulnerability mentions in findings
        if vulnerability_name or cve_id:
            search_term = cve_id or vulnerability_name
            if self.postgres and self.postgres.conn:
                try:
                    with self.postgres.conn.cursor() as cur:
                        query = """
                            SELECT DISTINCT 
                                s.customer_id,
                                s.target_domain,
                                f.finding_type,
                                f.data,
                                f.discovered_at
                            FROM findings f
                            JOIN sessions s ON f.session_id = s.session_id
                            WHERE f.data::text ILIKE %s
                            ORDER BY f.discovered_at DESC
                            LIMIT 50
                        """
                        cur.execute(query, [f'%{search_term}%'])
                        rows = cur.fetchall()
                        
                        for row in rows:
                            customer_id = row.get('customer_id') or 'default'
                            domain = row.get('target_domain') or 'unknown'
                            
                            # Check if already in affected_customers
                            existing = next(
                                (c for c in results["affected_customers"]
                                 if c["domain"] == domain and c["customer_id"] == customer_id),
                                None
                            )
                            
                            if not existing:
                                results["affected_customers"].append({
                                    "customer_id": customer_id,
                                    "domain": domain,
                                    "findings": [{
                                        "type": row.get('finding_type'),
                                        "data": row.get('data'),
                                        "discovered_at": str(row.get('discovered_at'))
                                    }]
                                })
                except Exception as e:
                    results["vuln_query_error"] = f"Vulnerability query error: {e}"
        
        return results
    
    def query_customer_findings(
        self,
        customer_id: str = None,
        domain: str = None,
        finding_type: str = None
    ) -> Dict[str, Any]:
        """
        Query all findings for a specific customer or domain.
        
        Args:
            customer_id: Customer ID
            domain: Domain name
            finding_type: Optional finding type filter
        
        Returns:
            Dict with findings grouped by type
        """
        results = {
            "customer_id": customer_id,
            "domain": domain,
            "findings_by_type": {},
            "total_findings": 0
        }
        
        if not self.postgres or not self.postgres.conn:
            return results
        
        try:
            with self.postgres.conn.cursor() as cur:
                query = """
                    SELECT 
                        f.finding_type,
                        f.data,
                        f.discovered_at,
                        s.target_domain,
                        s.customer_id
                    FROM findings f
                    JOIN sessions s ON f.session_id = s.session_id
                    WHERE 1=1
                """
                params = []
                
                if customer_id:
                    query += " AND s.customer_id = %s"
                    params.append(customer_id)
                
                if domain:
                    query += " AND s.target_domain = %s"
                    params.append(domain)
                
                if finding_type:
                    query += " AND f.finding_type = %s"
                    params.append(finding_type)
                
                query += " ORDER BY f.discovered_at DESC"
                
                cur.execute(query, params)
                rows = cur.fetchall()
                
                for row in rows:
                    ftype = row.get('finding_type') or 'unknown'
                    if ftype not in results["findings_by_type"]:
                        results["findings_by_type"][ftype] = []
                    
                    results["findings_by_type"][ftype].append({
                        "data": row.get('data'),
                        "discovered_at": str(row.get('discovered_at')),
                        "domain": row.get('target_domain'),
                        "customer_id": row.get('customer_id')
                    })
                    results["total_findings"] += 1
        
        except Exception as e:
            results["error"] = f"Query error: {e}"
        
        return results
    
    def natural_language_query(self, query: str) -> Dict[str, Any]:
        """
        Parse natural language query and execute appropriate query.
        
        Examples:
        - "Which customers are using MongoDB?"
        - "Show me all customers with vulnerable MongoDB versions"
        - "Find customers affected by CVE-2024-1234"
        """
        # Use LLM to parse query intent
        parse_prompt = f"""Parse this customer query and extract information:

Query: "{query}"

Extract and return JSON with:
{{
    "intent": "technology_query" | "vulnerability_query" | "customer_query" | "general",
    "technology": "technology name if mentioned",
    "version": "version if mentioned",
    "cve_id": "CVE ID if mentioned",
    "vulnerability_name": "vulnerability name if mentioned",
    "customer_id": "customer ID if mentioned",
    "domain": "domain if mentioned"
}}

Return ONLY the JSON object."""

        try:
            response = self.llm.generate(parse_prompt, timeout=20, stream=False, show_content=False).strip()
            
            # Parse JSON response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group(), strict=False)
                
                intent = parsed.get("intent", "general")
                
                if intent == "technology_query":
                    return self.query_customers_by_technology(
                        technology=parsed.get("technology", ""),
                        version=parsed.get("version"),
                        customer_id=parsed.get("customer_id")
                    )
                elif intent == "vulnerability_query":
                    return self.query_customers_by_vulnerability(
                        cve_id=parsed.get("cve_id"),
                        vulnerability_name=parsed.get("vulnerability_name"),
                        technology=parsed.get("technology")
                    )
                elif intent == "customer_query":
                    return self.query_customer_findings(
                        customer_id=parsed.get("customer_id"),
                        domain=parsed.get("domain")
                    )
                else:
                    return {"error": "Could not parse query intent", "parsed": parsed}
        
        except Exception as e:
            return {"error": f"Query parsing error: {e}"}


# Singleton instance
_customer_query_system: Optional[CustomerQuerySystem] = None


def get_customer_query_system() -> CustomerQuerySystem:
    """Get singleton CustomerQuerySystem instance."""
    global _customer_query_system
    if _customer_query_system is None:
        _customer_query_system = CustomerQuerySystem()
    return _customer_query_system
