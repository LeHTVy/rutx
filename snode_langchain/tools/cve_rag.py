"""
CVE RAG (Retrieval Augmented Generation) System

Uses ChromaDB to index and search CVE data for semantic queries.
This allows the LLM to find relevant CVEs based on natural language queries.

Usage:
    from snode_langchain.tools.cve_rag import CVEDatabase
    
    cve_db = CVEDatabase()
    cve_db.index_cves()  # One-time indexing
    
    results = cve_db.search("Apache Log4j RCE vulnerability")
"""
import os
import json
import re
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime

try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    print("⚠️ ChromaDB not installed. Run: pip install chromadb")


# ─────────────────────────────────────────────────────────────────
# CVE Parser
# ─────────────────────────────────────────────────────────────────

def parse_cve_json(filepath: str) -> Optional[Dict]:
    """Parse a CVE JSON file and extract key information"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        cve_id = data.get("cveMetadata", {}).get("cveId", "")
        if not cve_id:
            return None
        
        # Get description
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        
        descriptions = cna.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang", "").startswith("en"):
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")
        
        # Get title
        title = cna.get("title", "")
        
        # Get affected products
        affected = cna.get("affected", [])
        products = []
        vendors = []
        for item in affected:
            vendor = item.get("vendor", "")
            product = item.get("product", "")
            if vendor:
                vendors.append(vendor)
            if product:
                products.append(product)
        
        # Get severity from metrics
        severity = "unknown"
        cvss_score = 0.0
        
        # Check CNA metrics
        metrics = cna.get("metrics", [])
        for metric in metrics:
            if "cvssV3_1" in metric:
                cvss = metric["cvssV3_1"]
                severity = cvss.get("baseSeverity", "unknown").lower()
                cvss_score = cvss.get("baseScore", 0.0)
                break
            elif "cvssV3_0" in metric:
                cvss = metric["cvssV3_0"]
                severity = cvss.get("baseSeverity", "unknown").lower()
                cvss_score = cvss.get("baseScore", 0.0)
                break
            elif "other" in metric:
                other = metric.get("other", {}).get("content", {})
                if "other" in other:
                    severity = str(other.get("other", "")).lower()
        
        # Check ADP metrics
        adp = containers.get("adp", [])
        for adp_item in adp:
            adp_metrics = adp_item.get("metrics", [])
            for metric in adp_metrics:
                if "cvssV3_1" in metric:
                    cvss = metric["cvssV3_1"]
                    severity = cvss.get("baseSeverity", "unknown").lower()
                    cvss_score = cvss.get("baseScore", 0.0)
                    break
        
        # Get problem types (CWE)
        problem_types = cna.get("problemTypes", [])
        cwes = []
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                cwe_desc = desc.get("description", "")
                if cwe_id:
                    cwes.append(f"{cwe_id}: {cwe_desc}")
        
        # Get dates
        date_published = data.get("cveMetadata", {}).get("datePublished", "")
        
        # Build searchable text
        searchable_text = f"{cve_id} {title} {description} {' '.join(products)} {' '.join(vendors)} {' '.join(cwes)}"
        
        return {
            "cve_id": cve_id,
            "title": title,
            "description": description[:2000],  # Limit description length
            "severity": severity,
            "cvss_score": cvss_score,
            "products": list(set(products)),
            "vendors": list(set(vendors)),
            "cwes": cwes,
            "date_published": date_published,
            "searchable_text": searchable_text[:3000],
        }
        
    except Exception as e:
        return None


# ─────────────────────────────────────────────────────────────────
# CVE Database with RAG
# ─────────────────────────────────────────────────────────────────

class CVEDatabase:
    """ChromaDB-based CVE database for semantic search"""
    
    def __init__(self, 
                 cve_dir: str = None,
                 db_path: str = None,
                 collection_name: str = "cve_collection"):
        
        if not CHROMADB_AVAILABLE:
            raise ImportError("ChromaDB not installed. Run: pip install chromadb")
        
        # Get project root directory (works regardless of which user runs it)
        project_root = Path(__file__).parent.parent.parent  # cve_rag.py -> tools -> snode_langchain -> rutx
        
        # Default paths - use absolute paths from project root
        self.cve_dir = cve_dir or str(project_root / "cvelistV5-main" / "cves")
        self.db_path = db_path or str(project_root / "data" / "cve_chromadb")
        self.collection_name = collection_name
        
        # Initialize ChromaDB
        os.makedirs(self.db_path, exist_ok=True)
        self.client = chromadb.PersistentClient(path=self.db_path)
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )
        
        print(f"📚 CVE Database initialized")
        print(f"   Collection: {self.collection_name}")
        print(f"   Documents: {self.collection.count()}")
    
    def index_cves(self, 
                   years: List[int] = None,
                   severity_filter: List[str] = None,
                   max_cves: int = None,
                   batch_size: int = 500) -> int:
        """
        Index CVEs from the CVE list directory.
        
        Args:
            years: List of years to index (e.g., [2023, 2024, 2025])
            severity_filter: Only index CVEs with these severities
            max_cves: Maximum number of CVEs to index
            batch_size: Batch size for ChromaDB insertion
        
        Returns:
            Number of CVEs indexed
        """
        if years is None:
            years = [2021, 2022, 2023, 2024, 2025]  # Recent years by default
        
        if severity_filter is None:
            severity_filter = ["critical", "high", "medium"]
        
        print(f"\n🔄 Indexing CVEs from years: {years}")
        print(f"   Severity filter: {severity_filter}")
        
        cve_files = []
        for year in years:
            year_dir = os.path.join(self.cve_dir, str(year))
            if os.path.exists(year_dir):
                for root, dirs, files in os.walk(year_dir):
                    for file in files:
                        if file.endswith('.json') and file.startswith('CVE-'):
                            cve_files.append(os.path.join(root, file))
        
        print(f"   Found {len(cve_files)} CVE files")
        
        if max_cves:
            cve_files = cve_files[:max_cves]
        
        # Process in batches
        indexed = 0
        batch_ids = []
        batch_docs = []
        batch_metas = []
        
        for i, filepath in enumerate(cve_files):
            cve_data = parse_cve_json(filepath)
            
            if cve_data is None:
                continue
            
            # Apply severity filter
            if cve_data["severity"] not in severity_filter and "unknown" not in severity_filter:
                continue
            
            # Check if already indexed
            existing = self.collection.get(ids=[cve_data["cve_id"]])
            if existing and existing["ids"]:
                continue
            
            batch_ids.append(cve_data["cve_id"])
            batch_docs.append(cve_data["searchable_text"])
            batch_metas.append({
                "cve_id": cve_data["cve_id"],
                "title": cve_data["title"][:200],
                "severity": cve_data["severity"],
                "cvss_score": cve_data["cvss_score"],
                "products": ", ".join(cve_data["products"][:5]),
                "vendors": ", ".join(cve_data["vendors"][:3]),
                "date_published": cve_data["date_published"],
            })
            
            # Insert batch
            if len(batch_ids) >= batch_size:
                self.collection.add(
                    ids=batch_ids,
                    documents=batch_docs,
                    metadatas=batch_metas
                )
                indexed += len(batch_ids)
                print(f"   Indexed {indexed} CVEs...")
                batch_ids = []
                batch_docs = []
                batch_metas = []
        
        # Insert remaining
        if batch_ids:
            self.collection.add(
                ids=batch_ids,
                documents=batch_docs,
                metadatas=batch_metas
            )
            indexed += len(batch_ids)
        
        print(f"\n✅ Indexed {indexed} new CVEs")
        print(f"   Total in database: {self.collection.count()}")
        
        return indexed
    
    def search(self, 
               query: str, 
               n_results: int = 10,
               severity_filter: List[str] = None) -> List[Dict]:
        """
        Search for CVEs using semantic similarity.
        
        Args:
            query: Natural language query (e.g., "Apache RCE vulnerability")
            n_results: Number of results to return
            severity_filter: Filter by severity levels
        
        Returns:
            List of matching CVE records
        """
        where_filter = None
        if severity_filter:
            where_filter = {"severity": {"$in": severity_filter}}
        
        results = self.collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where_filter,
            include=["documents", "metadatas", "distances"]
        )
        
        cves = []
        if results and results["ids"] and results["ids"][0]:
            for i, cve_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                distance = results["distances"][0][i] if results["distances"] else 0
                
                cves.append({
                    "cve_id": cve_id,
                    "title": meta.get("title", ""),
                    "severity": meta.get("severity", "unknown"),
                    "cvss_score": meta.get("cvss_score", 0),
                    "products": meta.get("products", ""),
                    "vendors": meta.get("vendors", ""),
                    "date_published": meta.get("date_published", ""),
                    "relevance_score": 1 - distance,  # Convert distance to similarity
                })
        
        return cves
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get full details for a specific CVE from the JSON file"""
        # Find the CVE file
        year = cve_id.split("-")[1]
        num = cve_id.split("-")[2]
        
        # CVEs are stored in xxx directories (e.g., 44xxx for CVE-2021-44228)
        xxx_dir = num[:-3] + "xxx" if len(num) > 3 else "0xxx"
        
        filepath = os.path.join(self.cve_dir, year, xxx_dir, f"{cve_id}.json")
        
        if os.path.exists(filepath):
            return parse_cve_json(filepath)
        
        return None
    
    def stats(self) -> Dict:
        """Get database statistics"""
        count = self.collection.count()
        
        # Sample to get severity distribution
        if count > 0:
            sample = self.collection.get(limit=min(1000, count), include=["metadatas"])
            severities = {}
            for meta in sample["metadatas"]:
                sev = meta.get("severity", "unknown")
                severities[sev] = severities.get(sev, 0) + 1
            
            return {
                "total_cves": count,
                "severity_sample": severities,
            }
        
        return {"total_cves": 0}


# ─────────────────────────────────────────────────────────────────
# Tool wrapper for SNODE agent
# ─────────────────────────────────────────────────────────────────

_cve_db: Optional[CVEDatabase] = None

def get_cve_database() -> CVEDatabase:
    """Get or create the CVE database singleton"""
    global _cve_db
    if _cve_db is None:
        _cve_db = CVEDatabase()
    return _cve_db


def search_cves(query: str, n_results: int = 10, severity: str = None) -> Dict:
    """
    Search the CVE database for vulnerabilities matching a query.
    
    Args:
        query: Natural language query (e.g., "Apache Log4j RCE", "SQL injection WordPress")
        n_results: Number of results to return (default: 10)
        severity: Filter by severity (critical, high, medium, low)
    
    Returns:
        Dictionary with search results
    """
    try:
        db = get_cve_database()
        
        severity_filter = None
        if severity:
            severity_filter = [s.strip().lower() for s in severity.split(",")]
        
        results = db.search(query, n_results=n_results, severity_filter=severity_filter)
        
        return {
            "success": True,
            "query": query,
            "total_results": len(results),
            "cves": results,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "query": query,
        }


def lookup_cve(cve_id: str) -> Dict:
    """
    Look up detailed information for a specific CVE.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
    
    Returns:
        Dictionary with CVE details
    """
    try:
        db = get_cve_database()
        details = db.get_cve_details(cve_id)
        
        if details:
            return {
                "success": True,
                "cve": details,
            }
        else:
            return {
                "success": False,
                "error": f"CVE {cve_id} not found",
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


# ─────────────────────────────────────────────────────────────────
# Tool definitions for agent
# ─────────────────────────────────────────────────────────────────

CVE_RAG_TOOLS = [
    {
        "name": "search_cves",
        "description": "Search the CVE database for vulnerabilities using natural language. Example queries: 'Apache RCE vulnerability', 'SQL injection in WordPress', 'critical vulnerabilities in nginx'",
        "parameters": {
            "query": "Natural language search query",
            "n_results": "Number of results (default: 10)",
            "severity": "Filter by severity: critical, high, medium, low (optional)",
        },
        "function": search_cves,
    },
    {
        "name": "lookup_cve",
        "description": "Get detailed information about a specific CVE by its ID",
        "parameters": {
            "cve_id": "CVE identifier (e.g., CVE-2021-44228)",
        },
        "function": lookup_cve,
    },
]


# ─────────────────────────────────────────────────────────────────
# CLI for indexing
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE RAG Database Manager")
    parser.add_argument("--index", action="store_true", help="Index CVEs into the database")
    parser.add_argument("--years", type=str, default="2023,2024,2025", help="Years to index")
    parser.add_argument("--max", type=int, default=None, help="Max CVEs to index")
    parser.add_argument("--search", type=str, help="Search query")
    parser.add_argument("--lookup", type=str, help="Look up specific CVE")
    parser.add_argument("--stats", action="store_true", help="Show database stats")
    
    args = parser.parse_args()
    
    db = CVEDatabase()
    
    if args.index:
        years = [int(y.strip()) for y in args.years.split(",")]
        db.index_cves(years=years, max_cves=args.max)
    
    elif args.search:
        results = db.search(args.search)
        print(f"\n🔍 Search: {args.search}")
        print(f"   Found {len(results)} results:\n")
        for cve in results:
            print(f"   [{cve['severity'].upper()}] {cve['cve_id']}: {cve['title'][:60]}")
            print(f"         Products: {cve['products']}")
            print(f"         Score: {cve['relevance_score']:.3f}")
            print()
    
    elif args.lookup:
        details = db.get_cve_details(args.lookup)
        if details:
            print(f"\n📋 {details['cve_id']}")
            print(f"   Title: {details['title']}")
            print(f"   Severity: {details['severity']} (CVSS: {details['cvss_score']})")
            print(f"   Products: {', '.join(details['products'][:5])}")
            print(f"   Description: {details['description'][:500]}...")
        else:
            print(f"❌ CVE not found: {args.lookup}")
    
    elif args.stats:
        stats = db.stats()
        print(f"\n📊 CVE Database Stats")
        print(f"   Total CVEs: {stats['total_cves']}")
        if stats.get("severity_sample"):
            print(f"   Severity Distribution (sample):")
            for sev, count in stats["severity_sample"].items():
                print(f"      {sev}: {count}")
    
    else:
        parser.print_help()
