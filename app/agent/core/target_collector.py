"""
Target Collector Service
========================

Centralized service for collecting and categorizing targets for scanning tools.
Moved from graph.py to reduce hardcode logic and improve maintainability.
"""
from typing import Dict, List, Any, Optional, Set
import re


class TargetCollector:
    """
    Service for collecting targets from various sources (context, RAG, user input).
    
    Handles:
    - Collecting IPs, subdomains, URLs from context and RAG
    - Categorizing targets using cloud service metadata from ChromaDB
    - Filtering targets based on user modifications
    """
    
    def collect_all_targets(self, domain: str, context: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Collect all potential targets from context and RAG.
        
        Returns:
            Dict with keys: 'ips', 'subdomains', 'urls', 'all', 'stats'
        """
        all_targets = {
            "ips": [],
            "subdomains": [],
            "urls": [],
            "all": [],
            "stats": {
                "from_context": {"ips": 0, "subdomains": 0, "urls": 0},
                "from_rag": {"ips": 0, "subdomains": 0},
                "deduplicated": {"ips": 0, "subdomains": 0, "total": 0}
            }
        }
        
        # From context (current session)
        if context.get("ips"):
            context_ips = list(set(context.get("ips", [])))
            all_targets["ips"].extend(context_ips)
            all_targets["stats"]["from_context"]["ips"] = len(context_ips)
        
        if context.get("subdomains"):
            context_subs = list(set(context.get("subdomains", [])))
            all_targets["subdomains"].extend(context_subs)
            all_targets["stats"]["from_context"]["subdomains"] = len(context_subs)
        
        if context.get("interesting_urls"):
            context_urls = list(set(context.get("interesting_urls", [])))
            all_targets["urls"].extend(context_urls)
            all_targets["stats"]["from_context"]["urls"] = len(context_urls)
        
        # From RAG (persistent memory - previous scans)
        if domain:
            try:
                from app.rag.unified_memory import get_unified_rag
                rag = get_unified_rag()
                
                # Get IPs from RAG (only for this domain)
                rag_ips = rag.get_ips(domain, limit=100)
                if rag_ips:
                    # Filter to ensure they're for this domain
                    filtered_rag_ips = [ip for ip in rag_ips if ip]  # Basic validation
                    all_targets["ips"].extend(filtered_rag_ips)
                    all_targets["stats"]["from_rag"]["ips"] = len(filtered_rag_ips)
                
                # Get subdomains from RAG (only for this domain)
                rag_subs = rag.get_subdomains(domain, limit=100)
                if rag_subs:
                    # Filter to ensure they're subdomains of this domain
                    domain_base = domain.lower().replace("www.", "")
                    filtered_rag_subs = [
                        sub for sub in rag_subs 
                        if sub.lower().endswith(domain_base) or domain_base in sub.lower()
                    ]
                    all_targets["subdomains"].extend(filtered_rag_subs)
                    all_targets["stats"]["from_rag"]["subdomains"] = len(filtered_rag_subs)
            except Exception:
                pass
        
        # Extract domains from URLs
        for url in all_targets["urls"][:50]:
            url = url.strip()
            if url.startswith(("http://", "https://")):
                domain_from_url = re.sub(r'^https?://', '', url)
                domain_from_url = domain_from_url.split('/')[0].split(':')[0]
                if domain_from_url and domain_from_url not in all_targets["subdomains"]:
                    all_targets["subdomains"].append(domain_from_url)
        
        # Deduplicate (remove exact duplicates)
        original_ips_count = len(all_targets["ips"])
        original_subs_count = len(all_targets["subdomains"])
        
        all_targets["ips"] = list(set(all_targets["ips"]))
        all_targets["subdomains"] = list(set(all_targets["subdomains"]))
        all_targets["urls"] = list(set(all_targets["urls"]))
        
        all_targets["stats"]["deduplicated"]["ips"] = original_ips_count - len(all_targets["ips"])
        all_targets["stats"]["deduplicated"]["subdomains"] = original_subs_count - len(all_targets["subdomains"])
        
        # Combine all (deduplicated)
        all_targets["all"] = list(set(
            all_targets["ips"] + 
            all_targets["subdomains"] + 
            ([domain] if domain else [])
        ))
        
        all_targets["stats"]["deduplicated"]["total"] = (
            original_ips_count + original_subs_count - len(all_targets["all"])
        )
        
        return all_targets
    
    def get_targets_summary(self, domain: str, context: Dict[str, Any]) -> str:
        """
        Get a human-readable summary of collected targets.
        
        Returns formatted string with breakdown.
        """
        all_targets = self.collect_all_targets(domain, context)
        stats = all_targets["stats"]
        
        summary_parts = []
        
        total = len(all_targets["all"])
        if total > 0:
            summary_parts.append(f"**Total targets: {total}**")
            
            # Breakdown by type
            if all_targets["subdomains"]:
                summary_parts.append(f"  • Subdomains: {len(all_targets['subdomains'])}")
            if all_targets["ips"]:
                summary_parts.append(f"  • IP addresses: {len(all_targets['ips'])}")
            if all_targets["urls"]:
                summary_parts.append(f"  • URLs: {len(all_targets['urls'])}")
            
            # Source breakdown
            from_context = stats["from_context"]
            from_rag = stats["from_rag"]
            
            if from_context["ips"] > 0 or from_context["subdomains"] > 0:
                summary_parts.append(f"\n**From current session:**")
                if from_context["subdomains"] > 0:
                    summary_parts.append(f"  • {from_context['subdomains']} subdomains")
                if from_context["ips"] > 0:
                    summary_parts.append(f"  • {from_context['ips']} IPs")
            
            if from_rag["ips"] > 0 or from_rag["subdomains"] > 0:
                summary_parts.append(f"\n**From previous scans (RAG):**")
                if from_rag["subdomains"] > 0:
                    summary_parts.append(f"  • {from_rag['subdomains']} subdomains")
                if from_rag["ips"] > 0:
                    summary_parts.append(f"  • {from_rag['ips']} IPs")
            
            # Deduplication info
            dedup = stats["deduplicated"]
            if dedup["total"] > 0:
                summary_parts.append(f"\n**Deduplication:** Removed {dedup['total']} duplicates")
        
        return "\n".join(summary_parts) if summary_parts else "No targets collected yet."
    
    def get_categorized_targets(
        self, 
        domain: str, 
        category: str, 
        context: Dict[str, Any]
    ) -> List[str]:
        """
        Get targets for a specific category.
        
        Categories:
        - "subdomains": All discovered subdomains
        - "historical_ips": Non-Cloudflare IPs (potential origin servers)
        - "cloudflare_ips": Cloudflare CDN IPs
        - "all_ips": All IPs regardless of category
        - "all": All targets (IPs + subdomains)
        
        Returns:
            List of target strings (IPs or domains)
        """
        if category == "subdomains":
            return self._get_subdomains(domain, context)
        elif category == "historical_ips":
            return self._get_historical_ips(domain, context)
        elif category == "cloudflare_ips":
            return self._get_cloudflare_ips(domain, context)
        elif category == "all_ips":
            return self._get_all_ips(domain, context)
        elif category == "all":
            return self._get_all_targets(domain, context)
        else:
            return []
    
    def _get_subdomains(self, domain: str, context: Dict[str, Any]) -> List[str]:
        """Get all subdomains from RAG and context."""
        subdomains = []
        
        # From context
        if context.get("subdomains"):
            subdomains.extend(context.get("subdomains", []))
        
        # From RAG
        if domain:
            try:
                from app.rag.unified_memory import get_unified_rag
                rag = get_unified_rag()
                rag_subs = rag.get_subdomains(domain, limit=200)
                if rag_subs:
                    subdomains.extend(rag_subs)
            except Exception:
                pass
        
        return list(set(subdomains))
    
    def _get_historical_ips(self, domain: str, context: Dict[str, Any]) -> List[str]:
        """Get historical IPs (non-CDN/hosting, potential origin servers)."""
        # Check stored categories first
        categories = context.get("scan_categories", {})
        if categories.get("historical_ips"):
            return categories["historical_ips"]
        
        # Collect from RAG
        all_ips = self._get_all_ips(domain, context)
        
        # Categorize IPs using cloud service metadata
        try:
            from app.rag.unified_memory import get_unified_rag
            rag = get_unified_rag()
            
            # Get ASNs if available
            asns = {}
            if context.get("asns"):
                # Map IPs to ASNs if available
                host_ip_map = context.get("host_ip_map", {})
                for asn_info in context.get("asns", []):
                    # Try to find IPs with this ASN
                    pass  # ASN mapping is complex, skip for now
            
            # Categorize all IPs
            categorized = rag.categorize_ips(all_ips, asns)
            
            # Historical IPs = origin IPs (unknown/not in cloud services)
            historical = categorized.get("historical_ips", [])
            
            return historical
        except Exception:
            # Fallback: return all IPs if categorization fails
            return all_ips
    
    def _get_cloudflare_ips(self, domain: str, context: Dict[str, Any]) -> List[str]:
        """Get Cloudflare CDN IPs using cloud service metadata."""
        # Check stored categories first
        categories = context.get("scan_categories", {})
        if categories.get("cloudflare_ips"):
            return categories["cloudflare_ips"]
        
        # Collect from RAG
        all_ips = self._get_all_ips(domain, context)
        
        # Categorize IPs using cloud service metadata
        try:
            from app.rag.unified_memory import get_unified_rag
            rag = get_unified_rag()
            
            categorized = rag.categorize_ips(all_ips)
            cloudflare = categorized.get("cloudflare", [])
            
            return cloudflare
        except Exception:
            return []
    
    def _get_cloud_service_ips(self, domain: str, service_name: str, context: Dict[str, Any]) -> List[str]:
        """
        Get IPs for a specific cloud service (e.g., "digitalocean", "google_cloud").
        
        Uses ChromaDB metadata to identify service IPs.
        """
        all_ips = self._get_all_ips(domain, context)
        
        try:
            from app.rag.unified_memory import get_unified_rag
            rag = get_unified_rag()
            
            categorized = rag.categorize_ips(all_ips)
            return categorized.get(service_name, [])
        except Exception:
            return []
    
    def _get_all_ips(self, domain: str, context: Dict[str, Any]) -> List[str]:
        """Get all IPs from context and RAG."""
        ips = []
        
        # From context
        if context.get("ips"):
            ips.extend(context.get("ips", []))
        
        # From RAG
        if domain:
            try:
                from app.rag.unified_memory import get_unified_rag
                rag = get_unified_rag()
                rag_ips = rag.get_ips(domain, limit=100)
                if rag_ips:
                    ips.extend(rag_ips)
            except Exception:
                pass
        
        return list(set(ips))
    
    def _get_all_targets(self, domain: str, context: Dict[str, Any]) -> List[str]:
        """Get all targets (IPs + subdomains)."""
        all_targets = self.collect_all_targets(domain, context)
        return all_targets["all"]
    
    def filter_targets(
        self, 
        targets: List[str], 
        user_mods: Dict[str, Any],
        query: str = ""
    ) -> List[str]:
        """
        Apply user modifications to filter targets.
        
        User mods can include:
        - specific_target: Use only this target
        - scan_subdomains: Filter to subdomains only
        - scan_all_ips: Filter to IPs only
        - scan_all_targets: Use all targets
        """
        if not targets:
            return []
        
        # PRIORITY 1: Specific target overrides everything
        specific_target = user_mods.get("specific_target")
        if not specific_target and query:
            # Try to extract from query
            target_match = re.search(
                r'(?:use|scan|nmap|masscan)\s+(?:on\s+)?([a-z0-9.-]+\.[a-z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', 
                query, 
                re.IGNORECASE
            )
            if target_match:
                specific_target = target_match.group(1)
        
        if specific_target:
            return [specific_target]
        
        # PRIORITY 2: Category filters
        if user_mods.get("scan_subdomains") or ("subdomain" in query.lower() and "scan" in query.lower()):
            # Filter to subdomains only (exclude main domain and IPs)
            ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            filtered = [t for t in targets if not ip_pattern.match(t)]
            return filtered
        
        if user_mods.get("scan_all_ips") or ("ip" in query.lower() and "scan" in query.lower() and "subdomain" not in query.lower()):
            # Filter to IPs only
            ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            filtered = [t for t in targets if ip_pattern.match(t)]
            return filtered
        
        if user_mods.get("scan_all_targets"):
            # Use all targets
            return targets
        
        # Default: return all targets
        return targets
    
    def prepare_targets_for_tool(
        self,
        tool_name: str,
        domain: str,
        context: Dict[str, Any],
        user_mods: Dict[str, Any] = None,
        query: str = ""
    ) -> Dict[str, Any]:
        """
        Prepare target parameters for a specific tool.
        
        Returns:
            Dict with 'target', 'targets', and other tool-specific params
        """
        user_mods = user_mods or {}
        
        # Check for category scan request (dynamic cloud services)
        scan_category = None
        if user_mods.get("scan_subdomains"):
            scan_category = "subdomains"
        elif user_mods.get("scan_historical"):
            scan_category = "historical_ips"
        elif user_mods.get("scan_cloudflare"):
            scan_category = "cloudflare_ips"
        elif user_mods.get("scan_digitalocean"):
            scan_category = "digitalocean_ips"
        elif user_mods.get("scan_google_cloud"):
            scan_category = "google_cloud_ips"
        elif user_mods.get("scan_aws"):
            scan_category = "aws_ips"
        elif user_mods.get("scan_azure"):
            scan_category = "azure_ips"
        elif user_mods.get("scan_linode"):
            scan_category = "linode_ips"
        elif user_mods.get("scan_vultr"):
            scan_category = "vultr_ips"
        elif user_mods.get("scan_cdn_hosting"):
            scan_category = "cdn_hosting_ips"
        elif user_mods.get("scan_all_ips"):
            scan_category = "all_ips"
        elif user_mods.get("scan_all_targets"):
            scan_category = "all"
        
        # Get targets based on category or collect all
        if scan_category:
            targets = self.get_categorized_targets(domain, scan_category, context)
        else:
            all_targets = self.collect_all_targets(domain, context)
            targets = all_targets["all"]
        
        # Apply user filters
        targets = self.filter_targets(targets, user_mods, query)
        
        # Prepare tool params
        tool_params = {}
        
        # For tools that accept target lists
        if tool_name in ["nmap", "masscan", "nuclei", "httpx"]:
            if len(targets) > 1:
                tool_params["targets"] = targets[:50]  # Limit for batch processing
                tool_params["target"] = " ".join(targets[:20])  # For command line
            elif len(targets) == 1:
                tool_params["target"] = targets[0]
                tool_params["targets"] = [targets[0]]
            else:
                tool_params["target"] = domain
                tool_params["targets"] = [domain] if domain else []
        
        # For single-target tools
        else:
            if targets:
                tool_params["target"] = targets[0]
            else:
                tool_params["target"] = domain
        
        return tool_params


# Singleton instance
_target_collector: Optional[TargetCollector] = None


def get_target_collector() -> TargetCollector:
    """Get singleton TargetCollector instance."""
    global _target_collector
    if _target_collector is None:
        _target_collector = TargetCollector()
    return _target_collector
