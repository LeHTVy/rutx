"""
Memory Display Service
======================

Formats memory/context data for display in memory_query_node.
Centralizes all formatting logic to keep graph.py clean.
"""
from typing import Dict, Any, List


class MemoryDisplayService:
    """Service for formatting memory/context data for display."""
    
    @staticmethod
    def format_memory_query(context: Dict[str, Any], domain: str) -> str:
        """
        Format all stored data from context and RAG for display.
        
        Args:
            context: Current context dictionary
            domain: Target domain
            
        Returns:
            Formatted markdown string with all stored data
        """
        response_parts = []
        
        # Handle None domain
        if domain == "None" or domain is None:
            domain = "Unknown target"
        response_parts.append(f"## 📊 Stored Data for {domain}\n")
        
        # ─────────────────────────────────────────────────────────
        # TRY RAG FOR CROSS-SESSION DATA
        # ─────────────────────────────────────────────────────────
        rag_findings = {"subdomains": [], "hosts": [], "vulnerabilities": []}
        try:
            from app.rag.unified_memory import get_unified_rag
            rag = get_unified_rag()
            if domain and domain != "Unknown target":
                # Normalize domain (remove www, lowercase)
                normalized_domain = domain.lower().replace("www.", "").strip()
                rag_findings = rag.get_findings_for_domain(normalized_domain)
                
                # Filter to ensure all findings are for this specific domain
                if rag_findings.get("subdomains"):
                    # Ensure subdomains end with the domain
                    filtered_subs = [
                        s for s in rag_findings["subdomains"]
                        if isinstance(s, dict) and s.get("subdomain", "").lower().endswith(normalized_domain)
                    ] or [
                        s for s in rag_findings["subdomains"]
                        if isinstance(s, str) and s.lower().endswith(normalized_domain)
                    ]
                    rag_findings["subdomains"] = filtered_subs
                
                if rag_findings.get("subdomains") or rag_findings.get("hosts"):
                    response_parts.append("*Cross-session data from RAG:*\n")
        except Exception:
            pass
        
        # Emails - filter to only show emails related to target domain
        emails = context.get("emails", [])
        if emails:
            # Filter emails to only include those related to target domain
            domain_lower = domain.lower().replace('www.', '')
            target_base = domain_lower.split('.')[0] if '.' in domain_lower else domain_lower
            
            filtered_emails = []
            for email in emails:
                if '@' in email:
                    email_domain = email.split('@')[1].lower()
                    # Include if email domain matches target
                    if (domain_lower in email_domain or 
                        target_base in email_domain or
                        email_domain.endswith('.' + domain_lower) or
                        email_domain == domain_lower):
                        filtered_emails.append(email)
            
            if filtered_emails:
                response_parts.append(f"### 📧 Emails ({len(filtered_emails)} found)\n")
                for email in filtered_emails:
                    response_parts.append(f"  • {email}")
                response_parts.append("")
        
        # Subdomains - combine session + RAG
        subdomains = context.get("subdomains", [])
        rag_subs = rag_findings.get("subdomains", [])
        
        # Handle different formats: list of strings or list of dicts
        if rag_subs and isinstance(rag_subs[0], dict):
            rag_subs = [s.get("subdomain", "") for s in rag_subs if isinstance(s, dict)]
        elif rag_subs and isinstance(rag_subs[0], str):
            rag_subs = rag_subs
        
        all_subdomains = list(set(subdomains + rag_subs))  # Dedupe
        subdomain_count = len(all_subdomains) or context.get("subdomain_count", 0)
        
        # Check if user wants full list (e.g., "show all subdomains", "list all subdomains")
        query = context.get("query", "").lower() if context.get("query") else ""
        show_all = any(phrase in query for phrase in ["show all", "list all", "all subdomains", "every subdomain"])
        
        if all_subdomains:
            rag_indicator = " 💾" if rag_subs else ""
            response_parts.append(f"### 🌐 Subdomains ({subdomain_count} found){rag_indicator}\n")
            
            if show_all or subdomain_count <= 20:
                # Show all if requested or if count is small
                for sub in all_subdomains:
                    response_parts.append(f"  • {sub}")
            else:
                # Show summary with categories
                # Group by common patterns
                main_domain_subs = [s for s in all_subdomains if s.count('.') == 2]  # Direct subdomains
                nested_subs = [s for s in all_subdomains if s.count('.') > 2]  # Nested subdomains
                
                if main_domain_subs:
                    response_parts.append(f"  **Direct subdomains** ({len(main_domain_subs)}):")
                    for sub in sorted(main_domain_subs)[:10]:
                        response_parts.append(f"    • {sub}")
                    if len(main_domain_subs) > 10:
                        response_parts.append(f"    ... and {len(main_domain_subs) - 10} more")
                    response_parts.append("")
                
                if nested_subs:
                    response_parts.append(f"  **Nested subdomains** ({len(nested_subs)}):")
                    for sub in sorted(nested_subs)[:5]:
                        response_parts.append(f"    • {sub}")
                    if len(nested_subs) > 5:
                        response_parts.append(f"    ... and {len(nested_subs) - 5} more")
                    response_parts.append("")
                
                response_parts.append(f"  *💡 Tip: Type 'show all subdomains' to see the complete list*")
            
            response_parts.append("")
        elif subdomain_count > 0:
            response_parts.append(f"### 🌐 Subdomains\n  {subdomain_count} subdomains discovered (list not in memory)\n")
        
        # Hosts
        hosts = context.get("hosts", [])
        if hosts:
            response_parts.append(f"### 🖥️ Hosts ({len(hosts)} found)\n")
            for host in hosts:
                response_parts.append(f"  • {host}")
            response_parts.append("")
        
        # IPs - show categorized summary
        ips = context.get("ips", [])
        if ips:
            query = context.get("query", "").lower() if context.get("query") else ""
            show_all = any(phrase in query for phrase in ["show all", "list all", "all ips", "every ip"])
            
            response_parts.append(f"### 🔢 IP Addresses ({len(ips)} found)\n")
            
            if show_all or len(ips) <= 15:
                # Show all if requested or if count is small
                for ip in ips:
                    response_parts.append(f"  • {ip}")
            else:
                # Show first 10 and summary
                for ip in ips[:10]:
                    response_parts.append(f"  • {ip}")
                response_parts.append(f"  ... and {len(ips) - 10} more")
                response_parts.append(f"  *💡 Tip: Type 'show all ips' to see the complete list*")
            
            response_parts.append("")
        
        # ASNs
        asns = context.get("asns", [])
        if asns:
            response_parts.append(f"### 🏢 ASNs ({len(asns)} found)\n")
            for asn in asns:
                if isinstance(asn, dict):
                    asn_str = f"AS{asn.get('asn', '?')} - {asn.get('name', 'Unknown')}"
                    if asn.get('org'):
                        asn_str += f" ({asn.get('org')})"
                    response_parts.append(f"  • {asn_str}")
                else:
                    response_parts.append(f"  • {asn}")
            response_parts.append("")
        
        # Interesting URLs - filter to only show URLs related to target domain
        interesting_urls = context.get("interesting_urls", [])
        if interesting_urls:
            # Filter URLs to only include those related to target domain
            domain_lower = domain.lower().replace('www.', '')
            target_base = domain_lower.split('.')[0] if '.' in domain_lower else domain_lower
            
            filtered_urls = []
            exclude_domains = ['icann.org', 'whois', 'registrar', '1api.net', 'nic.', 'iana.org']
            
            for url in interesting_urls:
                url_lower = url.lower()
                # Exclude registrar/admin URLs
                if any(excluded in url_lower for excluded in exclude_domains):
                    continue
                
                # Include if URL contains target domain
                if (domain_lower in url_lower or 
                    target_base in url_lower or
                    url_lower.endswith('.' + domain_lower) or
                    url_lower.endswith(domain_lower)):
                    filtered_urls.append(url)
            
            if filtered_urls:
                response_parts.append(f"### 🔗 Interesting URLs ({len(filtered_urls)} found)\n")
                for url in filtered_urls:
                    response_parts.append(f"  • {url}")
                response_parts.append("")
        
        # ─────────────────────────────────────────────────────────
        # PORT SCAN RESULTS
        # ─────────────────────────────────────────────────────────
        open_ports = context.get("open_ports", [])
        if open_ports:
            response_parts.append(f"### 🔌 Open Ports ({len(open_ports)} found)\n")
            for port in open_ports:
                if isinstance(port, dict):
                    port_str = f"{port.get('port')}/{port.get('protocol', 'tcp')}"
                    service = port.get('service', '')
                    version = port.get('version', '')
                    if service:
                        port_str += f"  {service}"
                    if version:
                        port_str += f" ({version})"
                    response_parts.append(f"  • {port_str}")
                else:
                    response_parts.append(f"  • {port}")
            response_parts.append("")
        
        # OS Detection
        if context.get("os_detected"):
            response_parts.append(f"### 💻 OS Detected\n  {context['os_detected']}\n")
        
        # ─────────────────────────────────────────────────────────
        # VULNERABILITY RESULTS
        # ─────────────────────────────────────────────────────────
        vulnerabilities = context.get("vulnerabilities", [])
        if vulnerabilities:
            critical = context.get("critical_vulns", 0)
            high = context.get("high_vulns", 0)
            response_parts.append(f"### 🔓 Vulnerabilities ({len(vulnerabilities)} found)")
            if critical or high:
                response_parts.append(f"  🔴 Critical: {critical} | 🟠 High: {high}\n")
            else:
                response_parts.append("")
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown")
                template = vuln.get("template", "unknown")
                matched = vuln.get("matched", "")
                badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(severity, "⚪")
                response_parts.append(f"  {badge} [{template}] {matched}")
            response_parts.append("")
        
        # Nikto Findings
        nikto_findings = context.get("nikto_findings", [])
        if nikto_findings:
            response_parts.append(f"### 🕷️ Nikto Findings ({len(nikto_findings)} found)\n")
            for finding in nikto_findings:
                response_parts.append(f"  • {finding}")
            response_parts.append("")
        
        # SQLi Results
        if context.get("sqli_vulnerable"):
            dbs = context.get("databases_found", 0)
            response_parts.append(f"### 🔓 SQL Injection\n  ⚠️ Target is VULNERABLE to SQL injection!")
            if dbs:
                response_parts.append(f"  📁 {dbs} databases discovered")
            response_parts.append("")
        
        # ─────────────────────────────────────────────────────────
        # WEB DISCOVERY RESULTS
        # ─────────────────────────────────────────────────────────
        discovered_paths = context.get("discovered_paths", [])
        if discovered_paths:
            response_parts.append(f"### 📂 Discovered Paths ({len(discovered_paths)} found)\n")
            for path in discovered_paths:
                response_parts.append(f"  • {path}")
            response_parts.append("")
        
        # HTTP Probes
        http_probes = context.get("http_probes", [])
        if http_probes:
            response_parts.append(f"### 🌍 HTTP Probes ({len(http_probes)} found)\n")
            for probe in http_probes:
                response_parts.append(f"  • {probe}")
            response_parts.append("")
        
        # ─────────────────────────────────────────────────────────
        # WORDPRESS INFO
        # ─────────────────────────────────────────────────────────
        if context.get("wordpress_version"):
            response_parts.append(f"### 📦 WordPress Info")
            response_parts.append(f"  Version: {context['wordpress_version']}")
            if context.get("wp_users"):
                response_parts.append(f"  Users: {', '.join(context['wp_users'][:10])}")
            if context.get("wp_vulnerable_plugins"):
                response_parts.append(f"  ⚠️ Vulnerable Plugins: {', '.join(context['wp_vulnerable_plugins'])}")
            response_parts.append("")
        
        # WAF Detection
        if context.get("has_waf_check"):
            if context.get("waf_detected"):
                waf_name = context.get("waf_name", "Unknown")
                response_parts.append(f"### 🛡️ WAF Detected\n  ⚠️ {waf_name}\n")
            else:
                response_parts.append("### 🛡️ WAF Detection\n  ✅ No WAF detected\n")
        
        # ─────────────────────────────────────────────────────────
        # CREDENTIALS & EXPLOITS
        # ─────────────────────────────────────────────────────────
        cracked_creds = context.get("cracked_credentials", [])
        if cracked_creds:
            response_parts.append(f"### 🔑 Cracked Credentials ({len(cracked_creds)} found)\n")
            for cred in cracked_creds:
                user = cred.get("username", "?")
                passwd = cred.get("password", "?")
                service = cred.get("service", "")
                host = cred.get("host", "")
                response_parts.append(f"  • {user}:{passwd} ({service}@{host})")
            response_parts.append("")
        
        exploits_found = context.get("exploits_found", [])
        if exploits_found:
            response_parts.append(f"### 💣 Exploits Found ({len(exploits_found)})\n")
            for exp in exploits_found:
                title = exp.get("title", "Unknown")
                response_parts.append(f"  • {title}")
            response_parts.append("")
        
        # ─────────────────────────────────────────────────────────
        # SMB/NETWORK INFO
        # ─────────────────────────────────────────────────────────
        smb_shares = context.get("smb_shares", [])
        if smb_shares:
            response_parts.append(f"### 📁 SMB Shares ({len(smb_shares)} found)\n")
            for share in smb_shares:
                response_parts.append(f"  • {share}")
            response_parts.append("")
        
        smb_users = context.get("smb_users", [])
        if smb_users:
            response_parts.append(f"### 👤 SMB Users ({len(smb_users)} found)\n")
            for user in smb_users:
                response_parts.append(f"  • {user}")
            response_parts.append("")
        
        # ─────────────────────────────────────────────────────────
        # TECHNOLOGY & TOOLS
        # ─────────────────────────────────────────────────────────
        # Web Technologies (from whatweb)
        web_tech = context.get("web_technologies", [])
        if web_tech:
            response_parts.append(f"### 🔧 Web Technologies ({len(web_tech)} found)\n")
            for tech in web_tech[:20]:
                response_parts.append(f"  • {tech}")
            response_parts.append("")
        
        # Detected Technologies (from analyzer)
        detected_tech = context.get("detected_tech", [])
        if detected_tech and not web_tech:
            response_parts.append("### 🔧 Detected Technologies\n")
            for tech in detected_tech[:20]:
                response_parts.append(f"  • {tech}")
            response_parts.append("")
        
        # Tools run
        tools_run = context.get("tools_run", [])
        if tools_run:
            response_parts.append("### 🛠️ Tools Executed\n")
            for tool in tools_run:
                response_parts.append(f"  • {tool}")
            response_parts.append("")
        
        # ─────────────────────────────────────────────────────────
        # SCAN CATEGORIES - Categorized targets using cloud service metadata
        # ─────────────────────────────────────────────────────────
        # Use TargetCollector and cloud service metadata from ChromaDB
        try:
            from app.agent.core import get_target_collector
            from app.rag.unified_memory import get_unified_rag
            
            target_collector = get_target_collector()
            rag = get_unified_rag()
            
            if domain and domain != "Unknown target":
                # Get all IPs and subdomains
                all_ips = rag.get_ips(domain, limit=100)
                all_subs = rag.get_subdomains(domain, limit=100)
                
                # Categorize IPs using cloud service metadata (from ChromaDB)
                categorized = rag.categorize_ips(all_ips)
                
                # Extract categories
                historical_ips = categorized.get("historical_ips", [])  # Origin servers
                cloudflare_ips = categorized.get("cloudflare", [])
                digitalocean_ips = categorized.get("digitalocean", [])
                google_cloud_ips = categorized.get("google_cloud", [])
                aws_ips = categorized.get("aws", [])
                azure_ips = categorized.get("azure", [])
                linode_ips = categorized.get("linode", [])
                vultr_ips = categorized.get("vultr", [])
                
                # Group all CDN/hosting IPs (for display)
                cdn_hosting_ips = []
                for service_name in ["cloudflare", "digitalocean", "google_cloud", "aws", "azure", "linode", "vultr"]:
                    service_ips = categorized.get(service_name, [])
                    if service_ips:
                        cdn_hosting_ips.extend(service_ips)
                
                # Store categorized targets for scanning
                context["scan_categories"] = {
                    "historical_ips": historical_ips,
                    "cloudflare_ips": cloudflare_ips,
                    "digitalocean_ips": digitalocean_ips,
                    "google_cloud_ips": google_cloud_ips,
                    "aws_ips": aws_ips,
                    "azure_ips": azure_ips,
                    "linode_ips": linode_ips,
                    "vultr_ips": vultr_ips,
                    "cdn_hosting_ips": cdn_hosting_ips,
                    "subdomains": all_subs[:50],
                    "all_ips": all_ips
                }
                
                # Display scan categories (dynamic based on discovered services)
                if historical_ips or all_subs or cdn_hosting_ips:
                    response_parts.append("### 🎯 Scan Categories\n")
                    response_parts.append("*Choose a category to port scan:*\n")
                    
                    category_num = 1
                    
                    if historical_ips:
                        response_parts.append(f"  **{category_num}. Origin IPs** ({len(historical_ips)}) - Potential origin servers")
                        response_parts.append(f"     → `scan historical ips` or `nmap {' '.join(historical_ips[:3])}...`")
                        # Show first 5 IPs only
                        for ip in historical_ips[:5]:
                            response_parts.append(f"     • {ip}")
                        if len(historical_ips) > 5:
                            response_parts.append(f"     ... and {len(historical_ips) - 5} more")
                        response_parts.append("")
                        category_num += 1
                    
                    # Display discovered cloud services
                    service_display_order = [
                        ("cloudflare", "Cloudflare CDN IPs"),
                        ("digitalocean", "DigitalOcean IPs"),
                        ("google_cloud", "Google Cloud IPs"),
                        ("aws", "AWS IPs"),
                        ("azure", "Azure IPs"),
                        ("linode", "Linode IPs"),
                        ("vultr", "Vultr IPs"),
                    ]
                    
                    for service_name, display_name in service_display_order:
                        service_ips = categorized.get(service_name, [])
                        if service_ips:
                            response_parts.append(f"  **{category_num}. {display_name}** ({len(service_ips)})")
                            response_parts.append(f"     → `scan {service_name} ips`")
                            # Show first 3 IPs only
                            for ip in service_ips[:3]:
                                response_parts.append(f"     • {ip}")
                            if len(service_ips) > 3:
                                response_parts.append(f"     ... and {len(service_ips) - 3} more")
                            response_parts.append("")
                            category_num += 1
                    
                    if all_subs:
                        response_parts.append(f"  **{category_num}. Subdomains** ({len(all_subs)}) - All discovered subdomains")
                        response_parts.append(f"     → `scan subdomains` or `scan all subdomains`")
                        response_parts.append("")
                        category_num += 1
                    
                    total_targets = len(all_ips) + len(all_subs)
                    response_parts.append(f"  **All Targets** ({total_targets}) - Everything")
                    response_parts.append(f"     → `scan all targets`")
                    response_parts.append("")
        except Exception:
            # Silently fail - scan categories are optional
            pass
        
        # If nothing found
        if len(response_parts) <= 1:
            response_parts.append("No data stored yet. Run some scans first!")
        
        return "\n".join(response_parts)


# Singleton instance
_memory_display: MemoryDisplayService = None


def get_memory_display() -> MemoryDisplayService:
    """Get singleton MemoryDisplayService instance."""
    global _memory_display
    if _memory_display is None:
        _memory_display = MemoryDisplayService()
    return _memory_display
