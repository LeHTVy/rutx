"""
Programmatic Report Generator

This module generates structured, consistent programmatic reports from raw tool outputs.
Programmatic reports are NOT analysis reports - they are formatted representations of
raw scan data without LLM enrichment.

Flow:
    Tool Results → Programmatic Report (this module) → Stored in DB → LLM Analysis

Each tool has a dedicated generator that produces a consistent format.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json


class ProgrammaticReportGenerator:
    """
    Generates programmatic reports from tool execution results.

    Programmatic reports:
    - Structured, consistent format
    - No LLM involvement
    - Based purely on tool output
    - Stored before analysis phase
    """

    @staticmethod
    def generate_nmap_report(result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate programmatic report from Nmap scan results.

        Args:
            result: Raw Nmap execution result with 'result' key containing scan data

        Returns:
            Dict with 'content' (markdown string) and 'structured_data' (JSON)
        """
        scan_data = result.get("result", {})
        args = result.get("args", {})

        target = args.get("target", "Unknown")
        scan_type = args.get("scan_type", "Unknown")

        # Debug: Print what we received
        print(f"  [DEBUG GENERATOR] Scan data keys: {list(scan_data.keys())}")
        print(f"  [DEBUG GENERATOR] Scan data sample: {str(scan_data)[:200]}...")

        # Handle batch scan vs single scan data structures
        # Batch scan returns: {"results": {ip: [ports]}, "total_open_ports": int}
        # Single scan returns: {"hosts_discovered": list, "open_ports_summary": dict}

        if "results" in scan_data and "total_open_ports" in scan_data:
            # Batch scan format
            batch_results = scan_data.get("results", {})
            hosts_discovered_raw = scan_data.get("targets_with_open_ports", len(batch_results))

            # Convert batch results to open_ports_summary format
            open_ports_summary = {}
            for ip, ports in batch_results.items():
                if ports:  # Only include IPs with open ports
                    open_ports_summary[ip] = [
                        {"port": port, "protocol": "tcp", "service": "unknown", "version": ""}
                        for port in ports
                    ]

            services_detected = []  # Batch scans don't detect services
        else:
            # Single scan format
            hosts_discovered_raw = scan_data.get("hosts_discovered", [])
            open_ports_summary = scan_data.get("open_ports_summary", {})
            services_detected = scan_data.get("services_detected", [])

        # Handle both int (batch scan count) and list (detailed host data) cases
        if isinstance(hosts_discovered_raw, int):
            hosts_count = hosts_discovered_raw
            hosts_list = []
        else:
            hosts_count = len(hosts_discovered_raw) if hosts_discovered_raw else 0
            hosts_list = hosts_discovered_raw

        # For batch scans, update target to reflect multiple targets
        if "results" in scan_data:
            total_targets = scan_data.get("targets_count", scan_data.get("total_hosts_scanned", 0))
            target = f"{total_targets} targets (batch scan)"

        # Build structured data
        structured_data = {
            "scan_metadata": {
                "tool": "nmap",
                "target": target,
                "scan_type": scan_type,
                "timestamp": datetime.utcnow().isoformat(),
                "command": scan_data.get("command_executed", ""),
                "total_targets_scanned": scan_data.get("targets_count", scan_data.get("total_hosts_scanned", 0))
            },
            "hosts": hosts_list,
            "open_ports": open_ports_summary,
            "services": services_detected,
            "statistics": {
                "total_hosts": hosts_count,
                "total_open_ports": sum(len(ports) for ports in open_ports_summary.values()),
                "total_services": len(services_detected)
            }
        }

        # Build markdown content
        content = f"""## NMAP SCAN REPORT

### Scan Information
- **Target**: {target}
- **Scan Type**: {scan_type}
- **Timestamp**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

### Summary
- **Hosts Scanned**: {structured_data['scan_metadata'].get('total_targets_scanned', hosts_count)}
- **Hosts with Open Ports**: {hosts_count}
- **Total Open Ports**: {structured_data['statistics']['total_open_ports']}
- **Services Detected**: {len(services_detected)}

### Discovered Hosts
"""

        if not hosts_list and open_ports_summary:
            # Batch scan: display results from open_ports_summary
            content += "\n"
            for ip, port_list in sorted(open_ports_summary.items()):
                content += f"\n#### Host: {ip}\n"
                content += f"- **Open Ports**: {len(port_list)}\n"
                content += "- **Ports**:\n"
                for port_info in port_list:
                    port = port_info.get("port", "?")
                    protocol = port_info.get("protocol", "tcp")
                    service = port_info.get("service", "unknown")
                    content += f"  - `{port}/{protocol}`"
                    if service and service != "unknown":
                        content += f" - {service}"
                    content += "\n"
        elif hosts_list:
            # Single scan: display detailed host data
            for host in hosts_list:
                ip = host.get("ip", "Unknown")
                state = host.get("state", "unknown")
                hostname = host.get("hostname", "")

                content += f"\n#### Host: {ip}"
                if hostname:
                    content += f" ({hostname})"
                content += f"\n- **State**: {state}\n"

                # List ports for this host
                host_ports = open_ports_summary.get(ip, [])
                if host_ports:
                    content += "- **Open Ports**:\n"
                    for port_info in host_ports:
                        port = port_info.get("port", "?")
                        protocol = port_info.get("protocol", "tcp")
                        service = port_info.get("service", "unknown")
                        version = port_info.get("version", "")

                        content += f"  - `{port}/{protocol}` - {service}"
                        if version:
                            content += f" ({version})"
                        content += "\n"
        else:
            # No hosts with open ports
            total_scanned = structured_data['scan_metadata'].get('total_targets_scanned', hosts_count)
            content += f"\n**Result**: All {total_scanned} hosts scanned had no open ports in the scanned range (top-1000 ports).\n"
            content += "\nThis could indicate:\n"
            content += "- Hosts are properly firewalled\n"
            content += "- Hosts are down or unreachable\n"
            content += "- Ports outside the scanned range are open\n"

        return {
            "content": content,
            "structured_data": structured_data,
            "report_type": "nmap_scan",
            "title": f"Nmap Scan - {target}"
        }

    @staticmethod
    def generate_masscan_report(result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate programmatic report from Masscan scan results.

        Args:
            result: Raw Masscan execution result

        Returns:
            Dict with 'content' (markdown string) and 'structured_data' (JSON)
        """
        scan_data = result.get("result", {})
        args = result.get("args", {})

        targets = args.get("targets", [])
        ports_scanned = args.get("ports", "1-65535")

        # Extract results
        results_by_ip = scan_data.get("results", {})
        total_open_ports = scan_data.get("total_open_ports", 0)

        # Build structured data
        structured_data = {
            "scan_metadata": {
                "tool": "masscan",
                "targets": targets,
                "ports_scanned": ports_scanned,
                "timestamp": datetime.utcnow().isoformat(),
                "rate": args.get("rate", 10000)
            },
            "results": results_by_ip,
            "statistics": {
                "targets_scanned": len(targets),
                "hosts_with_open_ports": len(results_by_ip),
                "total_open_ports": total_open_ports
            }
        }

        # Build markdown content
        content = f"""## MASSCAN SCAN REPORT

### Scan Information
- **Targets**: {len(targets)} target(s)
- **Ports Scanned**: {ports_scanned}
- **Rate**: {args.get('rate', 10000)} packets/sec
- **Timestamp**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

### Summary
- **Hosts with Open Ports**: {len(results_by_ip)}
- **Total Open Ports Found**: {total_open_ports}

"""

        if total_open_ports == 0:
            content += "### Results\n\nNo open ports detected on any target.\n"
        else:
            content += "### Discovered Open Ports\n\n"

            # Group by domain/IP
            for ip, port_data in sorted(results_by_ip.items()):
                domain = port_data.get("domain", ip)
                open_ports = port_data.get("open_ports", [])

                content += f"#### {domain}\n"
                content += f"- **IP Address**: {ip}\n"
                content += f"- **Open Ports**: {len(open_ports)}\n"

                if open_ports:
                    content += "- **Port Details**:\n"
                    for port_info in sorted(open_ports, key=lambda x: x.get("port", 0)):
                        port = port_info.get("port")
                        protocol = port_info.get("protocol", "tcp")
                        content += f"  - `{port}/{protocol}`\n"

                content += "\n"

        return {
            "content": content,
            "structured_data": structured_data,
            "report_type": "masscan_scan",
            "title": f"Masscan Scan - {len(targets)} target(s)"
        }

    @staticmethod
    def generate_naabu_report(result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate programmatic report from Naabu scan results.

        Args:
            result: Raw Naabu execution result

        Returns:
            Dict with 'content' (markdown string) and 'structured_data' (JSON)
        """
        scan_data = result.get("result", {})
        args = result.get("args", {})

        targets = args.get("targets", [])

        # Extract results
        results_by_target = scan_data.get("results", {})
        total_open_ports = sum(
            len(data.get("open_ports", []))
            for data in results_by_target.values()
        )

        # Build structured data
        structured_data = {
            "scan_metadata": {
                "tool": "naabu",
                "targets": targets,
                "timestamp": datetime.utcnow().isoformat(),
                "rate": args.get("rate", 1000)
            },
            "results": results_by_target,
            "statistics": {
                "targets_scanned": len(targets),
                "hosts_with_open_ports": len(results_by_target),
                "total_open_ports": total_open_ports
            }
        }

        # Build markdown content
        content = f"""## NAABU SCAN REPORT

### Scan Information
- **Targets**: {len(targets)} target(s)
- **Rate**: {args.get('rate', 1000)} packets/sec
- **Timestamp**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

### Summary
- **Hosts with Open Ports**: {len(results_by_target)}
- **Total Open Ports Found**: {total_open_ports}

"""

        if total_open_ports == 0:
            content += "### Results\n\nNo open ports detected on any target.\n"
        else:
            content += "### Discovered Open Ports\n\n"

            for target, port_data in sorted(results_by_target.items()):
                open_ports = port_data.get("open_ports", [])

                content += f"#### {target}\n"
                content += f"- **Open Ports**: {len(open_ports)}\n"

                if open_ports:
                    content += "- **Port Details**:\n"
                    for port in sorted(open_ports):
                        content += f"  - `{port}`\n"

                content += "\n"

        return {
            "content": content,
            "structured_data": structured_data,
            "report_type": "naabu_scan",
            "title": f"Naabu Scan - {len(targets)} target(s)"
        }

    @staticmethod
    def generate_subdomain_report(amass_result: Optional[Dict[str, Any]],
                                   bbot_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate programmatic report from subdomain enumeration results.

        Args:
            amass_result: Raw Amass execution result
            bbot_result: Raw BBOT execution result

        Returns:
            Dict with 'content' (markdown string) and 'structured_data' (JSON)
        """
        # Extract subdomains from both tools
        amass_subdomains = set()
        bbot_subdomains = set()

        domain = "Unknown"

        if amass_result:
            amass_data = amass_result.get("result", {})
            amass_subdomains = set(amass_data.get("subdomains", []))
            domain = amass_result.get("args", {}).get("domain", domain)

        if bbot_result:
            bbot_data = bbot_result.get("result", {})
            bbot_subdomains = set(bbot_data.get("subdomains", []))
            if domain == "Unknown":
                domain = bbot_result.get("args", {}).get("target", domain)

        # Calculate overlap
        all_subdomains = amass_subdomains | bbot_subdomains
        overlap = amass_subdomains & bbot_subdomains
        amass_only = amass_subdomains - bbot_subdomains
        bbot_only = bbot_subdomains - amass_subdomains

        # Categorize subdomains by keyword
        categories = {
            "www": [],
            "api": [],
            "mail": [],
            "dev": [],
            "staging": [],
            "admin": [],
            "vpn": [],
            "internal": [],
            "test": [],
            "other": []
        }

        for subdomain in sorted(all_subdomains):
            subdomain_lower = subdomain.lower()
            categorized = False

            for category in categories.keys():
                if category in subdomain_lower and category != "other":
                    categories[category].append(subdomain)
                    categorized = True
                    break

            if not categorized:
                categories["other"].append(subdomain)

        # Build structured data
        structured_data = {
            "scan_metadata": {
                "tool": "subdomain_enumeration",
                "domain": domain,
                "timestamp": datetime.utcnow().isoformat(),
                "tools_used": []
            },
            "subdomains": {
                "all": sorted(list(all_subdomains)),
                "amass_only": sorted(list(amass_only)),
                "bbot_only": sorted(list(bbot_only)),
                "overlap": sorted(list(overlap))
            },
            "categories": {k: v for k, v in categories.items() if v},
            "statistics": {
                "total_unique": len(all_subdomains),
                "amass_found": len(amass_subdomains),
                "bbot_found": len(bbot_subdomains),
                "overlap_count": len(overlap)
            }
        }

        if amass_result:
            structured_data["scan_metadata"]["tools_used"].append("amass")
        if bbot_result:
            structured_data["scan_metadata"]["tools_used"].append("bbot")

        # Build markdown content
        content = f"""## SUBDOMAIN ENUMERATION REPORT

### Scan Information
- **Domain**: {domain}
- **Tools Used**: {', '.join(structured_data['scan_metadata']['tools_used'])}
- **Timestamp**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

### Summary
- **Total Unique Subdomains**: {len(all_subdomains)}
- **Amass Found**: {len(amass_subdomains)}
- **BBOT Found**: {len(bbot_subdomains)}
- **Overlap (Both Tools)**: {len(overlap)}

"""

        if len(all_subdomains) == 0:
            content += "### Results\n\nNo subdomains discovered.\n"
        else:
            content += "### Subdomain Categories\n\n"

            for category, subdomains in categories.items():
                if subdomains:
                    content += f"#### {category.upper()} ({len(subdomains)})\n"
                    for subdomain in sorted(subdomains)[:20]:  # Limit to first 20 per category
                        source = ""
                        if subdomain in overlap:
                            source = " [Both]"
                        elif subdomain in amass_only:
                            source = " [Amass]"
                        elif subdomain in bbot_only:
                            source = " [BBOT]"
                        content += f"- {subdomain}{source}\n"

                    if len(subdomains) > 20:
                        content += f"- ... and {len(subdomains) - 20} more\n"
                    content += "\n"

        return {
            "content": content,
            "structured_data": structured_data,
            "report_type": "subdomain_enum",
            "title": f"Subdomain Enumeration - {domain}"
        }

    @staticmethod
    def generate_shodan_report(result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate programmatic report from Shodan lookup results.

        Args:
            result: Raw Shodan execution result

        Returns:
            Dict with 'content' (markdown string) and 'structured_data' (JSON)
        """
        scan_data = result.get("result", {})
        args = result.get("args", {})

        target = args.get("ip", "Unknown")

        # Extract Shodan data
        ports = scan_data.get("ports", [])
        vulns = scan_data.get("vulns", [])
        hostnames = scan_data.get("hostnames", [])
        org = scan_data.get("org", "Unknown")
        isp = scan_data.get("isp", "Unknown")
        country = scan_data.get("country_name", scan_data.get("country", "Unknown"))
        city = scan_data.get("city", "Unknown")
        asn = scan_data.get("asn", "Unknown")
        last_update = scan_data.get("last_update", "Unknown")

        # Debug: Show what data we got from Shodan
        print(f"  [DEBUG SHODAN] Target: {target}")
        print(f"  [DEBUG SHODAN] Ports: {len(ports)}, Vulns: {len(vulns)}, Hostnames: {len(hostnames)}")
        print(f"  [DEBUG SHODAN] Org: {org}, ISP: {isp}")

        # Build structured data
        structured_data = {
            "scan_metadata": {
                "tool": "shodan",
                "target": target,
                "timestamp": datetime.utcnow().isoformat()
            },
            "shodan_data": {
                "ip": target,
                "org": org,
                "isp": isp,
                "hostnames": hostnames,
                "ports": ports,
                "vulnerabilities": vulns
            },
            "statistics": {
                "open_ports": len(ports),
                "vulnerabilities": len(vulns),
                "hostnames": len(hostnames)
            }
        }

        # Build markdown content
        content = f"""## SHODAN LOOKUP REPORT

### Target Information
- **IP Address**: {target}
- **Organization**: {org}
- **ISP**: {isp}
- **Location**: {city}, {country}
- **ASN**: {asn}
- **Last Updated**: {last_update}
- **Timestamp**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

### Summary
- **Open Ports**: {len(ports)}
- **Known Vulnerabilities**: {len(vulns)}
- **Hostnames**: {len(hostnames)}

"""

        if hostnames:
            content += "### Hostnames\n"
            for hostname in hostnames:
                content += f"- {hostname}\n"
            content += "\n"
        else:
            content += "### Hostnames\n\nNo hostnames found in Shodan database.\n\n"

        if ports:
            content += "### Open Ports (from Shodan)\n"
            for port in sorted(ports):
                content += f"- `{port}`\n"
            content += "\n"
        else:
            content += "### Open Ports\n\nNo open ports found in Shodan database for this IP.\n\n"

        if vulns:
            content += "### Known Vulnerabilities (CVEs from Shodan)\n"
            for vuln in vulns:
                content += f"- {vuln}\n"
            content += "\n"
        else:
            content += "### Vulnerabilities\n\n**No known vulnerabilities found in Shodan database.**\n\nThis means:\n- Either the target has no publicly known vulnerabilities\n- Or Shodan hasn't scanned this IP recently\n- This is NOT a guarantee the target is secure - only that no CVEs are in Shodan's database\n\n"

        return {
            "content": content,
            "structured_data": structured_data,
            "report_type": "shodan_lookup",
            "title": f"Shodan Lookup - {target}"
        }

    @staticmethod
    def generate_4stage_workflow_report(stage1_dns: Optional[Dict[str, Any]],
                                         stage2_shodan: Optional[Dict[str, Any]],
                                         stage3_naabu: Optional[Dict[str, Any]],
                                         stage4_nmap: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate programmatic report from 4-stage port scan workflow.

        Args:
            stage1_dns: DNS resolution results
            stage2_shodan: Shodan OSINT enrichment results
            stage3_naabu: Naabu port scan results
            stage4_nmap: Nmap service detection results (SOURCE OF TRUTH)

        Returns:
            Dict with 'content' (markdown) and 'structured_data' (JSON)
        """
        content = "## 4-STAGE PORT SCAN WORKFLOW REPORT\n\n"

        # Stage 1: DNS Resolution
        content += "### STAGE 1: DNS RESOLUTION\n\n"
        if stage1_dns and stage1_dns.get("success"):
            subdomains_count = stage1_dns.get("subdomains_count", 0)
            unique_ips = stage1_dns.get("unique_ips", [])
            public_ips = stage1_dns.get("public_ips", [])
            dedup_savings = stage1_dns.get("deduplication_savings", 0)

            content += f"- **Subdomains Resolved**: {subdomains_count}\n"
            content += f"- **Unique IPs**: {len(unique_ips)}\n"
            content += f"- **Public IPs**: {len(public_ips)}\n"
            content += f"- **Deduplication Savings**: {dedup_savings} ({(dedup_savings/subdomains_count*100):.1f}%)\n\n"

            if public_ips[:5]:
                content += "**Sample Public IPs**:\n"
                for ip in public_ips[:5]:
                    content += f"- {ip}\n"
                if len(public_ips) > 5:
                    content += f"- ... and {len(public_ips) - 5} more\n"
                content += "\n"
        else:
            content += "❌ Stage 1 failed or no data\n\n"

        # Stage 2: OSINT Enrichment
        content += "### STAGE 2: OSINT ENRICHMENT (Shodan)\n\n"
        if stage2_shodan and stage2_shodan.get("success"):
            stats = stage2_shodan.get("stats", {})
            content += f"- **IPs Queried**: {stats.get('total', 0)}\n"
            content += f"- **Successful**: {stats.get('successful', 0)}\n"
            content += f"- **Not Found**: {stats.get('not_found', 0)}\n"
            content += f"- **Failed**: {stats.get('failed', 0)}\n"
            content += f"- **Total Ports Discovered**: {stats.get('total_ports', 0)}\n"
            content += f"- **Total Services**: {stats.get('total_services', 0)}\n"
            content += f"- **Total CVEs**: {stats.get('total_vulns', 0)}\n"

            if stats.get('high_threat_ips'):
                content += f"\n⚠️ **High Threat IPs**: {stats.get('high_threat_count', 0)}\n"
                for ip in stats.get('high_threat_ips', [])[:3]:
                    content += f"- {ip}\n"
            content += "\n"
        else:
            content += "❌ Stage 2 failed or no data\n\n"

        # Stage 3: Naabu Scanning
        content += "### STAGE 3: NAABU PORT SCANNING\n\n"
        if stage3_naabu and stage3_naabu.get("success"):
            content += f"- **Targets Scanned**: {stage3_naabu.get('targets_count', 0)}\n"
            content += f"- **Targets with Open Ports**: {stage3_naabu.get('targets_with_open_ports', 0)}\n"
            content += f"- **Total Open Ports**: {stage3_naabu.get('total_open_ports', 0)}\n"
            content += f"- **Elapsed Time**: {stage3_naabu.get('elapsed_seconds', 0)}s\n\n"

            results = stage3_naabu.get("results", {})
            if results:
                content += "**Sample Results**:\n"
                for ip, ports in list(results.items())[:5]:
                    content += f"- {ip}: {len(ports)} ports → {', '.join(map(str, sorted(ports)[:10]))}\n"
                if len(results) > 5:
                    content += f"- ... and {len(results) - 5} more targets\n"
                content += "\n"
        else:
            content += "❌ Stage 3 failed or no data\n\n"

        # Stage 4: Nmap Service Detection (SOURCE OF TRUTH)
        content += "### STAGE 4: NMAP SERVICE DETECTION (🎯 SOURCE OF TRUTH)\n\n"
        if stage4_nmap and stage4_nmap.get("success"):
            stats = stage4_nmap.get("stats", {})
            content += f"- **Targets Scanned**: {stats.get('total', 0)}\n"
            content += f"- **Successful Scans**: {stats.get('successful', 0)}\n"
            content += f"- **Failed Scans**: {stats.get('failed', 0)}\n"
            content += f"- **Services Detected**: {stats.get('total_services', 0)}\n"
            content += f"- **OS Fingerprints**: {stats.get('os_detected', 0)}\n\n"

            services_by_type = stats.get("services_by_type", {})
            if services_by_type:
                content += "**Service Distribution**:\n"
                sorted_services = sorted(services_by_type.items(), key=lambda x: x[1], reverse=True)[:10]
                for svc, count in sorted_services:
                    content += f"- {svc}: {count} instances\n"
                content += "\n"

            results = stage4_nmap.get("results", [])
            if results:
                content += "**Sample Detailed Results**:\n"
                successful_results = [r for r in results if r.get("status") == "success"][:3]
                for res in successful_results:
                    ip = res.get("ip")
                    result_data = res.get("result", {})
                    services = result_data.get("services_detected", [])
                    os_info = result_data.get("os_matches", [])

                    content += f"\n**{ip}**:\n"
                    if services:
                        for svc in services[:5]:
                            port = svc.get("port", "?")
                            service = svc.get("service", "unknown")
                            version = svc.get("version", "")
                            content += f"- Port {port}: {service} {version}\n"
                    if os_info:
                        os_name = os_info[0].get("name", "Unknown")
                        accuracy = os_info[0].get("accuracy", "0")
                        content += f"- OS: {os_name} ({accuracy}% accuracy)\n"

                if len(successful_results) < len(results):
                    content += f"\n... and {len(results) - len(successful_results)} more targets\n"
                content += "\n"
        else:
            content += "❌ Stage 4 failed or no data\n\n"

        # Summary
        content += "## WORKFLOW SUMMARY\n\n"
        total_targets = stage1_dns.get("subdomains_count", 0) if stage1_dns else 0
        unique_ips_count = len(stage1_dns.get("unique_ips", [])) if stage1_dns else 0
        shodan_ports = stage2_shodan.get("stats", {}).get("total_ports", 0) if stage2_shodan else 0
        naabu_ports = stage3_naabu.get("total_open_ports", 0) if stage3_naabu else 0
        nmap_services = stage4_nmap.get("stats", {}).get("total_services", 0) if stage4_nmap else 0
        nmap_os_detected = stage4_nmap.get("stats", {}).get("os_detected", 0) if stage4_nmap else 0

        content += f"- **Original Subdomains**: {total_targets}\n"
        content += f"- **Deduplicated to**: {unique_ips_count} unique IPs ({((total_targets-unique_ips_count)/total_targets*100):.1f}% reduction)\n"
        content += f"- **OSINT Ports (Shodan)**: {shodan_ports}\n"
        content += f"- **Discovered Ports (Naabu)**: {naabu_ports}\n"
        content += f"- **🎯 Detected Services (Nmap)**: {nmap_services} (SOURCE OF TRUTH)\n"
        content += f"- **🎯 OS Fingerprints (Nmap)**: {nmap_os_detected}\n\n"

        content += "**Key Insight**: Nmap Stage 4 provides the authoritative service/version/OS data for vulnerability assessment.\n"

        # Structured data
        structured_data = {
            "workflow": "4-stage",
            "stage1_dns": stage1_dns,
            "stage2_shodan": stage2_shodan,
            "stage3_naabu": stage3_naabu,
            "stage4_nmap": stage4_nmap,
            "source_of_truth": "stage4_nmap",  # Mark which stage is authoritative
            "summary": {
                "original_targets": total_targets,
                "unique_ips": unique_ips_count,
                "deduplication_savings_pct": ((total_targets-unique_ips_count)/total_targets*100) if total_targets > 0 else 0,
                "osint_ports": shodan_ports,
                "discovered_ports": naabu_ports,
                "nmap_services": nmap_services,
                "nmap_os_detected": nmap_os_detected
            }
        }

        return {
            "content": content,
            "structured_data": structured_data,
            "report_type": "4stage_workflow",
            "title": "4-Stage Port Scan Workflow Report"
        }

    @staticmethod
    def generate_report(tool_name: str, *results) -> Optional[Dict[str, Any]]:
        """
        Generate a programmatic report for any tool.

        Args:
            tool_name: Name of the tool (nmap, masscan, naabu, subdomain, shodan, 4stage)
            *results: Tool result(s) - varies by tool

        Returns:
            Dict with report data or None if tool not supported
        """
        generators = {
            "nmap": ProgrammaticReportGenerator.generate_nmap_report,
            "masscan": ProgrammaticReportGenerator.generate_masscan_report,
            "naabu": ProgrammaticReportGenerator.generate_naabu_report,
            "shodan": ProgrammaticReportGenerator.generate_shodan_report,
        }

        if tool_name == "subdomain":
            # Special case: takes 2 results (amass, bbot)
            amass_result = results[0] if len(results) > 0 else None
            bbot_result = results[1] if len(results) > 1 else None
            return ProgrammaticReportGenerator.generate_subdomain_report(amass_result, bbot_result)

        if tool_name == "4stage" or tool_name == "4stage_workflow":
            # Special case: takes 4 results (dns, shodan, naabu, nmap)
            stage1_dns = results[0] if len(results) > 0 else None
            stage2_shodan = results[1] if len(results) > 1 else None
            stage3_naabu = results[2] if len(results) > 2 else None
            stage4_nmap = results[3] if len(results) > 3 else None
            return ProgrammaticReportGenerator.generate_4stage_workflow_report(
                stage1_dns, stage2_shodan, stage3_naabu, stage4_nmap
            )

        generator = generators.get(tool_name)
        if generator and len(results) > 0:
            return generator(results[0])

        return None
