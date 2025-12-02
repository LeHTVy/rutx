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

        # Extract structured data
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

        # Build structured data
        structured_data = {
            "scan_metadata": {
                "tool": "nmap",
                "target": target,
                "scan_type": scan_type,
                "timestamp": datetime.utcnow().isoformat(),
                "command": scan_data.get("command_executed", "")
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
- **Hosts Discovered**: {hosts_count}
- **Total Open Ports**: {structured_data['statistics']['total_open_ports']}
- **Services Detected**: {len(services_detected)}

### Discovered Hosts
"""

        if not hosts_list:
            content += "\nNo detailed host data available.\n"
        else:
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

        if ports:
            content += "### Open Ports\n"
            for port in sorted(ports):
                content += f"- `{port}`\n"
            content += "\n"

        if vulns:
            content += "### Known Vulnerabilities\n"
            for vuln in vulns:
                content += f"- {vuln}\n"
            content += "\n"
        else:
            content += "### Vulnerabilities\n\nNo known vulnerabilities found in Shodan database.\n\n"

        return {
            "content": content,
            "structured_data": structured_data,
            "report_type": "shodan_lookup",
            "title": f"Shodan Lookup - {target}"
        }

    @staticmethod
    def generate_report(tool_name: str, *results) -> Optional[Dict[str, Any]]:
        """
        Generate a programmatic report for any tool.

        Args:
            tool_name: Name of the tool (nmap, masscan, naabu, subdomain, shodan)
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

        generator = generators.get(tool_name)
        if generator and len(results) > 0:
            return generator(results[0])

        return None
