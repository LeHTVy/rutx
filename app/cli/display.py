"""
Display Utilities - Beautiful Output Formatting
================================================

Formats tool results for user-friendly display.
Uses Rich library for colors, tables, and panels.
"""
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


def format_subdomains(subdomains: List[str], domain: str) -> str:
    """Format subdomain list as bullet points."""
    if not subdomains:
        return f"No subdomains found for {domain}"
    
    lines = [f"**Found {len(subdomains)} subdomains for {domain}:**\n"]
    for sub in subdomains[:20]:  # Show max 20
        lines.append(f"• {sub}")
    
    if len(subdomains) > 20:
        lines.append(f"\n... and {len(subdomains) - 20} more")
    
    return "\n".join(lines)


def format_ports(ports_by_host: Dict[str, List[int]]) -> str:
    """Format port scan results as table-like list."""
    if not ports_by_host:
        return "No open ports found"
    
    lines = [f"**Open Ports ({len(ports_by_host)} hosts):**\n"]
    
    for host, ports in list(ports_by_host.items())[:15]:
        port_str = ", ".join(map(str, sorted(ports)[:10]))
        if len(ports) > 10:
            port_str += f" (+{len(ports)-10} more)"
        lines.append(f"• **{host}**: {port_str}")
    
    if len(ports_by_host) > 15:
        lines.append(f"\n... and {len(ports_by_host) - 15} more hosts")
    
    return "\n".join(lines)


def format_vulnerabilities(vulns: List[Dict]) -> str:
    """Format vulnerability list with severity."""
    if not vulns:
        return "No vulnerabilities detected"
    
    # Group by severity
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for v in vulns:
        sev = v.get("severity", "info").lower()
        if sev in by_severity:
            by_severity[sev].append(v)
        else:
            by_severity["info"].append(v)
    
    lines = [f"**Vulnerabilities Found ({len(vulns)} total):**\n"]
    
    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
    
    for sev in ["critical", "high", "medium", "low", "info"]:
        if by_severity[sev]:
            lines.append(f"\n{icons[sev]} **{sev.upper()}** ({len(by_severity[sev])})")
            for v in by_severity[sev][:5]:
                name = v.get("name", v.get("id", "Unknown"))
                host = v.get("host", v.get("target", ""))
                lines.append(f"  • {name} on {host}")
            if len(by_severity[sev]) > 5:
                lines.append(f"  ... and {len(by_severity[sev]) - 5} more")
    
    return "\n".join(lines)


def format_tool_result(tool: str, output: str, success: bool = True) -> str:
    """
    Format a single tool's output for display.
    
    Detects tool type and formats appropriately.
    """
    if not output:
        return f"**{tool}**: No output"
    
    output_lower = output.lower()
    lines = output.strip().split('\n')
    
    # === NMAP OUTPUT (comprehensive parser) ===
    if tool in ["nmap", "masscan"] or "nmap" in output_lower[:100] or "nmap scan report" in output_lower:
        import re
        
        # Parse nmap output into structured data by host
        hosts = {}
        current_host = None
        
        # Split by host markers (handle both newline and inline formats)
        # First normalize: convert inline "Nmap scan report" to newlines
        normalized = re.sub(r'\s*(Nmap scan report for)', r'\n\1', output)
        normalized = re.sub(r'\s*(PORT\s+STATE\s+SERVICE)', r'\n\1', normalized)
        
        for line in normalized.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # New host section
            if 'Nmap scan report for' in line:
                match = re.search(r'Nmap scan report for\s+([^\s(]+)', line)
                if match:
                    current_host = match.group(1)
                    ip_match = re.search(r'\(([0-9.]+)\)', line)
                    ip = ip_match.group(1) if ip_match else ""
                    hosts[current_host] = {"ip": ip, "ports": [], "status": ""}
            
            # Host status
            elif current_host and 'Host is up' in line:
                hosts[current_host]["status"] = "up"
            
            # Port lines (various formats)
            elif current_host:
                # Format: 22/tcp   open     ssh
                port_match = re.search(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)', line)
                if port_match:
                    port_num = port_match.group(1)
                    proto = port_match.group(2)
                    state = port_match.group(3)
                    service = port_match.group(4)
                    # Get version if present
                    version = ""
                    rest = line[port_match.end():].strip()
                    if rest:
                        version = rest[:40]
                    hosts[current_host]["ports"].append({
                        "port": port_num,
                        "proto": proto,
                        "state": state,
                        "service": service,
                        "version": version
                    })
        
        # Format output
        sections = []
        
        # Summary
        total_hosts = len(hosts)
        open_ports_count = sum(len([p for p in h["ports"] if p["state"] == "open"]) for h in hosts.values())
        sections.append(f"**🔍 Nmap Results: {total_hosts} hosts, {open_ports_count} open ports**\n")
        
        # Group hosts by similar results
        for hostname, data in list(hosts.items())[:10]:  # Limit to 10 hosts
            ip = f" ({data['ip']})" if data['ip'] else ""
            sections.append(f"\n**📍 {hostname}**{ip}")
            
            open_ports = [p for p in data["ports"] if p["state"] == "open"]
            filtered_ports = [p for p in data["ports"] if p["state"] == "filtered"]
            
            if open_ports:
                for p in open_ports:
                    icon = "🟢"
                    version_str = f" - {p['version']}" if p['version'] else ""
                    sections.append(f"  {icon} {p['port']}/{p['proto']} {p['service']}{version_str}")
            
            if filtered_ports and len(filtered_ports) <= 3:
                for p in filtered_ports:
                    sections.append(f"  🟡 {p['port']}/{p['proto']} filtered")
            elif filtered_ports:
                sections.append(f"  🟡 {len(filtered_ports)} ports filtered")
            
            if not open_ports and not filtered_ports:
                sections.append("  (no ports scanned)")
        
        if len(hosts) > 10:
            sections.append(f"\n_... and {len(hosts) - 10} more hosts_")
        
        if sections:
            return "\n".join(sections)
    
    # === SEARCHSPLOIT OUTPUT ===
    # searchsploit outputs a table with Exploit Title and Path
    if tool == "searchsploit" or "Exploit Title" in output or "exploits/" in output:
        import re
        
        exploits = []
        
        # Parse searchsploit table format
        # Format: "Title ... | path/to/exploit.py"
        entries = re.split(r'\s*•\s*|\n', output)
        
        for entry in entries:
            entry = entry.strip()
            if not entry or '---' in entry or 'Exploit Title' in entry or 'Shellcodes' in entry:
                continue
            
            # Match: "Some Exploit Title | path/file.ext"
            if '|' in entry:
                parts = entry.split('|')
                if len(parts) >= 2:
                    title = parts[0].strip()
                    path = parts[1].strip()
                    if title and path and '/' in path:
                        exploits.append({"title": title, "path": path})
        
        if exploits:
            sections = [f"**🔍 SearchSploit: {len(exploits)} exploits found**\n"]
            
            # Categorize by type
            remote_exec = []
            local_priv = []
            dos = []
            webapps = []
            other = []
            
            for e in exploits:
                path = e['path'].lower()
                title = e['title']
                if 'local' in path or 'privilege' in title.lower():
                    local_priv.append(e)
                elif 'dos' in path or 'denial' in title.lower():
                    dos.append(e)
                elif 'webapps' in path or 'remote' in path:
                    webapps.append(e)
                else:
                    other.append(e)
            
            if webapps:
                sections.append("\n🔴 **Web Application Exploits:**")
                for e in webapps:
                    sections.append(f"  • {e['title']}")
                    sections.append(f"    📁 `{e['path']}`")
            
            if local_priv:
                sections.append("\n🟠 **Local Privilege Escalation:**")
                for e in local_priv:
                    sections.append(f"  • {e['title']}")
                    sections.append(f"    📁 `{e['path']}`")
            
            if dos:
                sections.append("\n🟡 **Denial of Service:**")
                for e in dos:
                    sections.append(f"  • {e['title']}")
                    sections.append(f"    📁 `{e['path']}`")
            
            if other:
                sections.append("\n🔵 **Other Exploits:**")
                for e in other:
                    sections.append(f"  • {e['title']}")
                    sections.append(f"    📁 `{e['path']}`")
            
            return "\n".join(sections)
    
    # === KATANA OUTPUT ===
    # Katana outputs URLs/endpoints, not subdomains
    if tool == "katana" or (
        tool not in ["nmap", "masscan", "subfinder", "amass", "bbot"] and
        any('http://' in line or 'https://' in line for line in lines[:5])
    ):
        urls = [l.strip() for l in lines if l.strip() and ('http://' in l or 'https://' in l)]
        if urls:
            formatted = f"**Found {len(urls)} endpoints/URLs:**\n"
            for url in urls[:25]:  # Show max 25
                formatted += f"\n• {url}"
            if len(urls) > 25:
                formatted += f"\n\n*... and {len(urls) - 25} more*"
            return formatted
    
    # === BBOT OUTPUT ===
    # bbot outputs [TYPE] followed by data - parse and group by type
    if tool == "bbot" or "[DNS_NAME]" in output or "[OPEN_TCP_PORT]" in output or "[FINDING]" in output:
        import re
        
        # Parse bbot output into structured data
        dns_names = []
        open_ports = []
        findings = []
        urls = []
        emails = []
        technologies = []
        other = []
        
        # Split by common bbot markers
        entries = re.split(r'\s*•\s*|\n', output)
        
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            
            if "[DNS_NAME]" in entry:
                # Extract subdomain name
                match = re.search(r'\[DNS_NAME\]\s+(\S+)', entry)
                if match and match.group(1) not in dns_names:
                    dns_names.append(match.group(1))
            elif "[OPEN_TCP_PORT]" in entry:
                # Extract port info
                match = re.search(r'\[OPEN_TCP_PORT\]\s+(\S+)', entry)
                if match and match.group(1) not in open_ports:
                    open_ports.append(match.group(1))
            elif "[FINDING]" in entry:
                # Extract finding description
                match = re.search(r'"description":\s*"([^"]+)"', entry)
                if match:
                    findings.append(match.group(1))
            elif "[URL]" in entry and "[URL_UNVERIFIED]" not in entry:
                match = re.search(r'\[URL\]\s+(\S+)', entry)
                if match and match.group(1) not in urls:
                    urls.append(match.group(1))
            elif "[EMAIL_ADDRESS]" in entry:
                match = re.search(r'\[EMAIL_ADDRESS\]\s+(\S+)', entry)
                if match and match.group(1) not in emails:
                    emails.append(match.group(1))
            elif "[TECHNOLOGY]" in entry:
                match = re.search(r'"technology":\s*"([^"]+)"', entry)
                if match and match.group(1) not in technologies:
                    technologies.append(match.group(1))
        
        # Format output
        sections = []
        
        if findings:
            sections.append("🔴 **Findings:**")
            for f in findings[:10]:
                sections.append(f"  • {f}")
        
        if open_ports:
            sections.append(f"\n🔌 **Open Ports ({len(open_ports)}):**")
            for port in sorted(set(open_ports))[:15]:
                sections.append(f"  • {port}")
            if len(open_ports) > 15:
                sections.append(f"  _... and {len(open_ports) - 15} more_")
        
        if dns_names:
            # Filter to just subdomains, not external DNS
            subs = [d for d in dns_names if 'cloudflare' not in d.lower() and 'windows' not in d.lower()]
            if subs:
                sections.append(f"\n🌐 **Subdomains ({len(subs)}):**")
                for sub in subs[:20]:
                    sections.append(f"  • {sub}")
                if len(subs) > 20:
                    sections.append(f"  _... and {len(subs) - 20} more_")
        
        if urls:
            sections.append(f"\n🔗 **URLs Found ({len(urls)}):**")
            for url in urls[:10]:
                sections.append(f"  • {url}")
            if len(urls) > 10:
                sections.append(f"  _... and {len(urls) - 10} more_")
        
        if emails:
            sections.append(f"\n📧 **Emails:**")
            for email in emails[:5]:
                sections.append(f"  • {email}")
        
        if technologies:
            sections.append(f"\n🔧 **Technologies:**")
            for tech in technologies[:5]:
                sections.append(f"  • {tech}")
        
        if sections:
            return "\n".join(sections)
    
    # === SUBFINDER/AMASS OUTPUT ===
    # Raw output is just newline-separated subdomains (no http://)
    if tool in ["subfinder", "amass"] or (
        len(lines) > 3 and 
        all('.' in line and 'http' not in line.lower() for line in lines[:5] if line.strip()) and
        not any(kw in output_lower for kw in ['nmap', 'port', 'tcp', 'udp'])
    ):
        # List of subdomains
        subdomains = [l.strip() for l in lines if l.strip() and '.' in l and 'http' not in l.lower()]
        if subdomains:
            formatted = f"**Found {len(subdomains)} subdomains:**\n"
            for sub in subdomains[:25]:  # Show max 25
                formatted += f"\n• {sub}"
            if len(subdomains) > 25:
                formatted += f"\n\n*... and {len(subdomains) - 25} more*"
            return formatted
    
    # === DEFAULT ===
    # Just format as bullet list if multiple lines
    if len(lines) > 3:
        formatted = []
        for line in lines[:30]:
            if line.strip():
                formatted.append(f"• {line.strip()}")
        if len(lines) > 30:
            formatted.append(f"\n*... and {len(lines) - 30} more lines*")
        return "\n".join(formatted)
    
    # Single line or short output
    status = "✓" if success else "✗"
    return f"**{status} {tool}**\n\n{output}"


def format_analysis_response(results: Dict[str, Any]) -> str:
    """
    Format complete analysis results for display.
    
    Combines all tool outputs into a clean, readable format.
    """
    sections = []
    
    for tool, result in results.items():
        if hasattr(result, 'output') and result.output:
            formatted = format_tool_result(tool, result.output, result.success)
            sections.append(formatted)
        elif isinstance(result, str):
            sections.append(format_tool_result(tool, result))
    
    return "\n\n---\n\n".join(sections) if sections else "No results to display"


# Quick test
if __name__ == "__main__":
    # Test formatting
    subs = ["a.example.com", "b.example.com", "c.example.com"]
    print(format_subdomains(subs, "example.com"))
    print()
    print(format_ports({"10.0.0.1": [22, 80, 443], "10.0.0.2": [80]}))
