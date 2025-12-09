"""
SNODE LangChain - Nmap Tools
Wrapped security scanning tools for LangChain agent
"""
from langchain_core.tools import tool
import sys
import os

# Add rutx root to path for importing original tools
_rutx_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _rutx_root not in sys.path:
    sys.path.insert(0, _rutx_root)

from tools.nmap_tools import (
    nmap_scan,
    nmap_quick_scan as _nmap_quick_scan,
    nmap_service_detection as _nmap_service_detection,
    nmap_vuln_scan as _nmap_vuln_scan,
    nmap_port_scan as _nmap_port_scan,
)


def _format_port_results(result: dict) -> str:
    """Format nmap results for LLM consumption"""
    if not result.get("success"):
        return f"Scan failed: {result.get('error', 'Unknown error')}"
    
    output_lines = [
        f"Target: {result.get('target')}",
        f"Hosts discovered: {result.get('hosts_discovered', 0)}",
        f"Open ports: {result.get('open_ports_count', 0)}",
        ""
    ]
    
    for port in result.get("open_ports", []):
        if port.get("state") == "open":
            output_lines.append(
                f"  • Port {port['port']}/{port['protocol']}: {port.get('service', 'unknown')}"
            )
    
    return "\n".join(output_lines)


@tool
def nmap_quick_scan(target: str) -> str:
    """
    Quick port scan on top 100 most common ports.
    Use when: user wants a fast scan, initial recon, or quick check.
    Takes about 30 seconds.
    
    Args:
        target: IP address or hostname to scan
    
    Returns:
        List of open ports and services found
    """
    result = _nmap_quick_scan(target)
    return _format_port_results(result)


@tool
def nmap_service_detection(target: str, ports: str = "") -> str:
    """
    Detect service versions on open ports.
    Use when: user asks about services, versions, or what's running on ports.
    More detailed than quick scan.
    
    Args:
        target: IP address or hostname to scan
        ports: Optional specific ports (e.g., "80,443" or "1-1000")
    
    Returns:
        Detailed service information for each open port
    """
    result = _nmap_service_detection(target, ports)
    return _format_port_results(result)


@tool
def nmap_vuln_scan(target: str) -> str:
    """
    Scan for vulnerabilities using Nmap NSE scripts.
    Use when: user asks about vulnerabilities, CVEs, or security issues.
    Takes 5-10 minutes.
    
    Args:
        target: IP address or hostname to scan
    
    Returns:
        Vulnerabilities and CVEs found
    """
    result = _nmap_vuln_scan(target)
    
    if not result.get("success"):
        return f"Vulnerability scan failed: {result.get('error', 'Unknown error')}"
    
    output = result.get("output", "")
    
    # Extract CVE mentions
    import re
    cves = re.findall(r'CVE-\d{4}-\d+', output)
    
    summary = [
        f"Target: {result.get('target')}",
        f"CVEs found: {len(set(cves))}",
        ""
    ]
    
    if cves:
        summary.append("Vulnerabilities:")
        for cve in sorted(set(cves)):
            summary.append(f"  • {cve}")
    else:
        summary.append("No known CVEs detected.")
    
    return "\n".join(summary)


@tool
def nmap_port_scan(target: str, ports: str) -> str:
    """
    Scan specific ports on a target.
    Use when: user specifies exact ports like "check port 22" or "scan 80,443".
    
    Args:
        target: IP address or hostname to scan
        ports: Port specification (e.g., "22", "80,443", "1-1000")
    
    Returns:
        Status of specified ports
    """
    result = _nmap_port_scan(target, ports)
    return _format_port_results(result)


@tool
def nmap_scan_from_file(target_file: str = "", ports: str = "22,80,443,3389,8080,8443") -> str:
    """
    Scan multiple targets from a file using nmap -iL.
    BEST for scanning subdomain lists. Efficient batch scanning.
    Use when: user says "port scan these subdomains" or "scan the discovered hosts".
    
    Args:
        target_file: Path to file with targets (one per line). If empty, uses latest subdomain file.
        ports: Ports to scan (default: common web/services ports)
    
    Returns:
        Aggregated scan results for all targets
    """
    from pathlib import Path
    from utils.command_runner import CommandRunner
    
    # If no file specified, use latest subdomain discovery
    if not target_file:
        from snode_langchain.state import get_subdomain_file
        subdomain_file = get_subdomain_file()
        if subdomain_file and subdomain_file.exists():
            target_file = str(subdomain_file)
            print(f"  📁 Using subdomain file: {target_file}")
        else:
            return "Error: No target file specified and no recent subdomain discoveries found."
    
    target_path = Path(target_file)
    if not target_path.exists():
        return f"Error: Target file not found: {target_file}"
    
    # Count targets
    with open(target_path, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    print(f"  🎯 Scanning {len(targets)} targets from file")
    print(f"  🔌 Ports: {ports}")
    
    # Build nmap command: quiet, fast, no DNS resolution
    cmd = [
        "nmap",
        "-iL", str(target_path),
        "-p", ports,
        "-sS",           # TCP SYN scan (fast, stealthy)
        "-n",            # No DNS resolution (faster)
        "-T4",           # Faster timing
        "--open",        # Only show open ports
        "-oG", "-",      # Grepable output to stdout
    ]
    
    print(f"  Running: {' '.join(cmd[:6])}...")
    
    result = CommandRunner.run(cmd, timeout=1800, show_progress=True)
    
    if not result.success:
        return f"Scan failed: {result.error or result.stderr}"
    
    # Parse grepable output
    open_ports = {}
    for line in result.stdout.split('\n'):
        if 'Ports:' in line and 'Host:' in line:
            # Parse: Host: 1.2.3.4 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
            parts = line.split('Ports:')
            if len(parts) >= 2:
                host_part = parts[0].replace('Host:', '').strip().split()[0]
                ports_part = parts[1].strip()
                
                port_list = []
                for port_info in ports_part.split(','):
                    port_info = port_info.strip()
                    if '/open/' in port_info:
                        p = port_info.split('/')[0]
                        service = port_info.split('/')[4] if len(port_info.split('/')) > 4 else 'unknown'
                        port_list.append(f"{p}/{service}")
                
                if port_list:
                    open_ports[host_part] = port_list
    
    # Format output
    output = [
        f"📊 Scan Results: {len(targets)} targets, {len(open_ports)} with open ports",
        f"📌 Ports scanned: {ports}",
        ""
    ]
    
    if open_ports:
        output.append("🔓 Open Ports Found:")
        for host, ports_list in sorted(open_ports.items()):
            output.append(f"  {host}:")
            for p in ports_list:
                output.append(f"    • {p}")
    else:
        output.append("No open ports found on scanned targets.")
    
    output.append(f"\n⏱ Scan time: {result.elapsed_time:.1f}s")
    
    return '\n'.join(output)


# Export all tools
NMAP_TOOLS = [
    nmap_quick_scan,
    nmap_service_detection,
    nmap_vuln_scan,
    nmap_port_scan,
    nmap_scan_from_file,
]
