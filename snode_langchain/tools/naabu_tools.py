"""
Naabu Tools - LangChain Wrappers
Ultra-fast port scanning using ProjectDiscovery's naabu
"""
import os
import sys
from typing import List, Union

# Ensure tools directory is in path
_rutx_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _rutx_root not in sys.path:
    sys.path.insert(0, _rutx_root)

from langchain_core.tools import tool
from tools.naabu_tools import (
    naabu_full_scan as _naabu_full_scan,
    naabu_top_ports as _naabu_top_ports,
    naabu_web_ports as _naabu_web_ports,
    naabu_critical_ports as _naabu_critical_ports,
    naabu_batch_scan as _naabu_batch_scan
)


@tool
def naabu_full(targets: str) -> dict:
    """
    Full port scan (ALL 65535 ports) using naabu.
    Use for high-value targets where you need complete coverage.
    Very fast - 10000 packets/sec.
    
    Args:
        targets: Comma-separated targets like "192.168.1.1,10.0.0.5"
    
    Returns:
        Dictionary with all open ports per target
    """
    target_list = [t.strip() for t in targets.split(',')]
    return _naabu_full_scan(target_list if len(target_list) > 1 else target_list[0])


@tool
def naabu_top(targets: str, top: int = 1000) -> dict:
    """
    Scan top N most common ports using naabu.
    
    Args:
        targets: Comma-separated targets like "192.168.1.1,10.0.0.5"
        top: Number of top ports to scan (100, 1000, etc.)
    
    Returns:
        Dictionary with open ports per target
    """
    target_list = [t.strip() for t in targets.split(',')]
    return _naabu_top_ports(target_list if len(target_list) > 1 else target_list[0], top=top)


@tool
def naabu_web(targets: str) -> dict:
    """
    Scan only web-related ports using naabu.
    Fast check for web services.
    
    Args:
        targets: Comma-separated targets like "192.168.1.1,10.0.0.5"
    
    Returns:
        Dictionary with open web ports per target
    """
    target_list = [t.strip() for t in targets.split(',')]
    return _naabu_web_ports(target_list if len(target_list) > 1 else target_list[0])


@tool
def naabu_critical(targets: str) -> dict:
    """
    Scan critical service ports (databases, RDP, SMB, SSH, etc.).
    Use to find high-value services quickly.
    
    Args:
        targets: Comma-separated targets like "192.168.1.1,10.0.0.5"
    
    Returns:
        Dictionary with open critical ports per target
    """
    target_list = [t.strip() for t in targets.split(',')]
    return _naabu_critical_ports(target_list if len(target_list) > 1 else target_list[0])


@tool
def naabu_batch(targets: str, ports: str = "top-1000") -> dict:
    """
    Batch scan multiple targets with naabu.
    Good for scanning many hosts efficiently.
    
    Args:
        targets: Comma-separated targets like "192.168.1.1,192.168.1.2,192.168.1.3"
        ports: Port range like "1-65535", "80,443", or "top-1000"
    
    Returns:
        Dictionary with open ports per target
    """
    target_list = [t.strip() for t in targets.split(',')]
    return _naabu_batch_scan(target_list, ports=ports)


@tool
def naabu_scan_from_file(target_file: str = "", ports: str = "22,80,443,8080,8443") -> str:
    """
    Ultra-fast port scan from a file of targets using naabu -list.
    BEST for scanning subdomain lists. Much faster than nmap.
    Use when: user says "port scan these subdomains" or "fast scan discovered hosts".
    
    Args:
        target_file: Path to file with targets (one per line). If empty, uses latest subdomain file.
        ports: Ports to scan (default: common web/services ports)
    
    Returns:
        Scan results with open ports per target
    """
    from pathlib import Path
    from utils.command_runner import CommandRunner
    import shutil
    
    # Find naabu executable
    naabu_path = shutil.which("naabu")
    if not naabu_path:
        home = os.path.expanduser("~")
        for p in [f"{home}/go/bin/naabu", "/home/hellrazor/go/bin/naabu"]:
            if os.path.exists(p):
                naabu_path = p
                break
    
    if not naabu_path:
        return "Error: naabu not found. Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    
    # If no file specified, use latest subdomain discovery
    if not target_file:
        try:
            from snode_langchain.state import get_subdomain_file
            subdomain_file = get_subdomain_file()
            if subdomain_file and subdomain_file.exists():
                target_file = str(subdomain_file)
                print(f"  📁 Using subdomain file: {target_file}")
            else:
                return "Error: No target file specified and no recent subdomain discoveries found."
        except Exception as e:
            return f"Error loading subdomain file: {e}"
    
    target_path = Path(target_file)
    if not target_path.exists():
        return f"Error: Target file not found: {target_file}"
    
    # Count targets
    with open(target_path, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    print(f"  🎯 Scanning {len(targets)} targets with naabu (ultra-fast)")
    print(f"  🔌 Ports: {ports}")
    
    # Build naabu command
    cmd = [
        naabu_path,
        "-list", str(target_path),
        "-p", ports,
        "-silent",
        "-json",
    ]
    
    print(f"  Running naabu...")
    
    result = CommandRunner.run(cmd, timeout=600, show_progress=True)
    
    if not result.success:
        return f"Scan failed: {result.error or result.stderr}"
    
    # Parse JSON output (one JSON object per line)
    import json
    open_ports = {}
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            host = data.get('host', data.get('ip', 'unknown'))
            port = data.get('port')
            if host and port:
                if host not in open_ports:
                    open_ports[host] = []
                open_ports[host].append(port)
        except json.JSONDecodeError:
            continue
    
    # Format output
    output = [
        f"⚡ Naabu Scan Results: {len(targets)} targets, {len(open_ports)} with open ports",
        f"📌 Ports scanned: {ports}",
        ""
    ]
    
    if open_ports:
        output.append("🔓 Open Ports Found:")
        for host, ports_list in sorted(open_ports.items()):
            output.append(f"  {host}: {', '.join(map(str, sorted(ports_list)))}")
    else:
        output.append("No open ports found on scanned targets.")
    
    output.append(f"\n⏱ Scan time: {result.elapsed_time:.1f}s")
    
    return '\n'.join(output)


# Export all tools
NAABU_TOOLS = [naabu_full, naabu_top, naabu_web, naabu_critical, naabu_batch, naabu_scan_from_file]
