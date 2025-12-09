"""
Masscan Tools - LangChain Wrappers
Fast port scanning for batch operations
"""
import os
import sys
from typing import List, Union

# Ensure tools directory is in path
_rutx_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _rutx_root not in sys.path:
    sys.path.insert(0, _rutx_root)

from langchain_core.tools import tool
from tools.masscan_tools import (
    masscan_quick_scan as _masscan_quick_scan,
    masscan_batch_scan as _masscan_batch_scan,
    masscan_port_scan as _masscan_port_scan,
    masscan_web_scan as _masscan_web_scan
)


@tool
def masscan_quick(targets: str) -> dict:
    """
    Quick masscan on common ports (80, 443, 22, 8080, 8443, 3389).
    Very fast - scans at 1000 packets/sec.
    
    Args:
        targets: Comma-separated targets (IPs or hostnames) like "192.168.1.1,10.0.0.5"
    
    Returns:
        Dictionary with open ports per target
    """
    target_list = [t.strip() for t in targets.split(',')]
    return _masscan_quick_scan(target_list if len(target_list) > 1 else target_list[0])


@tool
def masscan_batch(targets: str) -> dict:
    """
    Optimized batch scan for many targets (10+ hosts).
    Uses higher scan rate (2000 pps) for speed.
    
    Args:
        targets: Comma-separated targets like "192.168.1.1,192.168.1.2,192.168.1.3"
    
    Returns:
        Dictionary with open ports per target
    """
    target_list = [t.strip() for t in targets.split(',')]
    return _masscan_batch_scan(target_list)


@tool
def masscan_ports(targets: str, ports: str) -> dict:
    """
    Scan specific ports on targets using masscan.
    
    Args:
        targets: Comma-separated targets like "192.168.1.1,10.0.0.5"
        ports: Port specification like "80,443" or "1-1000"
    
    Returns:
        Dictionary with open ports per target
    """
    target_list = [t.strip() for t in targets.split(',')]
    return _masscan_port_scan(target_list if len(target_list) > 1 else target_list[0], ports)


@tool
def masscan_web(targets: str) -> dict:
    """
    Scan only web-related ports (80, 443, 8080, 8443, 8000, 8888).
    
    Args:
        targets: Comma-separated targets like "192.168.1.1,10.0.0.5"
    
    Returns:
        Dictionary with open web ports per target
    """
    target_list = [t.strip() for t in targets.split(',')]
    return _masscan_web_scan(target_list if len(target_list) > 1 else target_list[0])


@tool
def masscan_scan_from_file(target_file: str = "", ports: str = "22,80,443,8080,8443", rate: int = 1000) -> str:
    """
    High-speed port scan from a file of targets using masscan -iL.
    FASTEST scanner for large target lists. Requires root privileges.
    Use when: user needs to scan many hosts very quickly.
    
    Args:
        target_file: Path to file with targets (one per line). If empty, uses latest subdomain file.
        ports: Ports to scan (default: common web/services ports)
        rate: Packets per second (default: 1000, max recommended: 10000)
    
    Returns:
        Scan results with open ports per target
    """
    from pathlib import Path
    from utils.command_runner import CommandRunner
    import shutil
    import json
    import tempfile
    
    # Find masscan executable
    masscan_path = shutil.which("masscan")
    if not masscan_path:
        for p in ["/usr/bin/masscan", "/usr/local/bin/masscan"]:
            if os.path.exists(p):
                masscan_path = p
                break
    
    if not masscan_path:
        return "Error: masscan not found. Install: sudo apt install masscan"
    
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
    
    print(f"  🎯 Scanning {len(targets)} targets with masscan (high-speed)")
    print(f"  🔌 Ports: {ports}")
    print(f"  ⚡ Rate: {rate} pps")
    
    # Create temp output file for JSON results
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
        output_file = tf.name
    
    # Build masscan command
    cmd = [
        masscan_path,
        "-iL", str(target_path),
        "-p", ports,
        "--rate", str(rate),
        "-oJ", output_file,
    ]
    
    print(f"  Running masscan...")
    
    result = CommandRunner.run(cmd, timeout=600, show_progress=True)
    
    # Parse JSON output file
    open_ports = {}
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                content = f.read().strip()
                # Masscan JSON can be array or NDJSON
                if content.startswith('['):
                    data = json.loads(content)
                else:
                    data = [json.loads(line) for line in content.split('\n') if line.strip()]
                
                for entry in data:
                    if isinstance(entry, dict):
                        ip = entry.get('ip', 'unknown')
                        for port_info in entry.get('ports', []):
                            port = port_info.get('port')
                            if ip and port:
                                if ip not in open_ports:
                                    open_ports[ip] = []
                                open_ports[ip].append(port)
    except Exception as e:
        print(f"  ⚠ Error parsing results: {e}")
    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)
    
    # Format output
    output = [
        f"🚀 Masscan Results: {len(targets)} targets, {len(open_ports)} with open ports",
        f"📌 Ports scanned: {ports}",
        f"⚡ Rate: {rate} pps",
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
MASSCAN_TOOLS = [masscan_quick, masscan_batch, masscan_ports, masscan_web, masscan_scan_from_file]
