"""
Masscan Tools Module
Fast port scanning for batch operations on multiple targets
Optimized for scanning large numbers of subdomains efficiently
"""

import subprocess
import json
import os
import re
from datetime import datetime
from typing import List, Union, Dict, Any


def _resolve_hostname_to_ip(hostname: str) -> str:
    """
    Resolve hostname to IP address for masscan (masscan requires IPs).
    
    Args:
        hostname: Hostname or IP address
    
    Returns:
        str: IP address or original hostname if resolution fails
    """
    import socket
    
    # Check if already an IP
    try:
        socket.inet_aton(hostname)
        return hostname  # Already an IP
    except socket.error:
        pass  # Not an IP, try to resolve
    
    # Try to resolve hostname to IP
    try:
        ip = socket.gethostbyname(hostname)
        print(f"    [DNS] Resolved {hostname} → {ip}")
        return ip
    except socket.gaierror:
        print(f"    [DNS] Warning: Could not resolve {hostname}, using as-is")
        return hostname


def masscan_scan(
    targets: Union[str, List[str]],
    ports: str = "80,443,8080,8443,22,21,25,3389",
    rate: int = 1000,
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Run masscan on specified targets with given ports.
    
    Args:
        targets: Single target or list of targets (IPs or hostnames)
        ports: Port specification (e.g., "80,443" or "1-1000")
        rate: Scan rate in packets/sec (default: 1000)
        timeout: Timeout in seconds (default: 300 = 5 minutes)
    
    Returns:
        dict: Structured scan result with targets and open ports
    """
    import time
    
    # Convert targets to list if single string
    if isinstance(targets, str):
        targets = [targets]
    
    # Resolve hostnames to IPs (masscan requires IPs)
    original_targets = targets.copy()
    resolved_targets = []
    hostname_to_ip = {}  # Track mapping for reporting
    
    for target in targets:
        ip = _resolve_hostname_to_ip(target)
        resolved_targets.append(ip)
        if ip != target:
            hostname_to_ip[target] = ip
    
    targets = resolved_targets
    
    # Generate output file path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = "/tmp/masscan_scans"
    os.makedirs(output_dir, exist_ok=True)
    
    json_output = os.path.join(output_dir, f"masscan_{timestamp}.json")
    
    # Build command
    # Masscan accepts multiple targets separated by commas
    targets_str = ",".join(targets)
    
    cmd_parts = [
        "masscan",
        targets_str,
        "-p", ports,
        "--rate", str(rate),
        "-oJ", json_output
    ]
    
    try:
        start_time = time.time()
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        elapsed = time.time() - start_time
        
        if result.returncode != 0:
            return {
                "success": False,
                "error": f"Masscan returned exit code {result.returncode}",
                "stderr": result.stderr,
                "stdout": result.stdout,
                "targets": targets
            }
        
        # Parse JSON output
        scan_results = {}
        try:
            with open(json_output, 'r') as f:
                # Masscan JSON is not valid JSON array, it's line-delimited JSON objects
                # We need to parse it line by line
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if not line or line in ['{', '}', '[', ']']:
                        continue
                    # Remove trailing comma if present
                    if line.endswith(','):
                        line = line[:-1]
                    try:
                        obj = json.loads(line)
                        ip = obj.get('ip')
                        port_info = obj.get('ports', [])
                        
                        if ip:
                            if ip not in scan_results:
                                scan_results[ip] = []
                            
                            # Port info is a list
                            if isinstance(port_info, list):
                                for port_obj in port_info:
                                    scan_results[ip].append({
                                        'port': port_obj.get('port'),
                                        'protocol': port_obj.get('proto', 'tcp'),
                                        'state': port_obj.get('status', 'open')
                                    })
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            # No output file means no results
            scan_results = {}
        
        # Build summary
        total_open_ports = sum(len(ports) for ports in scan_results.values())
        targets_with_ports = len(scan_results)
        
        return {
            "success": True,
            "tool": "masscan_scan",
            "targets": original_targets,  # Original hostnames
            "resolved_targets": targets,  # Resolved IPs
            "hostname_to_ip": hostname_to_ip,  # DNS mapping
            "targets_count": len(original_targets),
            "output_json": json_output,
            "output": result.stdout,
            "elapsed_seconds": round(elapsed, 2),
            "scan_rate": rate,
            "ports_scanned": ports,
            "results": scan_results,
            "targets_with_open_ports": targets_with_ports,
            "total_open_ports": total_open_ports,
            "command": ' '.join(cmd_parts),
            "summary": f"Masscan: {targets_with_ports}/{len(original_targets)} targets with open ports, {total_open_ports} total ports found",
            "timestamp": datetime.now().isoformat()
        }
        
    except subprocess.TimeoutExpired:
        timeout_mins = timeout // 60
        return {
            "success": False,
            "error": f"Masscan timed out after {timeout_mins} minutes",
            "targets": targets
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "masscan command not found. Please install masscan first.",
            "targets": targets
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "targets": targets
        }


def masscan_quick_scan(targets: Union[str, List[str]]) -> Dict[str, Any]:
    """
    Quick masscan on common ports (web + SSH + RDP).
    Uses balanced scan rate (1000 pps).
    
    Args:
        targets: Single target or list of targets
    
    Returns:
        dict: Structured scan result
    """
    return masscan_scan(
        targets=targets,
        ports="80,443,8080,8443,22,3389",
        rate=1000
    )


def masscan_batch_scan(targets: Union[str, List[str]]) -> Dict[str, Any]:
    """
    Optimized batch scan for many targets (10+ subdomains).
    Uses higher scan rate for speed.
    
    Args:
        targets: List of targets to scan
    
    Returns:
        dict: Structured scan result
    """
    return masscan_scan(
        targets=targets,
        ports="80,443,8080,8443,22,21,25,3389,3306,5432,1433",
        rate=10000  # Fast rate for batch operations
    )


def masscan_port_scan(targets: Union[str, List[str]], ports: str) -> Dict[str, Any]:
    """
    Scan specific ports on targets.
    
    Args:
        targets: Single target or list of targets
        ports: Port specification (e.g., "80,443" or "1-1000")
    
    Returns:
        dict: Structured scan result
    """
    return masscan_scan(
        targets=targets,
        ports=ports,
        rate=1000
    )


def masscan_web_scan(targets: Union[str, List[str]]) -> Dict[str, Any]:
    """
    Scan only web-related ports.
    
    Args:
        targets: Single target or list of targets
    
    Returns:
        dict: Structured scan result
    """
    return masscan_scan(
        targets=targets,
        ports="80,443,8080,8443,8000,8888,9000",
        rate=5000
    )


# ============================================================================
# TOOL DEFINITIONS FOR OLLAMA
# ============================================================================

MASSCAN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "masscan_quick_scan",
            "description": "Fast port scan on common ports (web, SSH, RDP) using masscan. Best for: 'quick scan multiple targets', 'fast batch scan'. Can scan 10+ targets in seconds.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Single target or comma-separated list of targets (IPs or hostnames)"
                    }
                },
                "required": ["targets"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "masscan_batch_scan",
            "description": "Optimized batch scan for many subdomains (10+). Scans common service ports at high speed. Use for: 'scan these subdomains', 'batch port scan', 'scan all targets'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Comma-separated list of targets to scan"
                    }
                },
                "required": ["targets"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "masscan_port_scan",
            "description": "Scan specific ports on multiple targets. Use for: 'check port 80 on these targets', 'scan ports 1-1000'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Single target or comma-separated list"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification: '80,443' or '1-1000'"
                    }
                },
                "required": ["targets", "ports"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "masscan_web_scan",
            "description": "Scan only web-related ports (HTTP/HTTPS variants). Fast web service discovery on multiple targets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Comma-separated list of targets"
                    }
                },
                "required": ["targets"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "masscan_scan",
            "description": "Custom masscan with any ports and scan rate. Use ONLY when other masscan tools don't fit. Advanced users only.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Comma-separated list of targets"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification"
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Scan rate in packets/sec (default: 1000)"
                    }
                },
                "required": ["targets"]
            }
        }
    }
]


# ============================================================================
# FUNCTION DISPATCHER
# ============================================================================

def execute_masscan_tool(tool_name: str, tool_args: dict) -> Dict[str, Any]:
    """
    Execute a masscan tool by name with given arguments
    
    Args:
        tool_name: Name of the tool function
        tool_args: Dictionary of arguments
    
    Returns:
        The result of the tool execution
    """
    tools_map = {
        "masscan_scan": masscan_scan,
        "masscan_quick_scan": masscan_quick_scan,
        "masscan_batch_scan": masscan_batch_scan,
        "masscan_port_scan": masscan_port_scan,
        "masscan_web_scan": masscan_web_scan
    }
    
    if tool_name not in tools_map:
        return {"error": f"Unknown tool '{tool_name}'"}
    
    try:
        func = tools_map[tool_name]
        
        # Handle targets argument - convert string to list if needed
        if 'targets' in tool_args and isinstance(tool_args['targets'], str):
            # Split comma-separated targets
            tool_args['targets'] = [t.strip() for t in tool_args['targets'].split(',')]
        
        result = func(**tool_args)
        return result
    except TypeError as e:
        return {"error": f"Invalid arguments for {tool_name}: {e}"}
    except Exception as e:
        return {"error": f"Error executing {tool_name}: {e}"}
