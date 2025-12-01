"""
Naabu Tools Module
Fast port scanning using ProjectDiscovery's naabu

Features:
- Ultra-fast port scanning (faster than masscan for many use cases)
- Built-in DNS resolution
- Top ports detection
- Full port range scanning for crown jewels
"""

import subprocess
import tempfile
import os
import json
from datetime import datetime
from typing import List, Union, Dict, Any
from collections import defaultdict


def naabu_scan(
    targets: Union[str, List[str]],
    ports: str = "1-65535",
    rate: int = 5000,
    timeout: int = 600
) -> Dict[str, Any]:
    """
    Run naabu port scan on targets
    
    Args:
        targets: Single target or list of targets
        ports: Port range (e.g., "1-65535", "80,443", "top-1000")
        rate: Scan rate in packets/sec
        timeout: Timeout in seconds
    
    Returns:
        dict: Scan results with {IP: [ports]}
    """
    # Convert to list
    if isinstance(targets, str):
        targets = [targets]
    
    # Check if naabu is available
    try:
        subprocess.run(["naabu", "-version"], capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return {
            "success": False,
            "error": "naabu not found. Install with: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "targets": targets
        }
    
    # Write targets to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write('\n'.join(targets))
        targets_file = f.name
    
    # Output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = "/tmp/naabu_scans"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"naabu_{timestamp}.txt")
    
    try:
        # Build command
        cmd = [
            "naabu",
            "-list", targets_file,
            "-p", ports,
            "-rate", str(rate),
            "-o", output_file,
            "-silent",
            "-json"  # JSON output
        ]
        
        print(f"    Running: naabu -list {targets_file} -p {ports} -rate {rate}")
        
        import time
        start_time = time.time()
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        elapsed = time.time() - start_time
        
        if result.returncode != 0 and result.returncode != 1:  # 1 is OK (no results)
            return {
                "success": False,
                "error": f"naabu returned exit code {result.returncode}",
                "stderr": result.stderr,
                "targets": targets
            }
        
        # Parse JSON output
        port_results = defaultdict(list)
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        host = data.get('host') or data.get('ip')
                        port = data.get('port')
                        
                        if host and port:
                            port_results[host].append(port)
                    except json.JSONDecodeError:
                        # Try parsing as simple "host:port" format
                        if ':' in line:
                            parts = line.strip().rsplit(':', 1)
                            if len(parts) == 2:
                                host, port = parts
                                try:
                                    port_results[host].append(int(port))
                                except ValueError:
                                    pass
        
        # Build summary
        total_open_ports = sum(len(ports) for ports in port_results.values())
        targets_with_ports = len(port_results)
        
        return {
            "success": True,
            "tool": "naabu_scan",
            "targets": targets,
            "targets_count": len(targets),
            "output_file": output_file,
            "elapsed_seconds": round(elapsed, 2),
            "scan_rate": rate,
            "ports_scanned": ports,
            "results": dict(port_results),
            "targets_with_open_ports": targets_with_ports,
            "total_open_ports": total_open_ports,
            "command": ' '.join(cmd),
            "summary": f"Naabu: {targets_with_ports}/{len(targets)} targets with open ports, {total_open_ports} total ports found"
        }
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"naabu timed out after {timeout}s",
            "targets": targets
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "targets": targets
        }
    finally:
        # Cleanup
        try:
            os.unlink(targets_file)
        except:
            pass


def naabu_full_scan(targets: Union[str, List[str]], rate: int = 10000) -> Dict[str, Any]:
    """
    Scan ALL 65535 ports (for crown jewels)
    
    Args:
        targets: Crown jewel targets
        rate: Higher rate for faster scanning
    
    Returns:
        dict: Scan results
    """
    return naabu_scan(targets, ports="1-65535", rate=rate, timeout=1800)  # 30 min timeout


def naabu_top_ports(targets: Union[str, List[str]], top: int = 1000, rate: int = 5000) -> Dict[str, Any]:
    """
    Scan top N most common ports
    
    Args:
        targets: Targets to scan
        top: Number of top ports (100, 1000, etc.)
        rate: Scan rate
    
    Returns:
        dict: Scan results
    """
    # Naabu supports top-ports syntax
    return naabu_scan(targets, ports=f"top-{top}", rate=rate)


def naabu_web_ports(targets: Union[str, List[str]]) -> Dict[str, Any]:
    """
    Scan only web-related ports (fast check for web services)
    
    Args:
        targets: Targets to scan
    
    Returns:
        dict: Scan results
    """
    web_ports = "80,443,8000,8080,8443,8888,3000,5000,9000,9090,4443"
    return naabu_scan(targets, ports=web_ports, rate=10000)


def naabu_critical_ports(targets: Union[str, List[str]]) -> Dict[str, Any]:
    """
    Scan critical services ports (databases, RDP, SMB, etc.)

    Args:
        targets: Targets to scan

    Returns:
        dict: Scan results
    """
    critical_ports = "22,23,21,25,3389,445,139,1433,3306,5432,27017,6379,9200,9300"
    return naabu_scan(targets, ports=critical_ports, rate=5000)


def naabu_batch_scan(targets: str, ports: str = "1-65535", rate: int = 1000, timeout: int = None) -> Dict[str, Any]:
    """
    Batch scan multiple targets with Naabu (for medium/low priority targets)

    Args:
        targets: Comma-separated list of targets
        ports: Port range (default: 1-65535 for comprehensive)
        rate: Scan rate in packets/sec (default: 1000 for stealth)
        timeout: Timeout in seconds (default: auto-calculated based on targets/ports)

    Returns:
        dict: Scan results with all targets
    """
    # Convert comma-separated string to list
    target_list = [t.strip() for t in targets.split(",")]

    # Calculate dynamic timeout if not provided
    if timeout is None:
        # Calculate port count
        if "-" in ports:
            parts = ports.split("-")
            port_count = int(parts[1]) - int(parts[0]) + 1
        elif "," in ports:
            port_count = len(ports.split(","))
        elif ports.startswith("top-"):
            port_count = int(ports.split("-")[1])
        else:
            port_count = 1000  # Default estimate

        # Formula: (targets * ports / rate) * safety_factor
        # Safety factor accounts for DNS resolution, retries, network delays
        num_targets = len(target_list)

        # Higher safety factor for batch scans (many targets = more DNS lookups, retries)
        if num_targets > 100:
            safety_factor = 3.0  # Large batches need more overhead time
        elif num_targets > 50:
            safety_factor = 2.5
        else:
            safety_factor = 2.0

        estimated_time = (num_targets * port_count / rate) * safety_factor

        # Minimum 10 minutes, maximum 6 hours
        timeout = max(600, min(21600, int(estimated_time)))

        print(f"    ⏱️  Auto-calculated timeout: {timeout}s ({timeout//60} minutes) for {num_targets} targets")
        print(f"       Formula: {num_targets} targets × {port_count} ports / {rate} pps × {safety_factor}x safety")

    # Use the base naabu_scan function
    return naabu_scan(target_list, ports=ports, rate=rate, timeout=timeout)


# ============================================================================
# Tool Execution Wrapper
# ============================================================================

# ============================================================================
# TOOL DEFINITIONS FOR OLLAMA
# ============================================================================

NAABU_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "naabu_full_scan",
            "description": "Scan ALL 65535 ports on crown jewel targets (comprehensive deep scan). Use for: CRITICAL/HIGH-VALUE targets, 'comprehensive port scan', 'full port range'. Takes 2-5 minutes per target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Single target or comma-separated list of crown jewel targets"
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Scan rate in packets/sec (default: 10000)"
                    }
                },
                "required": ["targets"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "naabu_top_ports",
            "description": "Scan top N most common ports (default: 1000). Fast and comprehensive for most scenarios. Use for: medium-value targets, 'standard port scan', 'top ports'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Comma-separated list of targets"
                    },
                    "top": {
                        "type": "integer",
                        "description": "Number of top ports to scan (100, 1000, 10000)"
                    }
                },
                "required": ["targets"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "naabu_web_ports",
            "description": "Fast scan for web services only (HTTP/HTTPS variants). Use for: 'check web services', 'find web servers', quick web discovery.",
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
            "name": "naabu_critical_ports",
            "description": "Scan critical service ports (RDP, SMB, databases, etc.). Use for: 'check critical services', 'find security risks', critical port discovery.",
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
            "name": "naabu_batch_scan",
            "description": "Batch scan multiple targets with comprehensive port coverage. Use for: medium/low priority targets, batch subdomain scanning, large-scale port discovery. Scans all 65535 ports by default at stealthy rate (1000 pps). Timeout is auto-calculated based on number of targets and port range (typically 20-180 minutes for 100-200 targets).",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Comma-separated list of targets (IPs or domains)"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range (default: 1-65535). Options: '1-65535', 'top-1000', '80,443,8080'"
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Scan rate in packets/sec (default: 1000 for stealth, max: 10000)"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: auto-calculated based on targets/ports/rate). Override only if needed."
                    }
                },
                "required": ["targets"]
            }
        }
    }
]


def execute_naabu_tool(tool_name: str, tool_args: dict) -> dict:
    """
    Execute a naabu tool by name with given arguments
    
    Args:
        tool_name: Name of the tool function
        tool_args: Dictionary of arguments
    
    Returns:
        The result of the tool execution
    """
    # Map tool names to functions
    tools = {
        "naabu_scan": naabu_scan,
        "naabu_full_scan": naabu_full_scan,
        "naabu_top_ports": naabu_top_ports,
        "naabu_web_ports": naabu_web_ports,
        "naabu_critical_ports": naabu_critical_ports,
        "naabu_batch_scan": naabu_batch_scan,
    }
    
    if tool_name not in tools:
        return {
            "success": False,
            "error": f"Unknown naabu tool: {tool_name}"
        }
    
    # Get the function
    func = tools[tool_name]
    
    # Execute with arguments
    try:
        return func(**tool_args)
    except Exception as e:
        return {
            "success": False,
            "error": f"Tool execution error: {str(e)}",
            "tool": tool_name,
            "args": tool_args
        }


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    print("Testing Naabu Tools...")
    
    # Test with a single target
    test_target = "scanme.nmap.org"
    
    print(f"\n1. Testing top-100 ports on {test_target}...")
    result = naabu_top_ports(test_target, top=100)
    
    if result["success"]:
        print(f"   ✅ {result['summary']}")
        if result["results"]:
            for host, ports in result["results"].items():
                print(f"   {host}: {ports[:10]}" + (" ..." if len(ports) > 10 else ""))
    else:
        print(f"   ❌ {result['error']}")
    
    print("\n2. Testing web ports...")
    result = naabu_web_ports(test_target)
    
    if result["success"]:
        print(f"   ✅ {result['summary']}")
    else:
        print(f"   ❌ {result['error']}")
    
    print("\n✅ Naabu tools ready!")
