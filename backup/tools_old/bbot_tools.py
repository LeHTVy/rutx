"""
BBOT Tools Module
BinaryEdge Bot (BBOT) - Recursive internet scanner
Provides advanced reconnaissance with modular scanning capabilities
"""

import subprocess
import json
import os
from datetime import datetime


def bbot_scan(target, modules=None, output_dir="/tmp/bbot_output", timeout=600):
    """
    Perform BBOT scan on target with specified modules.

    Args:
        target: Target domain, IP, or CIDR range
        modules: Comma-separated list of modules to use (e.g., "subdomain_enum,port_scan")
                If None, uses default safe modules
        output_dir: Directory to store scan results (default: /tmp/bbot_output)
        timeout: Timeout in seconds (default: 600 = 10 minutes)

    Returns:
        dict: Structured scan results
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Build command
        cmd = ["bbot", "-t", target, "-o", output_dir]

        if modules:
            cmd.extend(["-m", modules])
        else:
            # Default safe modules for reconnaissance
            cmd.extend(["-f", "safe"])

        # Add JSON output flag
        cmd.extend(["--json"])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        # Try to read JSON output file
        scan_data = {"findings": []}
        json_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]

        if json_files:
            json_path = os.path.join(output_dir, json_files[0])
            try:
                with open(json_path, 'r') as f:
                    scan_data = json.load(f)
            except:
                pass

        return {
            "success": True,
            "tool": "bbot_scan",
            "target": target,
            "modules": modules or "default_safe",
            "output_directory": output_dir,
            "scan_data": scan_data,
            "raw_output": result.stdout,
            "stderr": result.stderr if result.stderr else None,
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"BBOT scan timed out after {timeout} seconds",
            "target": target,
            "hint": "Consider increasing timeout or using more specific modules"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "bbot command not found. Please install BBOT first.",
            "install_hint": "Install: pipx install bbot or pip install bbot",
            "documentation": "https://github.com/blacklanternsecurity/bbot"
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "target": target
        }


def bbot_subdomain_enum(domain, passive=False, timeout=400):
    """
    Perform subdomain enumeration using BBOT's specialized modules.

    Args:
        domain: Target domain
        passive: Use only passive modules (default: False)
        timeout: Timeout in seconds (default: 400)

    Returns:
        dict: Subdomain enumeration results
    """
    try:
        output_dir = f"/tmp/bbot_subdomains_{domain.replace('.', '_')}"
        os.makedirs(output_dir, exist_ok=True)

        cmd = ["bbot", "-t", domain, "-o", output_dir]

        if passive:
            # Passive subdomain enumeration modules
            modules = "subdomains,certcheck,dnsbrute_targeted"
        else:
            # Active subdomain enumeration
            modules = "subdomains,subdomain_enum,certcheck,dnsbrute"

        cmd.extend(["-m", modules, "--json"])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        # Parse subdomains from output
        subdomains = []
        for line in result.stdout.split('\n'):
            if domain in line and line.strip():
                # Extract subdomain-like entries
                parts = line.split()
                for part in parts:
                    if domain in part and '.' in part:
                        subdomains.append(part.strip())

        subdomains = list(set(subdomains))  # Remove duplicates

        return {
            "success": True,
            "tool": "bbot_subdomain_enum",
            "domain": domain,
            "mode": "passive" if passive else "active",
            "subdomains_found": len(subdomains),
            "subdomains": subdomains,
            "raw_output": result.stdout,
            "output_directory": output_dir,
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"BBOT subdomain enumeration timed out after {timeout} seconds",
            "domain": domain
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "bbot command not found."
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "domain": domain
        }


def bbot_web_scan(target, timeout=400):
    """
    Perform web-focused reconnaissance using BBOT.

    Args:
        target: Target domain or IP
        timeout: Timeout in seconds (default: 400)

    Returns:
        dict: Web reconnaissance results
    """
    try:
        output_dir = f"/tmp/bbot_web_{target.replace('.', '_').replace('/', '_')}"
        os.makedirs(output_dir, exist_ok=True)

        # Web-focused modules
        modules = "httpx,wappalyzer,wayback,robots,spidering,ffuf_shortnames"

        cmd = ["bbot", "-t", target, "-o", output_dir, "-m", modules, "--json"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        return {
            "success": True,
            "tool": "bbot_web_scan",
            "target": target,
            "modules": modules,
            "raw_output": result.stdout,
            "output_directory": output_dir,
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"BBOT web scan timed out after {timeout} seconds",
            "target": target
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "bbot command not found."
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "target": target
        }


def bbot_quick_scan(target, timeout=300):
    """
    Perform quick reconnaissance scan using BBOT's fast modules.

    Args:
        target: Target domain, IP, or range
        timeout: Timeout in seconds (default: 300)

    Returns:
        dict: Quick scan results
    """
    try:
        output_dir = f"/tmp/bbot_quick_{target.replace('.', '_').replace('/', '_')}"
        os.makedirs(output_dir, exist_ok=True)

        # Quick, non-intrusive modules
        cmd = ["bbot", "-t", target, "-o", output_dir, "-f", "safe", "--json"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        return {
            "success": True,
            "tool": "bbot_quick_scan",
            "target": target,
            "raw_output": result.stdout,
            "output_directory": output_dir,
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"BBOT quick scan timed out after {timeout} seconds",
            "target": target
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "bbot command not found."
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "target": target
        }


# ============================================================================
# TOOL DEFINITIONS FOR OLLAMA
# ============================================================================

BBOT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "bbot_scan",
            "description": "Perform comprehensive BBOT reconnaissance scan with custom modules. Use for: 'advanced recon', 'bbot scan', 'recursive scan'. Supports various modules for deep reconnaissance.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target domain, IP, or CIDR range"
                    },
                    "modules": {
                        "type": "string",
                        "description": "Comma-separated list of BBOT modules (e.g., 'subdomain_enum,port_scan'). If not specified, uses safe defaults."
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Directory to store results (default: /tmp/bbot_output)"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 600)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bbot_subdomain_enum",
            "description": "Specialized subdomain enumeration using BBOT. Use for: 'find subdomains with bbot', 'enumerate subdomains bbot', 'bbot subdomain discovery'. More comprehensive than basic tools.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain for subdomain enumeration"
                    },
                    "passive": {
                        "type": "boolean",
                        "description": "Use only passive techniques (default: false)"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 400)"
                    }
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bbot_web_scan",
            "description": "Web-focused reconnaissance using BBOT. Use for: 'web recon', 'scan web technologies', 'identify web stack'. Discovers web technologies, endpoints, and vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target domain or IP address"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 400)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bbot_quick_scan",
            "description": "Quick BBOT scan with safe, non-intrusive modules. Use for: 'quick bbot scan', 'fast reconnaissance', 'safe scan'. Good for initial target assessment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target domain, IP, or range"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 300)"
                    }
                },
                "required": ["target"]
            }
        }
    }
]


# ============================================================================
# FUNCTION DISPATCHER
# ============================================================================

def execute_bbot_tool(tool_name, tool_args):
    """
    Execute a BBOT tool by name with given arguments

    Args:
        tool_name: Name of the tool function
        tool_args: Dictionary of arguments

    Returns:
        The result of the tool execution
    """
    tools_map = {
        "bbot_scan": bbot_scan,
        "bbot_subdomain_enum": bbot_subdomain_enum,
        "bbot_web_scan": bbot_web_scan,
        "bbot_quick_scan": bbot_quick_scan
    }

    if tool_name not in tools_map:
        return {
            "success": False,
            "error": f"Unknown BBOT tool '{tool_name}'"
        }

    try:
        func = tools_map[tool_name]
        result = func(**tool_args)
        return result
    except TypeError as e:
        return {
            "success": False,
            "error": f"Invalid arguments for {tool_name}: {e}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error executing {tool_name}: {e}"
        }
