"""
Amass Tools Module
OWASP Amass - In-depth attack surface mapping and asset discovery
Provides comprehensive subdomain enumeration and reconnaissance capabilities
"""

import subprocess
import json
import os
from datetime import datetime


def amass_enum(domain, passive=False, timeout=300):
    """
    Perform subdomain enumeration using Amass.

    Args:
        domain: Target domain to enumerate
        passive: Use passive reconnaissance only (default: False)
        timeout: Timeout in seconds (default: 300 = 5 minutes)

    Returns:
        dict: Structured result with subdomains found
    """
    try:
        # Build command
        cmd = ["amass", "enum", "-d", domain]

        if passive:
            cmd.append("-passive")

        # Add timeout to prevent hanging
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        # Parse output
        subdomains = []
        if result.stdout:
            subdomains = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

        return {
            "success": True,
            "tool": "amass_enum",
            "domain": domain,
            "mode": "passive" if passive else "active",
            "subdomains_found": len(subdomains),
            "subdomains": subdomains,
            "raw_output": result.stdout,
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Amass enumeration timed out after {timeout} seconds",
            "domain": domain
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "amass command not found. Please install Amass: https://github.com/owasp-amass/amass",
            "install_hint": "Install: sudo apt install amass (Debian/Ubuntu) or go install -v github.com/owasp-amass/amass/v4/...@master"
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "domain": domain
        }


def amass_intel(domain, whois=True, timeout=180):
    """
    Gather intelligence on a target domain using Amass intel module.

    Args:
        domain: Target domain
        whois: Include WHOIS information (default: True)
        timeout: Timeout in seconds (default: 180 = 3 minutes)

    Returns:
        dict: Intelligence data about the target
    """
    try:
        cmd = ["amass", "intel", "-d", domain]

        if whois:
            cmd.append("-whois")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        intel_data = []
        if result.stdout:
            intel_data = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

        return {
            "success": True,
            "tool": "amass_intel",
            "domain": domain,
            "intelligence_entries": len(intel_data),
            "data": intel_data,
            "raw_output": result.stdout,
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Amass intel timed out after {timeout} seconds",
            "domain": domain
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "amass command not found. Please install Amass first."
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "domain": domain
        }


def amass_db_list(domain=None):
    """
    List data in the Amass graph database.

    Args:
        domain: Optional domain to filter results

    Returns:
        dict: Database contents
    """
    try:
        cmd = ["amass", "db", "-list"]

        if domain:
            cmd.extend(["-d", domain])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False
        )

        db_entries = []
        if result.stdout:
            db_entries = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

        return {
            "success": True,
            "tool": "amass_db_list",
            "domain": domain or "all",
            "entries_found": len(db_entries),
            "entries": db_entries,
            "raw_output": result.stdout,
            "timestamp": datetime.now().isoformat()
        }

    except FileNotFoundError:
        return {
            "success": False,
            "error": "amass command not found."
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}"
        }


# ============================================================================
# TOOL DEFINITIONS FOR OLLAMA
# ============================================================================

AMASS_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "amass_enum",
            "description": "Perform comprehensive subdomain enumeration using OWASP Amass. Use for: 'find subdomains', 'enumerate subdomains', 'discover assets', 'map attack surface'. Discovers subdomains through active and passive techniques.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain to enumerate (e.g., 'example.com')"
                    },
                    "passive": {
                        "type": "boolean",
                        "description": "Use passive reconnaissance only (no direct probing) - default: false"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 300)"
                    }
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "amass_intel",
            "description": "Gather intelligence on target domain using Amass intel module. Use for: 'gather intel', 'domain intelligence', 'WHOIS lookup', 'reconnaissance'. Collects organizational and infrastructure data.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain for intelligence gathering"
                    },
                    "whois": {
                        "type": "boolean",
                        "description": "Include WHOIS information - default: true"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 180)"
                    }
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "amass_db_list",
            "description": "List historical data from Amass graph database. Use for: 'check amass history', 'list previous scans', 'database query'. Shows previously discovered assets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Optional domain to filter database results"
                    }
                },
                "required": []
            }
        }
    }
]


# ============================================================================
# FUNCTION DISPATCHER
# ============================================================================

def execute_amass_tool(tool_name, tool_args):
    """
    Execute an Amass tool by name with given arguments

    Args:
        tool_name: Name of the tool function
        tool_args: Dictionary of arguments

    Returns:
        The result of the tool execution
    """
    tools_map = {
        "amass_enum": amass_enum,
        "amass_intel": amass_intel,
        "amass_db_list": amass_db_list
    }

    if tool_name not in tools_map:
        return {
            "success": False,
            "error": f"Unknown Amass tool '{tool_name}'"
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
