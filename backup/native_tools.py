"""
Native Tools - Wrappers for LLM to call unified tool runner
All tools run with native output formats and save to JSON
"""

from rutx.backup.unified_tool_runner import (
    run_nmap_native,
    run_amass_native,
    run_bbot_native,
    run_shodan_native,
    read_tool_output,
    list_scan_results
)


# ============================================================================
# NMAP NATIVE TOOLS
# ============================================================================

def nmap_quick_native(target):
    """Quick Nmap scan with native JSON output"""
    return run_nmap_native(target, scan_type="quick")


def nmap_aggressive_native(target):
    """Aggressive Nmap scan (-A) with native JSON output"""
    return run_nmap_native(target, scan_type="aggressive")


def nmap_vuln_native(target):
    """Vulnerability scan with native JSON output"""
    return run_nmap_native(target, scan_type="vuln")


def nmap_service_native(target, ports=None):
    """Service version detection with native JSON output"""
    return run_nmap_native(target, scan_type="service", ports=ports)


def nmap_comprehensive_native(target):
    """Comprehensive scan with all features"""
    return run_nmap_native(target, scan_type="comprehensive")


# ============================================================================
# AMASS NATIVE TOOLS
# ============================================================================

def amass_enum_native(domain, passive=False):
    """Amass subdomain enumeration with native JSON output"""
    return run_amass_native(domain, mode="enum", passive=passive)


def amass_intel_native(domain):
    """Amass intelligence gathering with native JSON output"""
    return run_amass_native(domain, mode="intel")


# ============================================================================
# BBOT NATIVE TOOLS
# ============================================================================

def bbot_subdomain_native(target):
    """BBOT subdomain enumeration with native JSON output"""
    return run_bbot_native(target, preset="subdomain-enum")


def bbot_web_native(target):
    """BBOT web reconnaissance with native JSON output"""
    return run_bbot_native(target, preset="web-basic")


def bbot_comprehensive_native(target):
    """BBOT comprehensive scan with native JSON output"""
    return run_bbot_native(target, modules="subdomain-enum,httpx,wappalyzer,wayback")


# ============================================================================
# SHODAN NATIVE TOOLS
# ============================================================================

def shodan_host_native(ip):
    """Shodan host lookup with native JSON output"""
    return run_shodan_native(ip, lookup_type="host")


def shodan_search_native(query):
    """Shodan search with native JSON output"""
    return run_shodan_native(query, lookup_type="search")


# ============================================================================
# FILE MANAGEMENT TOOLS
# ============================================================================

def read_scan_file(filename):
    """Read a scan result JSON file"""
    from unified_tool_runner import SCAN_OUTPUT_DIR
    import os
    file_path = os.path.join(SCAN_OUTPUT_DIR, filename)
    return read_tool_output(file_path)


def list_scan_files(tool_name=None):
    """List available scan result files"""
    return list_scan_results(tool_name=tool_name)


# ============================================================================
# TOOL DEFINITIONS FOR OLLAMA (LLM)
# ============================================================================

NATIVE_TOOLS = [
    # NMAP TOOLS
    {
        "type": "function",
        "function": {
            "name": "nmap_quick_native",
            "description": "Quick Nmap scan (top 100 ports, fast). Runs like terminal command, saves JSON. Use for: 'quick scan', 'fast nmap', 'check if host is up'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP/hostname"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_aggressive_native",
            "description": "Aggressive Nmap scan (-A: OS, version, scripts, traceroute). Terminal-style execution, JSON output. Use for: 'detailed scan', 'identify OS', 'aggressive scan'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP/hostname"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_vuln_native",
            "description": "Nmap vulnerability scan with NSE vuln scripts. Terminal-style, JSON output. Use for: 'find vulnerabilities', 'vuln scan', 'security audit'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP/hostname"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_service_native",
            "description": "Service version detection scan. Terminal-style, JSON output. Use for: 'detect services', 'version scan', 'identify software'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP/hostname"},
                    "ports": {"type": "string", "description": "Optional: specific ports (e.g., '80,443,8080')"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_comprehensive_native",
            "description": "Comprehensive Nmap scan (all features: vuln, version, OS, scripts). Long-running, JSON output. Use for: 'complete scan', 'full analysis', 'thorough check'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP/hostname"}
                },
                "required": ["target"]
            }
        }
    },

    # AMASS TOOLS
    {
        "type": "function",
        "function": {
            "name": "amass_enum_native",
            "description": "Amass subdomain enumeration. Terminal-style, native JSON output. Use for: 'find subdomains', 'enumerate domains', 'discover assets'. Takes 5-10 minutes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain (e.g., 'example.com')"},
                    "passive": {"type": "boolean", "description": "Passive mode only (default: false)"}
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "amass_intel_native",
            "description": "Amass intelligence gathering (WHOIS, ASN, etc.). Native JSON output. Use for: 'domain intel', 'org info', 'WHOIS lookup'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain"}
                },
                "required": ["domain"]
            }
        }
    },

    # BBOT TOOLS
    {
        "type": "function",
        "function": {
            "name": "bbot_subdomain_native",
            "description": "BBOT advanced subdomain enumeration. Terminal-style, native JSON. Use for: 'comprehensive subdomain discovery', 'bbot enum'. Takes 5-15 minutes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target domain"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bbot_web_native",
            "description": "BBOT web reconnaissance (technologies, endpoints). Native JSON output. Use for: 'web scan', 'identify stack', 'find endpoints'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target domain/IP"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bbot_comprehensive_native",
            "description": "BBOT comprehensive reconnaissance (subdomains + web + tech). Long-running, JSON output. Use for: 'full bbot scan', 'complete recon'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target domain"}
                },
                "required": ["target"]
            }
        }
    },

    # SHODAN TOOLS
    {
        "type": "function",
        "function": {
            "name": "shodan_host_native",
            "description": "Shodan host lookup (fast, returns JSON). Use for: 'check IP', 'shodan lookup', 'threat intel'. Usually completes in <5 seconds.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Target IP address"}
                },
                "required": ["ip"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "shodan_search_native",
            "description": "Shodan search query (returns JSON). Use for: 'search shodan', 'find targets', 'query database'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Shodan search query"}
                },
                "required": ["query"]
            }
        }
    },

    # FILE MANAGEMENT
    {
        "type": "function",
        "function": {
            "name": "read_scan_file",
            "description": "Read a saved scan result JSON file for detailed analysis. Use when you need to analyze full scan data.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Filename (e.g., 'nmap_192_168_1_1_20250121_150322.json')"}
                },
                "required": ["filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_scan_files",
            "description": "List available scan result files. Use to see what scans have been run.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string", "description": "Optional: filter by tool (nmap/amass/bbot/shodan)"}
                },
                "required": []
            }
        }
    }
]


# ============================================================================
# FUNCTION DISPATCHER
# ============================================================================

def execute_native_tool(tool_name, tool_args):
    """Execute a native tool by name"""
    tools_map = {
        "nmap_quick_native": nmap_quick_native,
        "nmap_aggressive_native": nmap_aggressive_native,
        "nmap_vuln_native": nmap_vuln_native,
        "nmap_service_native": nmap_service_native,
        "nmap_comprehensive_native": nmap_comprehensive_native,
        "amass_enum_native": amass_enum_native,
        "amass_intel_native": amass_intel_native,
        "bbot_subdomain_native": bbot_subdomain_native,
        "bbot_web_native": bbot_web_native,
        "bbot_comprehensive_native": bbot_comprehensive_native,
        "shodan_host_native": shodan_host_native,
        "shodan_search_native": shodan_search_native,
        "read_scan_file": read_scan_file,
        "list_scan_files": list_scan_files
    }

    if tool_name not in tools_map:
        return {"error": f"Unknown tool: {tool_name}"}

    try:
        return tools_map[tool_name](**tool_args)
    except TypeError as e:
        return {"error": f"Invalid arguments for {tool_name}: {e}"}
    except Exception as e:
        return {"error": f"Error executing {tool_name}: {e}"}
