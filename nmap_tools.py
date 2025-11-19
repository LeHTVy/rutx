"""
Nmap Tools Module
Comprehensive nmap scanning functions for network reconnaissance
Supports most common nmap use cases and options
"""

import subprocess
import shlex
import socket
import re


def get_local_network_info():
    """
    Get local network information including IP addresses, subnet masks, and network ranges for scanning.

    Returns:
        dict: Contains hostname, primary_ip, all_ips, interfaces, and scan_ranges
    """
    try:
        hostname = socket.gethostname()

        # Get primary IP by connecting to a public DNS server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
        except:
            primary_ip = "Unable to determine"

        # Get all IPs associated with hostname
        try:
            all_ips = socket.gethostbyname_ex(hostname)[2]
        except:
            all_ips = []

        interface_info = []
        scan_ranges = []

        # Try to get network interface information (Windows-specific)
        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_interface = None

                for line in lines:
                    # Detect adapter name
                    if 'adapter' in line.lower():
                        current_interface = line.strip().rstrip(':')

                    # Look for IPv4 Address
                    if 'IPv4 Address' in line and current_interface:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match and not ip_match.group(1).startswith('127.'):
                            ip_addr = ip_match.group(1)
                            interface_info.append(f"{current_interface}: {ip_addr}")

                            # Suggest /24 network
                            octets = ip_addr.split('.')
                            if len(octets) == 4:
                                network_base = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                                if network_base not in scan_ranges:
                                    scan_ranges.append(network_base)
        except:
            pass

        # Fallback: suggest /24 network if we have a primary IP
        if not scan_ranges and primary_ip != "Unable to determine":
            octets = primary_ip.split('.')
            if len(octets) == 4:
                network_base = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                scan_ranges.append(network_base)

        return {
            "hostname": hostname,
            "primary_ip": primary_ip,
            "all_ips": all_ips,
            "interfaces": interface_info,
            "scan_ranges": scan_ranges
        }

    except Exception as ex:
        return {"error": f"{type(ex).__name__}: {ex}"}


def nmap_scan(target, options=""):
    """
    Run an Nmap scan on the specified target with optional parameters.

    Args:
        target: The target to scan (IP address, hostname, or IP range)
        options: Additional Nmap command line options (e.g., "-sS -p 80,443")

    Returns:
        str: The output of the Nmap scan
    """
    cmd_parts = ["nmap"]

    if options:
        cmd_parts.extend(shlex.split(options))

    cmd_parts.append(target)

    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=600,  # Increased timeout for comprehensive scans
            check=False
        )

        if result.returncode != 0:
            return f"Error: Nmap returned non-zero exit code {result.returncode}\nStderr: {result.stderr}\nStdout: {result.stdout}"

        return result.stdout

    except subprocess.TimeoutExpired:
        return "Error: Nmap scan timed out after 10 minutes"
    except FileNotFoundError:
        return "Error: nmap command not found. Please install nmap first."
    except Exception as ex:
        return f"Error: {type(ex).__name__}: {ex}"


# ============================================================================
# HOST DISCOVERY & BASIC SCANNING
# ============================================================================

def nmap_ping_scan(target):
    """
    Perform a ping scan to discover live hosts (no port scanning).
    Equivalent to: nmap -sn target

    Args:
        target: The target or range to scan (e.g., "192.168.1.0/24")

    Returns:
        str: The list of live hosts
    """
    return nmap_scan(target, "-sn")


def nmap_list_scan(target):
    """
    List scan - simply list targets without scanning them.
    Equivalent to: nmap -sL target

    Args:
        target: The target or range to list

    Returns:
        str: List of targets
    """
    return nmap_scan(target, "-sL")


def nmap_quick_scan(target):
    """
    Perform a quick TCP scan on the most common 100 ports.
    Equivalent to: nmap -T4 -F target

    Args:
        target: The target to scan

    Returns:
        str: The output of the quick scan
    """
    return nmap_scan(target, "-T4 -F")


def nmap_fast_scan(target):
    """
    Fast scan - scan fewer ports than default.
    Equivalent to: nmap -F target

    Args:
        target: The target to scan

    Returns:
        str: The output of the fast scan
    """
    return nmap_scan(target, "-F")


# ============================================================================
# PORT SCANNING
# ============================================================================

def nmap_port_scan(target, ports):
    """
    Scan specific ports on the target.

    Args:
        target: The target to scan
        ports: Port specification (e.g., "80", "80,443", "1-1000", "U:53,T:80")

    Returns:
        str: The output of the port scan
    """
    return nmap_scan(target, f"-p {ports}")


def nmap_all_ports(target):
    """
    Scan all 65535 ports (comprehensive but slow).
    Equivalent to: nmap -p- target

    Args:
        target: The target to scan

    Returns:
        str: The output scanning all ports
    """
    return nmap_scan(target, "-p-")


def nmap_top_ports(target, num_ports):
    """
    Scan the top N most common ports.
    Equivalent to: nmap --top-ports N target

    Args:
        target: The target to scan
        num_ports: Number of top ports to scan (e.g., 100, 1000)

    Returns:
        str: The output of the scan
    """
    return nmap_scan(target, f"--top-ports {num_ports}")


# ============================================================================
# SERVICE & VERSION DETECTION
# ============================================================================

def nmap_service_detection(target, ports=""):
    """
    Perform service version detection on the target.
    Equivalent to: nmap -sV target

    Args:
        target: The target to scan
        ports: Optional port specification (if not provided, scans default ports)

    Returns:
        str: The output with service detection results
    """
    options = "-sV"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options)


def nmap_intense_service_scan(target, ports=""):
    """
    Intensive service version detection (tries all probes).
    Equivalent to: nmap -sV --version-intensity 9 target

    Args:
        target: The target to scan
        ports: Optional port specification

    Returns:
        str: Detailed service version information
    """
    options = "-sV --version-intensity 9"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options)


# ============================================================================
# OS DETECTION
# ============================================================================

def nmap_os_detection(target):
    """
    Attempt to detect the operating system of the target.
    Equivalent to: nmap -O target
    Note: May require administrator/root privileges.

    Args:
        target: The target to scan

    Returns:
        str: The output with OS detection results
    """
    return nmap_scan(target, "-O")


def nmap_aggressive_scan(target):
    """
    Aggressive scan: OS detection, version detection, script scanning, and traceroute.
    Equivalent to: nmap -A target
    Note: This is comprehensive but slower and more detectable.

    Args:
        target: The target to scan

    Returns:
        str: Comprehensive scan results
    """
    return nmap_scan(target, "-A")


# ============================================================================
# SCAN TECHNIQUES
# ============================================================================

def nmap_stealth_scan(target, ports=""):
    """
    Stealth SYN scan (half-open scan).
    Equivalent to: nmap -sS target
    Note: Requires administrator/root privileges.

    Args:
        target: The target to scan
        ports: Optional port specification

    Returns:
        str: Stealth scan results
    """
    options = "-sS"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options)


def nmap_udp_scan(target, ports=""):
    """
    UDP port scan.
    Equivalent to: nmap -sU target
    Note: UDP scans are slower than TCP scans.

    Args:
        target: The target to scan
        ports: Optional port specification (common: 53,67,68,69,123,135,137,138,139,161,162)

    Returns:
        str: UDP scan results
    """
    options = "-sU"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options)


def nmap_tcp_connect_scan(target, ports=""):
    """
    TCP Connect scan (full TCP handshake).
    Equivalent to: nmap -sT target
    Note: More detectable but doesn't require privileges.

    Args:
        target: The target to scan
        ports: Optional port specification

    Returns:
        str: TCP connect scan results
    """
    options = "-sT"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options)


# ============================================================================
# NSE SCRIPT SCANNING
# ============================================================================

def nmap_script_scan(target, script, ports=""):
    """
    Run specific Nmap NSE scripts against the target.

    Args:
        target: The target to scan
        script: The script name or category (e.g., "http-title", "vuln", "default")
        ports: Optional port specification

    Returns:
        str: The output of the script scan
    """
    options = f"--script {script}"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options)


def nmap_default_scripts(target):
    """
    Run default NSE scripts (safe, useful, and fast).
    Equivalent to: nmap -sC target or nmap --script=default target

    Args:
        target: The target to scan

    Returns:
        str: Results from default scripts
    """
    return nmap_scan(target, "-sC")


def nmap_vuln_scan(target):
    """
    Scan for common vulnerabilities using NSE vuln scripts.
    Equivalent to: nmap --script vuln target

    Args:
        target: The target to scan

    Returns:
        str: Vulnerability scan results
    """
    return nmap_scan(target, "--script vuln")


def nmap_web_scan(target, ports="80,443,8080,8443"):
    """
    Scan for web services and gather information.
    Equivalent to: nmap --script http-enum,http-title,http-headers target

    Args:
        target: The target to scan
        ports: Web ports to scan (default: 80,443,8080,8443)

    Returns:
        str: Web service information
    """
    return nmap_scan(target, f"-p {ports} --script http-enum,http-title,http-headers,http-methods")


# ============================================================================
# ADDITIONAL FEATURES
# ============================================================================

def nmap_traceroute(target):
    """
    Perform traceroute to the target.
    Equivalent to: nmap --traceroute target

    Args:
        target: The target to trace

    Returns:
        str: Traceroute results
    """
    return nmap_scan(target, "--traceroute")


def nmap_comprehensive_scan(target):
    """
    Comprehensive scan: all ports, service detection, OS detection, scripts, traceroute.
    Equivalent to: nmap -p- -sV -sC -O --traceroute target
    Note: This is VERY slow but extremely thorough.

    Args:
        target: The target to scan

    Returns:
        str: Comprehensive scan results
    """
    return nmap_scan(target, "-p- -sV -sC -O --traceroute")


def nmap_no_ping_scan(target, ports=""):
    """
    Skip host discovery (assume host is up).
    Equivalent to: nmap -Pn target
    Useful when firewall blocks ping probes.

    Args:
        target: The target to scan
        ports: Optional port specification

    Returns:
        str: Scan results
    """
    options = "-Pn"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options)


# ============================================================================
# TOOL DEFINITIONS FOR OLLAMA
# ============================================================================

NMAP_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_local_network_info",
            "description": "Get local network information including IP addresses and suggested scan ranges. Use this FIRST to discover the network before scanning.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_ping_scan",
            "description": "Discover live hosts in a network range without port scanning. Use for: 'find devices', 'discover hosts', 'what's on the network', 'find active machines'. Fast host discovery.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Network range (e.g., '192.168.1.0/24', '10.0.0.0/16')"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_quick_scan",
            "description": "Quick scan of top 100 most common ports. Use for: 'quick scan', 'fast check', 'initial reconnaissance'. Takes ~30 seconds.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_port_scan",
            "description": "Scan specific ports. Use when user specifies exact ports like 'check port 22', 'scan ports 80,443', 'check SSH', 'is port 3389 open'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port(s) to scan: single '80', list '80,443,8080', range '1-1000', TCP/UDP 'T:80,U:53'"
                    }
                },
                "required": ["target", "ports"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_all_ports",
            "description": "Scan ALL 65535 ports (comprehensive but VERY slow, 10+ minutes). Use only when user explicitly requests 'all ports', 'full port scan', 'comprehensive ports'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_top_ports",
            "description": "Scan top N most common ports. Use for 'scan top 1000 ports', 'check common ports', 'top 100 ports'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "num_ports": {
                        "type": "string",
                        "description": "Number of top ports (e.g., '100', '1000')"
                    }
                },
                "required": ["target", "num_ports"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_service_detection",
            "description": "Detect service versions on open ports. Use for: 'what services are running', 'service version', 'what's on port 80', 'identify software'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Optional: specific ports to check"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_os_detection",
            "description": "Detect operating system. Use for: 'what OS', 'operating system', 'is it Windows or Linux', 'OS fingerprint'. Requires admin privileges.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_aggressive_scan",
            "description": "Aggressive comprehensive scan: OS, services, scripts, traceroute. Use for: 'aggressive scan', 'detailed scan', 'thorough analysis', 'full information'. Slower but very detailed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_vuln_scan",
            "description": "Scan for vulnerabilities using NSE scripts. Use for: 'check vulnerabilities', 'find security issues', 'vuln scan', 'security audit'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_udp_scan",
            "description": "Scan UDP ports. Use for: 'UDP scan', 'check DNS', 'SNMP', 'DHCP'. Slower than TCP scans.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Optional: UDP ports (common: 53,67,123,161,162)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_web_scan",
            "description": "Scan for web services and gather HTTP information. Use for: 'web scan', 'HTTP server', 'website info', 'web services'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Optional: web ports (default: 80,443,8080,8443)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_stealth_scan",
            "description": "Stealth SYN scan (less detectable). Use for: 'stealth scan', 'stealthy', 'SYN scan', 'sneaky scan'. Requires admin privileges.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Optional: specific ports"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_script_scan",
            "description": "Run specific NSE scripts. Use for custom script scanning with categories like 'vuln', 'exploit', 'auth', 'default' or specific scripts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "script": {
                        "type": "string",
                        "description": "Script name or category (e.g., 'vuln', 'http-title', 'ssl-cert')"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Optional: specific ports"
                    }
                },
                "required": ["target", "script"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_traceroute",
            "description": "Trace network path to target. Use for: 'traceroute', 'network path', 'route to host', 'hops'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_no_ping_scan",
            "description": "Skip host discovery (assume target is up). Use when firewall blocks pings or when you're sure the host is online but not responding to ping.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Optional: ports to scan"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": "Custom nmap scan with any options. Use ONLY when none of the other specialized tools fit the requirement. Accepts any valid nmap command-line options.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address, hostname, or range"
                    },
                    "options": {
                        "type": "string",
                        "description": "Nmap command-line options (e.g., '-sS -p 1-1000 -T4')"
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

def execute_tool(tool_name, tool_args):
    """
    Execute a tool by name with given arguments

    Args:
        tool_name: Name of the tool function
        tool_args: Dictionary of arguments

    Returns:
        The result of the tool execution
    """
    tools_map = {
        "get_local_network_info": get_local_network_info,
        "nmap_scan": nmap_scan,
        "nmap_ping_scan": nmap_ping_scan,
        "nmap_list_scan": nmap_list_scan,
        "nmap_quick_scan": nmap_quick_scan,
        "nmap_fast_scan": nmap_fast_scan,
        "nmap_port_scan": nmap_port_scan,
        "nmap_all_ports": nmap_all_ports,
        "nmap_top_ports": nmap_top_ports,
        "nmap_service_detection": nmap_service_detection,
        "nmap_intense_service_scan": nmap_intense_service_scan,
        "nmap_os_detection": nmap_os_detection,
        "nmap_aggressive_scan": nmap_aggressive_scan,
        "nmap_stealth_scan": nmap_stealth_scan,
        "nmap_udp_scan": nmap_udp_scan,
        "nmap_tcp_connect_scan": nmap_tcp_connect_scan,
        "nmap_script_scan": nmap_script_scan,
        "nmap_default_scripts": nmap_default_scripts,
        "nmap_vuln_scan": nmap_vuln_scan,
        "nmap_web_scan": nmap_web_scan,
        "nmap_traceroute": nmap_traceroute,
        "nmap_comprehensive_scan": nmap_comprehensive_scan,
        "nmap_no_ping_scan": nmap_no_ping_scan
    }

    if tool_name not in tools_map:
        return f"Error: Unknown tool '{tool_name}'"

    try:
        func = tools_map[tool_name]
        result = func(**tool_args)
        return result
    except TypeError as e:
        return f"Error: Invalid arguments for {tool_name}: {e}"
    except Exception as e:
        return f"Error executing {tool_name}: {e}"
