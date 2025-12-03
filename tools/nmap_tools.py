"""
Nmap Tools Module
Comprehensive nmap scanning functions for network reconnaissance
Supports most common nmap use cases and options
"""

import subprocess
import shlex
import socket
import re
import os
from datetime import datetime


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


def nmap_scan(target, options="", return_dict=True, timeout=600):
    """
    Run an Nmap scan on the specified target with optional parameters.
    Now includes XML output for database integration.

    Args:
        target: The target to scan (IP address, hostname, or IP range)
        options: Additional Nmap command line options (e.g., "-sS -p 80,443")
        return_dict: If True, return structured dict; if False, return raw stdout
        timeout: Timeout in seconds (default: 600 = 10 minutes)

    Returns:
        dict: Structured scan result with output_xml path for database parsing
    """
    import time

    # Generate output file paths
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^\w\-.]', '_', target)
    output_dir = "/tmp/nmap_scans"
    os.makedirs(output_dir, exist_ok=True)

    xml_output = os.path.join(output_dir, f"nmap_{safe_target}_{timestamp}.xml")

    cmd_parts = ["nmap", "-oX", xml_output]

    if options:
        cmd_parts.extend(shlex.split(options))

    cmd_parts.append(target)

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
                "error": f"Nmap returned exit code {result.returncode}",
                "stderr": result.stderr,
                "stdout": result.stdout,
                "target": target
            }

        # Parse stdout for quick summary
        stdout = result.stdout
        open_ports = []
        hosts = []
        host_up = False

        for line in stdout.splitlines():
            # Extract host info from "Nmap scan report for ..."
            host_match = re.search(r'Nmap scan report for ([\w\.\-]+)(?: \((\d+\.\d+\.\d+\.\d+)\))?', line)
            if host_match:
                hostname = host_match.group(1)
                ip = host_match.group(2) or hostname
                hosts.append({"hostname": hostname, "ip": ip})

            # Check if host is up
            if 'Host is up' in line:
                host_up = True

            # Extract port info - handles variable whitespace
            # Format: "22/tcp   open  ssh" or "443/tcp open  https"
            port_match = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s*(.*)?$', line)
            if port_match:
                open_ports.append({
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": (port_match.group(4) or "").strip()
                })

        # Count open, filtered, and closed ports
        open_count = len([p for p in open_ports if p["state"] == "open"])
        filtered_count = len([p for p in open_ports if p["state"] == "filtered"])
        closed_count = len([p for p in open_ports if p["state"] == "closed"])

        # If no hosts found but host was up, add the target as a host
        if not hosts and host_up:
            hosts.append({"hostname": target, "ip": target})

        # Build informative summary
        summary_parts = [f"{len(hosts)} host(s)"]
        if open_count > 0:
            summary_parts.append(f"{open_count} open")
        if filtered_count > 0:
            summary_parts.append(f"{filtered_count} filtered")
        if closed_count > 0:
            summary_parts.append(f"{closed_count} closed")

        if not open_ports and host_up:
            summary_parts.append("(host up, all scanned ports filtered/closed)")

        return {
            "success": True,
            "tool": "nmap_scan",
            "target": target,
            "output_xml": xml_output,  # CRITICAL: For database parsing
            "output": stdout,
            "elapsed_seconds": round(elapsed, 2),
            "hosts_discovered": len(hosts),
            "hosts": hosts,
            "host_up": host_up,
            "open_ports_count": open_count,
            "filtered_ports_count": filtered_count,
            "closed_ports_count": closed_count,
            "open_ports": open_ports,
            "command": ' '.join(cmd_parts),
            "summary": f"Nmap scan: {', '.join(summary_parts)}",
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        timeout_mins = timeout // 60
        return {
            "success": False,
            "error": f"Nmap scan timed out after {timeout_mins} minutes",
            "target": target
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "nmap command not found. Please install nmap first.",
            "target": target
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "target": target
        }


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
    Uses -Pn to skip host discovery (treats host as online even if it blocks ping).
    Equivalent to: nmap -Pn -T4 -F target

    Args:
        target: The target to scan

    Returns:
        dict: Structured scan result with open ports and services
    """
    return nmap_scan(target, "-Pn -T4 -F")


def nmap_fast_scan(target):
    """
    Fast scan - scan fewer ports than default.
    Uses -Pn to skip host discovery (treats host as online even if it blocks ping).
    Equivalent to: nmap -Pn -F target

    Args:
        target: The target to scan

    Returns:
        dict: Structured scan result with open ports and services
    """
    return nmap_scan(target, "-Pn -F")


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
    Note: This can take 60+ minutes depending on target.

    Args:
        target: The target to scan

    Returns:
        str: The output scanning all ports
    """
    return nmap_scan(target, "-p-", timeout=3600)  # 60 minute timeout


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

def nmap_service_detection(target, ports="", timeout=600):
    """
    Perform service version detection on the target.
    Uses -Pn to skip host discovery (treats host as online).
    Equivalent to: nmap -Pn -sV target

    Args:
        target: The target to scan
        ports: Optional port specification (if not provided, scans default ports)
        timeout: Timeout in seconds (default: 600)

    Returns:
        dict: Structured scan result with services detected
    """
    options = "-Pn -sV"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options, timeout=timeout)


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
    Note: Requires administrator/root privileges.

    Args:
        target: The target to scan

    Returns:
        dict: OS detection results (or basic scan if not admin)
    """
    # Check if running as admin/root
    try:
        import sys
        if sys.platform == 'win32':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            import os as os_module
            is_admin = os_module.geteuid() == 0
    except:
        is_admin = False
    
    if is_admin:
        print(f"    🔓 Admin mode: OS detection enabled")
        return nmap_scan(target, "-O")
    else:
        print(f"    🔒 User mode: OS detection requires root/admin privileges")
        print(f"    💡 Tip: Run with sudo/admin for OS detection")
        print(f"    ℹ️  Running basic port scan instead...")
        return nmap_scan(target, "-Pn -sV")


def nmap_aggressive_scan(target):
    """
    Aggressive scan: OS detection, version detection, script scanning, and traceroute.
    Uses -Pn to skip host discovery (treats host as online).
    Equivalent to: nmap -Pn -A target (admin) or nmap -Pn -sV -sC (user)
    Note: This is comprehensive but slower and more detectable.

    Args:
        target: The target to scan

    Returns:
        dict: Comprehensive structured scan results
    """
    # Check if running as admin/root
    try:
        import sys
        if sys.platform == 'win32':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            import os as os_module
            is_admin = os_module.geteuid() == 0
    except:
        is_admin = False
    
    if is_admin:
        # Full aggressive scan with OS detection
        print(f"    🔓 Admin mode: Full aggressive scan (-A)")
        return nmap_scan(target, "-Pn -A")
    else:
        # Aggressive scan without OS detection (no root required)
        print(f"    🔒 User mode: Aggressive scan without OS detection")
        print(f"    💡 Tip: Run with sudo/admin for full -A scan")
        return nmap_scan(target, "-Pn -sV -sC")


# ============================================================================
# SCAN TECHNIQUES
# ============================================================================

def nmap_stealth_scan(target, ports=""):
    """
    Stealth SYN scan (half-open scan).
    Equivalent to: nmap -sS target (admin) or nmap -sT target (user)
    Note: SYN scan requires administrator/root privileges.

    Args:
        target: The target to scan
        ports: Optional port specification

    Returns:
        dict: Stealth scan results (or TCP connect scan if not admin)
    """
    # Check if running as admin/root
    try:
        import sys
        if sys.platform == 'win32':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            import os as os_module
            is_admin = os_module.geteuid() == 0
    except:
        is_admin = False
    
    if is_admin:
        # SYN scan (stealthy)
        print(f"    🔓 Admin mode: SYN scan (-sS)")
        options = "-sS"
    else:
        # TCP Connect scan (fallback for non-root)
        print(f"    🔒 User mode: TCP Connect scan (-sT) instead of SYN")
        print(f"    💡 Tip: Run with sudo/admin for stealth SYN scan")
        options = "-sT"
    
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
    Uses -Pn to skip host discovery (treats host as online).
    Equivalent to: nmap -Pn -sC target or nmap -Pn --script=default target

    Args:
        target: The target to scan

    Returns:
        dict: Structured results from default scripts
    """
    return nmap_scan(target, "-Pn -sC")


def nmap_vuln_scan(target, timeout=900):
    """
    Scan for common vulnerabilities using NSE vuln scripts.
    Uses -Pn to skip host discovery (treats host as online).
    Equivalent to: nmap -Pn --script vuln target

    Args:
        target: The target to scan
        timeout: Timeout in seconds (default: 900)

    Returns:
        dict: Structured scan result with vulnerabilities detected
    """
    return nmap_scan(target, "-Pn --script vuln", timeout=timeout)


def nmap_web_scan(target, ports="80,443,8080,8443", timeout=600):
    """
    Scan for web services and gather information.
    Uses -Pn to skip host discovery (treats host as online).
    Equivalent to: nmap -Pn --script http-enum,http-title,http-headers target

    Args:
        target: The target to scan
        ports: Web ports to scan (default: 80,443,8080,8443)
        timeout: Timeout in seconds (default: 600)

    Returns:
        dict: Web service information
    """
    return nmap_scan(target, f"-Pn -p {ports} --script http-enum,http-title,http-headers,http-methods", timeout=timeout)


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
    Note: This is VERY slow (60+ minutes) but extremely thorough.

    Args:
        target: The target to scan

    Returns:
        str: Comprehensive scan results
    """
    # Check if running as admin to determine scan options
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    
    if is_admin:
        # Full comprehensive scan with all features (requires admin)
        # -p-: All ports
        # -sV: Service version detection
        # -sC: Default scripts
        # -O: OS detection (requires admin)
        # --traceroute: Trace route to target
        options = "-p- -sV -sC -O --traceroute"
        print(f"    🔓 Admin mode: Full comprehensive scan (all ports + OS detection)")
    else:
        # Non-privileged comprehensive scan
        # -p-: All ports
        # -sV: Service version detection
        # -Pn: Skip host discovery (treat as online)
        # Note: Skipping -sC scripts and -O OS detection which may require privileges
        options = "-Pn -p- -sV"
        print(f"    🔒 User mode: Comprehensive scan (all ports, no OS detection)")
        print(f"    💡 Tip: Run as Administrator for OS detection and NSE scripts")
    
    return nmap_scan(target, options, timeout=3600)


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
            "name": "nmap_comprehensive_scan",
            "description": "Most comprehensive scan available: ALL 65535 ports + service detection + OS detection + default scripts + traceroute. Use for critical/high-value targets requiring complete assessment. Very slow (30+ minutes).",
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
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_stealth_batch_scan",
            "description": "Stealth batch scan for multiple targets using Nmap. Designed to be less noisy than Naabu. Features: SYN scan if admin, rate limiting (default 300 pps), timing control (T0-T5), batch processing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Comma-separated list of targets (hostnames or IPs)"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification: 'top-100', 'top-1000', '1-65535', or specific ports like '80,443' (default: top-1000)"
                    },
                    "timing": {
                        "type": "string",
                        "description": "Nmap timing: T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal (default), T4=Aggressive, T5=Insane"
                    },
                    "max_rate": {
                        "type": "integer",
                        "description": "Maximum packets per second (default: 300)"
                    }
                },
                "required": ["targets"]
            }
        }
    }
]


def nmap_service_detection_batch(targets: list = None, source: str = None,
                                  scan_discovered_ports: bool = True,
                                  save_results: bool = False, timeout: int = 1800) -> dict:
    """
    Stage 4 tool: Batch Nmap service detection for 4-stage workflow.

    This is the SOURCE OF TRUTH for the final report. It provides:
    - Service/version detection (-sV)
    - OS fingerprinting (-O when possible)
    - Detailed banner grabbing

    Args:
        targets: List of IPs or dict of {IP: [ports]} from Stage 3
        source: Source identifier (e.g., "stage3_naabu_results")
        scan_discovered_ports: If True, scan only discovered ports; if False, scan all common ports
        save_results: Whether to save results for next stage
        timeout: Timeout in seconds per host

    Returns:
        dict: Comprehensive Nmap scan results with stage metadata
    """
    from typing import Dict, List, Any
    import time

    print(f"\n  🎯 [STAGE 4] Nmap Service Detection (Source of Truth)")

    # Parse targets - could be list of IPs or dict of {IP: [ports]}
    if isinstance(targets, dict):
        # Stage 3 passed {IP: [ports]} dict
        target_port_map = targets
        target_list = list(targets.keys())
    elif isinstance(targets, list):
        # Simple list of IPs
        target_list = targets
        target_port_map = {}
    else:
        return {
            "success": False,
            "error": f"Invalid targets type: {type(targets)}",
            "stage": 4
        }

    print(f"     - Targets to scan: {len(target_list)}")
    print(f"     - Scan mode: {'Discovered ports only' if scan_discovered_ports and target_port_map else 'All common ports'}")

    all_results = []
    successful = 0
    failed = 0

    # Aggregate statistics
    total_services = 0
    total_os_detected = 0
    services_by_type = {}

    for i, ip in enumerate(target_list, 1):
        ports_to_scan = target_port_map.get(ip, []) if scan_discovered_ports and target_port_map else []

        if ports_to_scan:
            ports_str = ",".join(map(str, sorted(ports_to_scan)[:100]))  # Limit to 100 ports
            print(f"     [{i}/{len(target_list)}] Scanning {ip} → {len(ports_to_scan)} ports...", end=" ")
        else:
            ports_str = ""
            print(f"     [{i}/{len(target_list)}] Scanning {ip} → default ports...", end=" ")

        try:
            result = nmap_service_detection(ip, ports=ports_str, timeout=timeout)

            if result.get("success"):
                services = result.get("services_detected", [])
                os_info = result.get("os_matches", [])

                print(f"✓ {len(services)} services, OS: {'Yes' if os_info else 'No'}")

                successful += 1
                total_services += len(services)
                if os_info:
                    total_os_detected += 1

                # Track service types
                for svc in services:
                    svc_name = svc.get("service", "unknown")
                    services_by_type[svc_name] = services_by_type.get(svc_name, 0) + 1

                all_results.append({
                    "ip": ip,
                    "result": result,
                    "status": "success"
                })
            else:
                print(f"✗ {result.get('error', 'Unknown error')}")
                failed += 1
                all_results.append({
                    "ip": ip,
                    "error": result.get("error"),
                    "status": "failed"
                })

        except Exception as e:
            print(f"✗ Exception: {str(e)}")
            failed += 1
            all_results.append({
                "ip": ip,
                "error": str(e),
                "status": "failed"
            })

        # Brief pause between scans to avoid overwhelming the network
        if i < len(target_list):
            time.sleep(0.5)

    print(f"\n  📊 [STAGE 4] Summary (Source of Truth):")
    print(f"     - Successful: {successful}")
    print(f"     - Failed: {failed}")
    print(f"     - Total services detected: {total_services}")
    print(f"     - OS detected: {total_os_detected}/{len(target_list)}")

    if services_by_type:
        print(f"     - Top services found:")
        sorted_services = sorted(services_by_type.items(), key=lambda x: x[1], reverse=True)[:5]
        for svc, count in sorted_services:
            print(f"       • {svc}: {count}")

    return {
        "success": True,
        "stage": 4,
        "source_of_truth": True,  # Mark this as authoritative
        "results": all_results,
        "stats": {
            "total": len(target_list),
            "successful": successful,
            "failed": failed,
            "total_services": total_services,
            "os_detected": total_os_detected,
            "services_by_type": services_by_type
        },
        "summary": f"Stage 4 Nmap: Scanned {len(target_list)} IPs, detected {total_services} services, {total_os_detected} OS fingerprints"
    }


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
        "nmap_stealth_batch_scan": nmap_stealth_batch_scan,
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
        return {
            "success": False,
            "error": f"Invalid arguments for {tool_name}: {e}",
            "tool": tool_name
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error executing {tool_name}: {e}",
            "tool": tool_name
        }


def nmap_stealth_batch_scan(targets, ports="top-1000", timing="T3", max_rate=300):
    """
    Stealth batch scan for multiple targets using Nmap.
    Designed to be less noisy than Naabu while still being reasonably fast.

    Features:
    - Stealth SYN scan (-sS) if admin, TCP connect (-sT) otherwise
    - Timing control to reduce noise (default T3 = "Normal")
    - Rate limiting to avoid detection
    - Top ports for speed, or custom port specification
    - Batch processing with single Nmap invocation

    Args:
        targets: Comma-separated list of targets (hostnames or IPs)
        ports: Port specification:
            - "top-100", "top-1000" (common ports)
            - "1-65535" (all ports)
            - "80,443,8080" (specific ports)
        timing: Nmap timing template:
            - "T0" = Paranoid (slowest, stealthiest)
            - "T1" = Sneaky (very slow)
            - "T2" = Polite (slow)
            - "T3" = Normal (balanced - default)
            - "T4" = Aggressive (fast)
            - "T5" = Insane (fastest, noisiest)
        max_rate: Maximum packets per second (default 300 for stealth)

    Returns:
        dict: Scan results with per-host port information
    """
    import tempfile
    import time

    # Parse targets
    # Handle malformed input: LLM sometimes passes string representation of list
    if isinstance(targets, str) and targets.startswith('[') and targets.endswith(']'):
        import ast
        try:
            parsed = ast.literal_eval(targets)
            if isinstance(parsed, list):
                target_list = [str(t).strip() for t in parsed if str(t).strip()]
            else:
                target_list = [t.strip() for t in targets.split(",") if t.strip()]
        except (ValueError, SyntaxError):
            target_list = [t.strip() for t in targets.split(",") if t.strip()]
    else:
        target_list = [t.strip() for t in targets.split(",") if t.strip()]

    if not target_list:
        return {
            "success": False,
            "error": "No valid targets provided",
            "targets": []
        }

    # Create temporary target file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        targets_file = f.name
        for target in target_list:
            f.write(f"{target}\n")

    try:
        # Parse port specification
        if ports.startswith("top-"):
            top_count = ports.split("-")[1]
            port_option = f"--top-ports {top_count}"
            ports_display = f"top-{top_count}"
        else:
            port_option = f"-p {ports}"
            ports_display = ports

        # Check if running as admin for SYN scan
        try:
            import sys
            if sys.platform == 'win32':
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            else:
                import os as os_module
                is_admin = os_module.geteuid() == 0
        except:
            is_admin = False

        # Build Nmap command
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = "/tmp/nmap_scans"
        os.makedirs(output_dir, exist_ok=True)
        xml_output = os.path.join(output_dir, f"nmap_batch_{timestamp}.xml")

        cmd = ["nmap"]

        # Scan type
        if is_admin:
            cmd.append("-sS")  # SYN scan (stealthy)
            scan_type = "SYN (stealth)"
        else:
            cmd.append("-sT")  # TCP connect (fallback)
            scan_type = "TCP connect"

        # Add stealth options
        cmd.extend([
            f"-{timing}",  # Timing template
            f"--max-rate={max_rate}",  # Rate limiting
            "-Pn",  # Skip host discovery (assume hosts are up)
            "--disable-arp-ping",  # More stealthy
            "-iL", targets_file,  # Input target list
            "-oX", xml_output  # XML output
        ])

        # Add port specification
        cmd.extend(shlex.split(port_option))

        print(f"  🎯 Nmap stealth batch scan")
        print(f"     Targets: {len(target_list)} hosts")
        print(f"     Ports: {ports_display}")
        print(f"     Scan type: {scan_type}")
        print(f"     Timing: {timing} (max rate: {max_rate} pps)")

        # Calculate estimated time
        if ports.startswith("top-"):
            port_count = int(top_count)
        elif "-" in ports:
            parts = ports.split("-")
            port_count = int(parts[1]) - int(parts[0]) + 1
        else:
            port_count = len(ports.split(","))

        estimated_seconds = (len(target_list) * port_count) / max_rate
        print(f"     Estimated time: {int(estimated_seconds // 60)}m {int(estimated_seconds % 60)}s")

        # Run scan
        start_time = time.time()

        # Dynamic timeout based on workload
        timeout = max(600, int(estimated_seconds * 2))  # 2x safety factor
        print(f"     Timeout set to: {int(timeout // 60)}m {int(timeout % 60)}s")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        elapsed_seconds = time.time() - start_time
        print(f"     Scan completed in: {int(elapsed_seconds // 60)}m {int(elapsed_seconds % 60)}s")
        print(f"     Nmap return code: {result.returncode}")

        if result.returncode != 0:
            print(f"     [ERROR] Nmap failed with return code {result.returncode}")
            print(f"     [ERROR] stderr: {result.stderr[:200]}")
            return {
                "success": False,
                "error": f"Nmap returned exit code {result.returncode}",
                "stderr": result.stderr,
                "stdout": result.stdout,
                "targets": target_list,
                "targets_count": len(target_list)
            }

        # Parse results
        stdout = result.stdout
        results = {}  # {IP/hostname: [ports]}
        hostname_to_ip = {}
        current_host = None
        current_ip = None
        total_open_ports = 0

        for line in stdout.splitlines():
            # Extract host info
            host_match = re.search(r'Nmap scan report for ([\w\.\-]+)(?: \((\d+\.\d+\.\d+\.\d+)\))?', line)
            if host_match:
                current_host = host_match.group(1)
                current_ip = host_match.group(2) or current_host
                hostname_to_ip[current_host] = current_ip
                results[current_ip] = []

            # Extract open ports
            port_match = re.match(r'^(\d+)/(tcp|udp)\s+open\s*(.*)?$', line)
            if port_match and current_ip:
                port_num = int(port_match.group(1))
                results[current_ip].append(port_num)
                total_open_ports += 1

        # Count targets with open ports
        targets_with_open_ports = sum(1 for ports in results.values() if len(ports) > 0)

        print(f"  ✅ Scan complete: {targets_with_open_ports}/{len(target_list)} hosts have open ports ({total_open_ports} total)")
        print(f"     Duration: {int(elapsed_seconds // 60)}m {int(elapsed_seconds % 60)}s")
        print(f"     [DEBUG] Parsed {len(results)} results entries")
        if len(results) > 0:
            print(f"     [DEBUG] Sample result: {list(results.items())[0] if results else 'none'}")

        return {
            "success": True,
            "tool": "nmap_stealth_batch_scan",
            "targets": target_list,
            "targets_count": len(target_list),
            "results": results,
            "hostname_to_ip": hostname_to_ip,
            "total_hosts_scanned": len(target_list),
            "hosts_with_ports": targets_with_open_ports,
            "targets_with_open_ports": targets_with_open_ports,
            "total_open_ports": total_open_ports,
            "scan_duration": int(elapsed_seconds),
            "elapsed_seconds": elapsed_seconds,
            "scan_rate": max_rate,
            "ports_scanned": ports_display,
            "timing": timing,
            "output_xml": xml_output,
            "stdout": stdout,
            "stderr": result.stderr
        }

    except subprocess.TimeoutExpired:
        timeout_mins = timeout // 60
        print(f"     [ERROR] Scan timed out after {timeout_mins} minutes")
        return {
            "success": False,
            "error": f"Nmap batch scan timed out after {timeout_mins} minutes",
            "targets": target_list,
            "targets_count": len(target_list),
            "estimated_seconds": estimated_seconds,
            "timeout_seconds": timeout
        }
    except Exception as e:
        print(f"     [ERROR] Unexpected error: {e}")
        return {
            "success": False,
            "error": f"Unexpected error during batch scan: {e}",
            "targets": target_list,
            "targets_count": len(target_list)
        }
    finally:
        # Cleanup temp file
        try:
            os.unlink(targets_file)
        except:
            pass
