"""
Port Metadata Registry
======================

Comprehensive database of TCP/UDP ports, services, and scanning profiles.
Used by agents to understand network services and configure scanners.

Total Ports: 65535 (1-65535)
"""

from typing import Dict, List, Any, Optional

# ═══════════════════════════════════════════════════════════════
# PORT RANGES
# ═══════════════════════════════════════════════════════════════
PORT_RANGE_FULL = "1-65535"
PORT_RANGE_PRIVILEGED = "1-1024"
PORT_RANGE_EPHEMERAL = "49152-65535"

# ═══════════════════════════════════════════════════════════════
# COMMON PORTS & SERVICES (Metadata)
# ═══════════════════════════════════════════════════════════════
PORT_INFO: Dict[int, Dict[str, str]] = {
    # File Transfer
    20: {"service": "ftp-data", "description": "FTP Data Transfer"},
    21: {"service": "ftp", "description": "File Transfer Protocol (Control)"},
    69: {"service": "tftp", "description": "Trivial File Transfer Protocol"},
    
    # Remote Access
    22: {"service": "ssh", "description": "Secure Shell"},
    23: {"service": "telnet", "description": "Telnet (Unencrypted)"},
    3389: {"service": "ms-wbt-server", "description": "RDP (Remote Desktop)"},
    5900: {"service": "vnc", "description": "VNC Remote Access"},
    
    # Mail
    25: {"service": "smtp", "description": "Simple Mail Transfer Protocol"},
    110: {"service": "pop3", "description": "Post Office Protocol v3"},
    143: {"service": "imap", "description": "Internet Message Access Protocol"},
    465: {"service": "smtps", "description": "SMTP over SSL"},
    587: {"service": "submission", "description": "SMTP Submission"},
    993: {"service": "imaps", "description": "IMAP over SSL"},
    995: {"service": "pop3s", "description": "POP3 over SSL"},
    
    # Web
    80: {"service": "http", "description": "Hypertext Transfer Protocol"},
    443: {"service": "https", "description": "HTTP Secure"},
    8000: {"service": "http-alt", "description": "Common Web Dev Port"},
    8008: {"service": "http-alt", "description": "Common Web Dev Port"},
    8080: {"service": "http-proxy", "description": "Common Web Proxy/Dev"},
    8443: {"service": "https-alt", "description": "Common HTTPS Dev"},
    8888: {"service": "http-alt", "description": "Common Web Port"},
    
    # Infrastructure
    53: {"service": "domain", "description": "Domain Name System"},
    67: {"service": "bootps", "description": "DHCP Server"},
    68: {"service": "bootpc", "description": "DHCP Client"},
    123: {"service": "ntp", "description": "Network Time Protocol"},
    161: {"service": "snmp", "description": "Simple Network Management Protocol"},
    389: {"service": "ldap", "description": "Lightweight Directory Access Protocol"},
    636: {"service": "ldaps", "description": "LDAP over SSL"},
    
    # Windows / SMB
    135: {"service": "msrpc", "description": "Microsoft RPC Endpoint Mapper"},
    137: {"service": "netbios-ns", "description": "NetBIOS Name Service"},
    138: {"service": "netbios-dgm", "description": "NetBIOS Datagram Service"},
    139: {"service": "netbios-ssn", "description": "NetBIOS Session Service"},
    445: {"service": "microsoft-ds", "description": "SMB / CIFS"},
    
    # Databases
    1433: {"service": "ms-sql-s", "description": "Microsoft SQL Server"},
    1521: {"service": "oracle", "description": "Oracle Database"},
    3306: {"service": "mysql", "description": "MySQL Database"},
    5432: {"service": "postgresql", "description": "PostgreSQL Database"},
    6379: {"service": "redis", "description": "Redis Key-Value Store"},
    27017: {"service": "mongodb", "description": "MongoDB"},
    9200: {"service": "elasticsearch", "description": "Elasticsearch REST API"},
}

# ═══════════════════════════════════════════════════════════════
# SCANNING PROFILES
# ═══════════════════════════════════════════════════════════════
PORT_PROFILES = {
    # 26 Critical Ports (Fastest Recon)
    "critical": "21,22,23,25,53,67,68,80,110,123,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443,8888",
    
    # Web Focus
    "web": "80,443,8000,8008,8080,8443,8888,3000,5000",
    
    # Database Focus
    "database": "1433,1521,3306,5432,6379,27017,9200",
    
    # Windows Infrastructure
    "windows": "53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,5986",
    
    # Mail Infrastructure
    "mail": "25,110,143,465,587,993,995",
    
    # Top 100 Common Ports (Approximate)
    "top_100": "7,9,13,20,21,22,23,25,26,37,53,67,68,69,80,81,88,102,110,111,113,119,123,135,137,138,139,143,161,162,179,194,201,264,311,389,443,445,464,465,500,513,514,520,543,544,548,554,587,593,631,636,646,873,990,993,995,1025,1026,1027,1110,1433,1521,1720,1723,1755,1900,2000,2001,2049,2082,2083,2086,2087,2095,2096,2121,3306,3389,3690,4899,5060,5432,5631,5666,5800,5900,6000,6001,6667,8000,8008,8009,8080,8081,8443,8888,9000,9090,27017",
    
    # Full Range (Warning: Slow)
    "full": PORT_RANGE_FULL,
}

# ═══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def get_port_description(port: int) -> str:
    """Get description for a port."""
    info = PORT_INFO.get(port)
    if info:
        return f"{port}/{info['service']}: {info['description']}"
    return f"{port}/unknown"

def get_service_ports(service_name: str) -> List[int]:
    """Get ports common for a service (fuzzy match)."""
    service_name = service_name.lower()
    return [p for p, info in PORT_INFO.items() if service_name in info['service'].lower()]

def get_profile_ports(profile_name: str) -> str:
    """Get comma-separated string of ports for a profile."""
    return PORT_PROFILES.get(profile_name.lower(), PORT_PROFILES["critical"])
