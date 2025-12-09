"""
DNS Tools - LangChain Wrappers
Bulk DNS resolution and reverse lookups
"""
import os
import sys

# Ensure tools directory is in path
_rutx_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _rutx_root not in sys.path:
    sys.path.insert(0, _rutx_root)

from langchain_core.tools import tool
from tools.dns_tools import (
    resolve_dns as _resolve_dns,
    reverse_dns_lookup as _reverse_dns_lookup,
    dnsx_bulk_resolve as _dnsx_bulk_resolve
)


@tool
def resolve_dns(domain: str) -> dict:
    """
    Resolve a domain name to IP address(es).
    
    Args:
        domain: Domain name to resolve (e.g., "example.com")
    
    Returns:
        Dictionary with A records and status
    """
    return _resolve_dns(domain)


@tool  
def reverse_dns(ip: str) -> dict:
    """
    Perform reverse DNS lookup (PTR record) to find hostname from IP.
    
    Args:
        ip: IP address to lookup (e.g., "8.8.8.8")
    
    Returns:
        Dictionary with hostname if found
    """
    return _reverse_dns_lookup(ip)


@tool
def bulk_dns_resolve(subdomains: list) -> dict:
    """
    Bulk resolve multiple subdomains to IPs using dnsx (very fast).
    Can resolve 100+ subdomains in seconds.
    
    Args:
        subdomains: List of subdomains like ["api.example.com", "www.example.com"]
    
    Returns:
        Dictionary mapping subdomain to IP address
    """
    return _dnsx_bulk_resolve(subdomains)


# Export all tools
DNS_TOOLS = [resolve_dns, reverse_dns, bulk_dns_resolve]
