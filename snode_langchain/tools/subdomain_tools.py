"""
SNODE LangChain - Subdomain Enumeration Tools
Wrapped subdomain discovery tools for LangChain agent
"""
import sys
import os

# Add rutx root to path for importing original tools
_rutx_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _rutx_root not in sys.path:
    sys.path.insert(0, _rutx_root)

from langchain_core.tools import tool

# Import from correct original tool files
from tools.bbot_tools import bbot_subdomain_enum as _bbot_subdomain_enum
from tools.amass_tools import amass_enum as _amass_enum
from tools.subfinder_tools import subfinder_enum as _subfinder_enum


def _format_subdomain_results(result: dict) -> str:
    """Format subdomain results for LLM consumption and save to file"""
    if not result.get("success"):
        return f"Subdomain enumeration failed: {result.get('error', 'Unknown error')}"
    
    subdomains = result.get("subdomains", [])
    domain = result.get('target') or result.get('domain', 'unknown')
    
    # AUTO-SAVE: Save subdomains to file for later use
    if subdomains:
        try:
            from snode_langchain.state import save_subdomains
            save_subdomains(subdomains, domain)
        except Exception as e:
            print(f"  ⚠ Could not save subdomains: {e}")
    
    output_lines = [
        f"Domain: {domain}",
        f"Subdomains found: {len(subdomains)}",
    ]
    
    # Include ASN/ISP information if available (from amass)
    asn_info = result.get("asn_info", [])
    hosting_providers = result.get("hosting_providers", [])
    ip_ranges = result.get("ip_ranges", [])
    
    if asn_info:
        output_lines.append("")
        output_lines.append("🌐 **Infrastructure Analysis:**")
        for asn in asn_info:
            output_lines.append(f"  ASN {asn['asn']}: {asn['org']} ({asn['name']})")
            for rng in asn.get("ranges", []):
                output_lines.append(f"    • {rng['cidr']} - {rng['subdomain_count']} subdomain(s)")
    
    if hosting_providers:
        output_lines.append("")
        output_lines.append(f"**Hosting Providers:** {', '.join(set(hosting_providers))}")
    
    output_lines.append("")
    output_lines.append("**Subdomains:**")
    
    # Show first 50 subdomains
    for sub in subdomains[:50]:
        output_lines.append(f"  • {sub}")
    
    if len(subdomains) > 50:
        output_lines.append(f"  ... and {len(subdomains) - 50} more")
    
    # Add note about saved file
    if subdomains:
        output_lines.append("")
        output_lines.append(f"📁 Subdomains saved to file for port scanning.")
    
    return "\n".join(output_lines)


@tool
def bbot_subdomain_enum(domain: str) -> str:
    """
    Discover subdomains using BBOT (active + passive scanning).
    Use when: user asks to find subdomains, enumerate hosts, or discover infrastructure.
    Fast and comprehensive. Takes 1-5 minutes.
    
    Args:
        domain: Root domain to enumerate (e.g., "example.com")
    
    Returns:
        List of discovered subdomains
    """
    result = _bbot_subdomain_enum(domain)
    return _format_subdomain_results(result)


@tool
def amass_enum(domain: str) -> str:
    """
    Discover subdomains using Amass (passive mode).
    Use when: user wants passive/stealthy subdomain discovery.
    Uses OSINT sources only, no direct scanning.
    
    Args:
        domain: Root domain to enumerate (e.g., "example.com")
    
    Returns:
        List of discovered subdomains from OSINT sources
    """
    result = _amass_enum(domain)
    return _format_subdomain_results(result)


@tool
def subfinder_enum(domain: str) -> str:
    """
    Discover subdomains using Subfinder (fast passive scanning).
    Use when: user wants quick subdomain discovery using online sources.
    Very fast, uses certificate transparency and DNS databases.
    
    Args:
        domain: Root domain to enumerate (e.g., "example.com")
    
    Returns:
        List of discovered subdomains from passive sources
    """
    result = _subfinder_enum(domain)
    return _format_subdomain_results(result)


# Export all tools
SUBDOMAIN_TOOLS = [
    bbot_subdomain_enum,
    amass_enum,
    subfinder_enum,
]
