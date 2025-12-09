"""
SNODE LangChain - Shodan OSINT Tools
Wrapped Shodan intelligence tools for LangChain agent
"""
import sys
import os

# Add rutx root to path for importing original tools
_rutx_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _rutx_root not in sys.path:
    sys.path.insert(0, _rutx_root)

from langchain_core.tools import tool

# Import from correct original tool file
from tools.shodan_tools import shodan_lookup as _shodan_lookup


@tool
def shodan_lookup(target: str) -> str:
    """
    Query Shodan for intelligence about an IP address.
    Use when: user asks about known services, historical data, or threat intelligence.
    Provides information about ports, services, and CVEs from Shodan database.
    
    Args:
        target: IP address to look up in Shodan
    
    Returns:
        Shodan intelligence including ports, services, and vulnerabilities
    """
    result = _shodan_lookup(target)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        if "not found" in str(error_msg).lower():
            return f"No Shodan data for {target} (not indexed)"
        return f"Shodan lookup failed: {error_msg}"
    
    output_lines = [
        f"Target: {target}",
        f"Organization: {result.get('org', 'Unknown')}",
        f"ISP: {result.get('isp', 'Unknown')}",
        f"Country: {result.get('country_name', 'Unknown')}",
        ""
    ]
    
    # Ports and services
    ports = result.get("ports", [])
    if ports:
        output_lines.append(f"Open ports ({len(ports)}):")
        for port in ports[:20]:
            output_lines.append(f"  • Port {port}")
    
    # CVEs
    vulns = result.get("vulns", [])
    if vulns:
        output_lines.append(f"\nVulnerabilities ({len(vulns)}):")
        for cve in vulns[:10]:
            output_lines.append(f"  • {cve}")
        if len(vulns) > 10:
            output_lines.append(f"  ... and {len(vulns) - 10} more")
    
    return "\n".join(output_lines)


# Export all tools
SHODAN_TOOLS = [
    shodan_lookup,
]
