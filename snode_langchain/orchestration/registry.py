"""
Tool Registry - Capability-based tool grouping for intelligent orchestration
"""
from typing import Dict, List, Optional


# Tool capability mapping
# Maps capability names to lists of tool names that provide that capability
TOOL_CAPABILITIES: Dict[str, List[str]] = {
    # Subdomain enumeration tools
    "subdomain_enumeration": [
        "bbot_subdomain_enum",
        "amass_enum",
        "subfinder_enum",
    ],
    
    # Port scanning tools
    "port_scanning": [
        "nmap_quick_scan",
        "nmap_service_scan",
    ],
    
    # Service detection
    "service_detection": [
        "nmap_service_scan",
    ],
    
    # Vulnerability scanning
    "vulnerability_scanning": [
        "nmap_vuln_scan",
        "nuclei_scan",
    ],
    
    # Web fingerprinting
    "web_fingerprinting": [
        "whatweb_scan",
        "httpx_probe",
    ],
    
    # DNS enumeration
    "dns_enumeration": [
        "dnsx_enum",
    ],
}


# Reverse mapping: tool -> capabilities
TOOL_TO_CAPABILITIES: Dict[str, List[str]] = {}
for capability, tools in TOOL_CAPABILITIES.items():
    for tool in tools:
        if tool not in TOOL_TO_CAPABILITIES:
            TOOL_TO_CAPABILITIES[tool] = []
        TOOL_TO_CAPABILITIES[tool].append(capability)


def get_tools_for_capability(capability: str, agent=None) -> List[str]:
    """
    Get all tools that provide a given capability.
    If agent is provided, filter to only available tools.
    
    Args:
        capability: Capability name (e.g., "subdomain_enumeration")
        agent: Optional agent to filter by available tools
        
    Returns:
        List of tool names
    """
    tools = TOOL_CAPABILITIES.get(capability, [])
    
    if agent is not None:
        # Filter to only tools that are actually registered
        available = getattr(agent, 'tool_map', {})
        tools = [t for t in tools if t in available]
    
    return tools


def get_capabilities_for_tool(tool_name: str) -> List[str]:
    """Get all capabilities a tool provides"""
    return TOOL_TO_CAPABILITIES.get(tool_name, [])


def get_all_capabilities() -> List[str]:
    """Get list of all registered capabilities"""
    return list(TOOL_CAPABILITIES.keys())


def register_tool(tool_name: str, capabilities: List[str]) -> None:
    """
    Register a new tool with its capabilities.
    Useful for dynamically adding tools.
    """
    for capability in capabilities:
        if capability not in TOOL_CAPABILITIES:
            TOOL_CAPABILITIES[capability] = []
        if tool_name not in TOOL_CAPABILITIES[capability]:
            TOOL_CAPABILITIES[capability].append(tool_name)
    
    # Update reverse mapping
    TOOL_TO_CAPABILITIES[tool_name] = capabilities
