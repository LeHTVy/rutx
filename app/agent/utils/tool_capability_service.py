"""
Tool Capability Service
=======================

Centralized service for tool capability detection and phase flag management.
Replaces hardcoded tool lists in graph.py with metadata-driven logic.
"""
from typing import Dict, Any, List, Set, Optional
from app.agent.utils.validators import TOOL_CAPABILITIES


class ToolCapabilityService:
    """
    Service for detecting tool capabilities and setting phase flags.
    
    Uses TOOL_CAPABILITIES metadata instead of hardcoded lists.
    """
    
    # Capability to flag mappings
    CAPABILITY_FLAGS = {
        "subdomain": "has_subdomains",
        "passive_recon": "has_subdomains",  # Also sets has_subdomains
        "port_scan": "has_ports",
        "fast_scan": "has_ports",  # Also sets has_ports
        "vuln_scan": "vuln_scan_done",
        "cve_detection": "vuln_scan_done",  # Also sets vuln_scan_done
        "directory_bruteforce": "has_web_discovery",
        "fuzzing": "has_web_discovery",
        "http_probe": "has_web_discovery",
    }
    
    # Tools that can detect security tech (WAF/CDN)
    SECURITY_TECH_DETECTION_TOOLS = {
        "httpx", "wafw00f", "whatweb", "clatscope"
    }
    
    @staticmethod
    def get_tool_capabilities(tool_name: str) -> List[str]:
        """Get capabilities for a tool from metadata."""
        return TOOL_CAPABILITIES.get(tool_name.lower(), [])
    
    @staticmethod
    def should_set_flag(tool_name: str, flag_name: str) -> bool:
        """
        Check if tool should set a specific flag based on capabilities.
        
        Args:
            tool_name: Name of the tool
            flag_name: Name of flag to check (has_subdomains, has_ports, etc.)
            
        Returns:
            True if tool has capability that maps to this flag
        """
        capabilities = ToolCapabilityService.get_tool_capabilities(tool_name)
        
        for capability in capabilities:
            mapped_flag = ToolCapabilityService.CAPABILITY_FLAGS.get(capability)
            if mapped_flag == flag_name:
                return True
        
        return False
    
    @staticmethod
    def update_context_flags(tool_name: str, context: Dict[str, Any], params: Dict[str, Any] = None) -> None:
        """
        Update context flags based on tool capabilities.
        
        Replaces hardcoded tool lists with capability-based detection.
        
        Args:
            tool_name: Name of the tool that was executed
            context: Context dict to update
            params: Tool parameters (optional, for setting last_domain/target)
        """
        params = params or {}
        
        # Check each flag type
        if ToolCapabilityService.should_set_flag(tool_name, "has_subdomains"):
            context["has_subdomains"] = True
            if params.get("domain"):
                context["last_domain"] = params.get("domain")
        
        if ToolCapabilityService.should_set_flag(tool_name, "has_ports"):
            context["has_ports"] = True
            if params.get("target"):
                context["last_target"] = params.get("target")
        
        if ToolCapabilityService.should_set_flag(tool_name, "vuln_scan_done"):
            context["vuln_scan_done"] = True
        
        if ToolCapabilityService.should_set_flag(tool_name, "has_web_discovery"):
            context["has_web_discovery"] = True
    
    @staticmethod
    def can_detect_security_tech(tool_name: str) -> bool:
        """
        Check if tool can detect security tech (WAF/CDN).
        
        Uses metadata + known security detection tools.
        """
        tool_lower = tool_name.lower()
        
        # Check explicit list
        if tool_lower in ToolCapabilityService.SECURITY_TECH_DETECTION_TOOLS:
            return True
        
        # Check capabilities
        capabilities = ToolCapabilityService.get_tool_capabilities(tool_name)
        if "tech_detection" in capabilities:
            return True
        
        return False


# Singleton instance
_tool_capability_service: Optional[ToolCapabilityService] = None


def get_tool_capability_service() -> ToolCapabilityService:
    """Get singleton ToolCapabilityService instance."""
    global _tool_capability_service
    if _tool_capability_service is None:
        _tool_capability_service = ToolCapabilityService()
    return _tool_capability_service
