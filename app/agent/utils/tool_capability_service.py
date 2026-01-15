"""
Tool Capability Service - Simplified Version

Uses tool registry category instead of hardcoded capabilities.
Main purpose: Update context flags based on tool category from registry.

Focus: No hardcode - uses tool registry metadata.
"""
from typing import Dict, Any
from app.tools.registry import get_registry, ToolCategory


# Map tool category to context flags (no hardcode - uses registry)
CATEGORY_TO_FLAGS = {
    ToolCategory.RECON: ["has_subdomains"],  # Recon tools typically find subdomains
    ToolCategory.OSINT: ["has_subdomains"],  # OSINT tools also find subdomains
    ToolCategory.SCANNING: ["has_ports"],  # Scanning tools find ports
    ToolCategory.VULN: ["vuln_scan_done"],  # Vuln tools complete vuln scanning
    ToolCategory.ENUM: ["has_web_discovery"],  # Enum tools discover web content
}

# Tools that can detect security tech (WAF/CDN) - minimal hardcode for special cases
SECURITY_TECH_DETECTION_TOOLS = {
    "httpx", "wafw00f", "whatweb", "clatscope"
}


class ToolCapabilityService:
    """
    Service for detecting tool capabilities and setting phase flags.
    
    Uses tool registry category instead of hardcoded capabilities.
    """
    
    @staticmethod
    def _get_tool_category(tool_name: str) -> ToolCategory:
        """Get tool category from registry."""
        registry = get_registry()
        spec = registry.tools.get(tool_name.lower())
        if spec and spec.category:
            return spec.category
        return None
    
    @staticmethod
    def should_set_flag(tool_name: str, flag_name: str) -> bool:
        """
        Check if tool should set a specific flag based on category.
        
        Args:
            tool_name: Name of the tool
            flag_name: Name of flag to check (has_subdomains, has_ports, etc.)
            
        Returns:
            True if tool category maps to this flag
        """
        category = ToolCapabilityService._get_tool_category(tool_name)
        if not category:
            return False
        
        flags = CATEGORY_TO_FLAGS.get(category, [])
        return flag_name in flags
    
    @staticmethod
    def update_context_flags(tool_name: str, context: Dict[str, Any], params: Dict[str, Any] = None) -> None:
        """
        Update context flags based on tool category from registry.
        
        No hardcode - uses tool registry metadata.
        
        Args:
            tool_name: Name of the tool that was executed
            context: Context dict to update
            params: Tool parameters (optional, for setting last_domain/target)
        """
        params = params or {}
        category = ToolCapabilityService._get_tool_category(tool_name)
        
        if not category:
            return  # Unknown tool, skip
        
        # Update flags based on category
        flags = CATEGORY_TO_FLAGS.get(category, [])
        
        if "has_subdomains" in flags:
            context["has_subdomains"] = True
            if params.get("domain"):
                context["last_domain"] = params.get("domain")
        
        if "has_ports" in flags:
            context["has_ports"] = True
            if params.get("target"):
                context["last_target"] = params.get("target")
        
        if "vuln_scan_done" in flags:
            context["vuln_scan_done"] = True
        
        if "has_web_discovery" in flags:
            context["has_web_discovery"] = True
    
    @staticmethod
    def can_detect_security_tech(tool_name: str) -> bool:
        """
        Check if tool can detect security tech (WAF/CDN).
        
        Uses explicit list for known security detection tools.
        """
        tool_lower = tool_name.lower()
        
        # Check explicit list (minimal hardcode for special cases)
        if tool_lower in SECURITY_TECH_DETECTION_TOOLS:
            return True
        
        # Could also check category if we add tech_detection category in future
        return False


# Singleton instance
_tool_capability_service: ToolCapabilityService = None


def get_tool_capability_service() -> ToolCapabilityService:
    """Get singleton ToolCapabilityService instance."""
    global _tool_capability_service
    if _tool_capability_service is None:
        _tool_capability_service = ToolCapabilityService()
    return _tool_capability_service
