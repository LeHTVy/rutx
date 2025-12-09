# Orchestration module - LangGraph-based workflows
from .base import BaseOrchestrator, TaskStatus, WorkflowStatus
from .registry import (
    get_tools_for_capability,
    get_capabilities_for_tool,
    get_all_capabilities,
    TOOL_CAPABILITIES,
)

# LangGraph-based workflows
try:
    from .langgraph_recon import SmartReconGraph
    from .langgraph_subdomain import (
        SubdomainGraph, 
        is_subdomain_query, 
        extract_domain_from_query
    )
    from .langgraph_vulnscan import (
        VulnScanGraph,
        is_vulnscan_query,
    )
    from .langgraph_attacksurface import (
        AttackSurfaceGraph,
        is_attacksurface_query,
    )
    LANGGRAPH_AVAILABLE = True
except ImportError as e:
    print(f"Warning: LangGraph workflows not available: {e}")
    SmartReconGraph = None
    SubdomainGraph = None
    VulnScanGraph = None
    AttackSurfaceGraph = None
    is_subdomain_query = None
    is_vulnscan_query = None
    is_attacksurface_query = None
    extract_domain_from_query = None
    LANGGRAPH_AVAILABLE = False

# Available workflows registry
WORKFLOWS = {
    "smart_recon": SmartReconGraph,
    "subdomain": SubdomainGraph,
    "vulnscan": VulnScanGraph,
    "attack_surface": AttackSurfaceGraph,
}

__all__ = [
    "BaseOrchestrator",
    "TaskStatus",
    "WorkflowStatus",
    # LangGraph workflows
    "SmartReconGraph",
    "SubdomainGraph",
    "VulnScanGraph",
    "AttackSurfaceGraph",
    # Intent detection
    "is_subdomain_query",
    "is_vulnscan_query",
    "is_attacksurface_query",
    "extract_domain_from_query",
    # Registry
    "WORKFLOWS",
    "LANGGRAPH_AVAILABLE",
    "get_tools_for_capability",
    "get_capabilities_for_tool",
    "get_all_capabilities",
    "TOOL_CAPABILITIES",
]
