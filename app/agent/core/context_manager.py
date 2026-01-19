"""
Context Manager - Centralized Context Handling for SNODE
=========================================================

Single source of truth for session context.
All nodes and agents use this instead of scattered context dicts.

Key responsibilities:
1. Maintain target/domain across all nodes
2. Aggregate context from SharedMemory and AttackMemory
3. Provide prioritized target resolution
4. Validate context updates
"""
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from datetime import datetime
import re

from app.ui import get_logger

logger = get_logger()


@dataclass
class SessionContext:
    """
    Immutable snapshot of context for a single request.
    
    This is the structured representation passed between nodes,
    replacing the ad-hoc Dict[str, Any] that was losing data.
    """
    # Target information (prioritized: target_domain > last_domain > url > ip)
    target_domain: Optional[str] = None
    target_ip: Optional[str] = None
    url_target: Optional[str] = None
    last_domain: Optional[str] = None
    last_candidate: Optional[str] = None  # For target verification flow
    
    # Discovered assets
    subdomains: List[str] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    detected_tech: List[str] = field(default_factory=list)
    vulns_found: List[Dict[str, Any]] = field(default_factory=list)
    
    # Session tracking
    tools_run: List[str] = field(default_factory=list)
    current_phase: int = 1
    last_agent: Optional[str] = None
    current_agent: Optional[str] = None
    
    # Counts (for quick access)
    subdomain_count: int = 0
    port_count: int = 0
    
    # Flags
    has_subdomains: bool = False
    has_ports: bool = False
    is_correction: bool = False  # User correcting target
    
    # Timestamps
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def get_target(self) -> Optional[str]:
        """
        Get the prioritized target.
        
        Priority order:
        1. target_domain (explicitly verified)
        2. last_domain (from conversation)
        3. Extract from url_target
        4. target_ip
        """
        if self.target_domain and self._is_valid_domain(self.target_domain):
            return self.target_domain
        if self.last_domain and self._is_valid_domain(self.last_domain):
            return self.last_domain
        if self.url_target:
            domain = self._extract_domain_from_url(self.url_target)
            if domain:
                return domain
        if self.target_ip and self._is_valid_ip(self.target_ip):
            return self.target_ip
        return None
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if string looks like a valid domain."""
        if not domain:
            return False
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string looks like a valid IP."""
        if not ip:
            return False
        pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, ip))
    
    def _extract_domain_from_url(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc if parsed.netloc else None
        except:
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionContext":
        """
        Create SessionContext from dictionary.
        
        Handles legacy context dicts gracefully.
        """
        # Map legacy keys to new structure
        mapped = {}
        
        # Target fields
        mapped["target_domain"] = data.get("target_domain")
        mapped["target_ip"] = data.get("target_ip")
        mapped["url_target"] = data.get("url_target")
        mapped["last_domain"] = data.get("last_domain")
        mapped["last_candidate"] = data.get("last_candidate")
        
        # Assets
        mapped["subdomains"] = data.get("subdomains", [])
        mapped["open_ports"] = data.get("open_ports", [])
        mapped["detected_tech"] = data.get("detected_tech", [])
        mapped["vulns_found"] = data.get("vulns_found", [])
        
        # Session
        mapped["tools_run"] = data.get("tools_run", [])
        mapped["current_phase"] = data.get("current_phase", 1)
        mapped["last_agent"] = data.get("last_agent")
        mapped["current_agent"] = data.get("current_agent")
        
        # Counts
        mapped["subdomain_count"] = data.get("subdomain_count", len(mapped["subdomains"]))
        mapped["port_count"] = data.get("port_count", len(mapped["open_ports"]))
        
        # Flags
        mapped["has_subdomains"] = data.get("has_subdomains", len(mapped["subdomains"]) > 0)
        mapped["has_ports"] = data.get("has_ports", len(mapped["open_ports"]) > 0)
        mapped["is_correction"] = data.get("is_correction", False)
        
        return cls(**{k: v for k, v in mapped.items() if v is not None or k in ["target_domain", "target_ip"]})
    
    def merge_with(self, updates: Dict[str, Any]) -> "SessionContext":
        """
        Create new SessionContext with updates applied.
        
        Immutable pattern - returns new instance.
        """
        current = self.to_dict()
        
        # Handle list merges specially (don't replace, extend)
        list_fields = ["subdomains", "open_ports", "detected_tech", "vulns_found", "tools_run"]
        for field in list_fields:
            if field in updates and updates[field]:
                existing = current.get(field, [])
                new_items = updates[field]
                if isinstance(new_items, list):
                    # Dedupe while preserving order
                    combined = existing + [x for x in new_items if x not in existing]
                    updates[field] = combined
        
        # Apply updates
        current.update(updates)
        current["updated_at"] = datetime.now().isoformat()
        
        # Update counts
        current["subdomain_count"] = len(current.get("subdomains", []))
        current["port_count"] = len(current.get("open_ports", []))
        current["has_subdomains"] = current["subdomain_count"] > 0
        current["has_ports"] = current["port_count"] > 0
        
        return SessionContext.from_dict(current)


class ContextManager:
    """
    Centralized context handling - single source of truth.
    
    Aggregates from:
    - Session state (current request)
    - SharedMemory (inter-agent communication)
    - AttackMemory (persistent findings)
    
    Usage:
        ctx_mgr = get_context_manager()
        context = ctx_mgr.get_context()
        target = context.get_target()
    """
    
    def __init__(self):
        self._session_context: Optional[SessionContext] = None
        self._shared_memory = None
        self._attack_memory = None
    
    @property
    def shared_memory(self):
        """Lazy-load shared memory."""
        if self._shared_memory is None:
            from app.memory import get_shared_memory
            self._shared_memory = get_shared_memory()
        return self._shared_memory
    
    @property
    def attack_memory(self):
        """Lazy-load attack memory."""
        if self._attack_memory is None:
            from app.memory import get_attack_memory
            self._attack_memory = get_attack_memory()
        return self._attack_memory
    
    def get_context(self) -> SessionContext:
        """
        Get current aggregated context.
        
        Combines:
        1. Session context (current request)
        2. SharedMemory (inter-agent data)
        3. AttackMemory persistent facts
        
        Returns new SessionContext with all data merged.
        """
        if self._session_context is None:
            self._session_context = SessionContext()
        
        # Start with session context
        context = self._session_context
        
        # Merge in SharedMemory data
        try:
            shared = self.shared_memory.to_dict()
            context = context.merge_with(shared)
        except Exception as e:
            logger.warning(f"SharedMemory merge failed: {e}", icon="")
        
        # Add SessionMemory data (subdomains, ports, vulns from session)
        try:
            if self.attack_memory:
                # attack_memory is now SessionMemory - access agent_context
                agent_ctx = self.attack_memory.agent_context
                
                # Get subdomains
                if agent_ctx.subdomains:
                    context = context.merge_with({"subdomains": agent_ctx.subdomains})
                
                # Get ports
                if agent_ctx.open_ports:
                    context = context.merge_with({"open_ports": agent_ctx.open_ports})
                
                # Get vulns
                if agent_ctx.vulnerabilities:
                    context = context.merge_with({"vulns_found": agent_ctx.vulnerabilities})
        except Exception as e:
            logger.warning(f"SessionMemory merge failed: {e}", icon="")
        
        return context
    
    def update_context(self, updates: Dict[str, Any]) -> SessionContext:
        """
        Update context with validation.
        
        Args:
            updates: Dictionary of fields to update
            
        Returns:
            New SessionContext with updates applied
        """
        if self._session_context is None:
            self._session_context = SessionContext()
        
        # Validate target updates
        if "target_domain" in updates and updates["target_domain"]:
            domain = updates["target_domain"]
            if not self._validate_target(domain):
                logger.warning(f"Invalid target_domain: {domain}", icon="")
                updates.pop("target_domain")
        
        # Apply updates
        self._session_context = self._session_context.merge_with(updates)
        
        # Sync to SharedMemory for inter-agent access
        try:
            self._sync_to_shared_memory(updates)
        except Exception as e:
            logger.warning(f"SharedMemory sync failed: {e}", icon="")
        
        return self._session_context
    
    def set_target(self, target: str, source: str = "user") -> bool:
        """
        Set the primary target with validation.
        
        Args:
            target: Domain, IP, or URL
            source: Where this target came from (user, verification, etc.)
            
        Returns:
            True if target was set successfully
        """
        if not target:
            return False
        
        # Determine target type
        if self._is_url(target):
            domain = self._extract_domain(target)
            self.update_context({
                "url_target": target,
                "target_domain": domain,
                "last_domain": domain
            })
        elif self._is_ip(target):
            self.update_context({
                "target_ip": target,
                "last_domain": target
            })
        elif self._is_domain(target):
            self.update_context({
                "target_domain": target,
                "last_domain": target
            })
        else:
            # Might be a company name - store as candidate
            self.update_context({"last_candidate": target})
            return False
        
        logger.info(f"Target set: {target} (source: {source})", icon="")
        return True
    
    def get_target(self) -> Optional[str]:
        """Get the prioritized target."""
        context = self.get_context()
        return context.get_target()
    
    def clear(self) -> None:
        """Clear session context (for new engagement)."""
        self._session_context = SessionContext()
    
    def _validate_target(self, target: str) -> bool:
        """Validate target format."""
        return self._is_domain(target) or self._is_ip(target) or self._is_url(target)
    
    def _is_domain(self, s: str) -> bool:
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, s))
    
    def _is_ip(self, s: str) -> bool:
        pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, s))
    
    def _is_url(self, s: str) -> bool:
        return s.startswith("http://") or s.startswith("https://")
    
    def _extract_domain(self, url: str) -> Optional[str]:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc if parsed.netloc else None
        except:
            return None
    
    def _sync_to_shared_memory(self, updates: Dict[str, Any]) -> None:
        """Sync relevant updates to SharedMemory for inter-agent access."""
        # shared_memory is now AgentContext from app.memory.session
        ctx = self.shared_memory
        
        # Sync domain
        if updates.get("target_domain"):
            ctx.domain = updates["target_domain"]
        if updates.get("last_domain"):
            ctx.domain = updates["last_domain"]
        
        # Sync subdomains
        if updates.get("subdomains"):
            ctx.add_subdomains(updates["subdomains"])
        
        # Sync technologies  
        if updates.get("detected_tech"):
            for tech in updates["detected_tech"]:
                ctx.add_technology(tech)
        
        # Sync tools run
        if updates.get("tools_run"):
            for tool in updates["tools_run"]:
                ctx.add_tool_run(tool)


# Singleton instance
_context_manager: Optional[ContextManager] = None


def get_context_manager() -> ContextManager:
    """Get or create the context manager singleton."""
    global _context_manager
    if _context_manager is None:
        _context_manager = ContextManager()
    return _context_manager


def reset_context_manager() -> None:
    """Reset context manager (for new engagement)."""
    global _context_manager
    if _context_manager:
        _context_manager.clear()
    _context_manager = None
