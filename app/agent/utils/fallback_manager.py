"""
Fallback Manager - Graceful Failure Handling
=============================================

Implements a graceful fallback pattern:
- If step A fails, try step B
- Learn from past failures
- Suggest parameter adjustments

Key responsibilities:
1. Provide fallback tools when primary fails
2. Check if we should retry based on past failures
3. Suggest different parameters for retry
"""
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime


# Tool fallback chains - ordered by preference
TOOL_FALLBACKS: Dict[str, List[str]] = {
    # Subdomain enumeration
    "amass": ["subfinder", "assetfinder", "findomain"],
    "subfinder": ["amass", "assetfinder", "findomain"],
    "assetfinder": ["subfinder", "amass"],
    
    # Port scanning
    "nmap": ["masscan", "rustscan"],
    "masscan": ["nmap", "rustscan"],
    "rustscan": ["nmap", "masscan"],
    
    # Directory bruteforce
    "gobuster": ["ffuf", "dirsearch", "feroxbuster"],
    "ffuf": ["gobuster", "dirsearch", "feroxbuster"],
    "dirsearch": ["gobuster", "ffuf"],
    "feroxbuster": ["gobuster", "ffuf"],
    
    # Vulnerability scanning
    "nuclei": ["nikto"],
    "nikto": ["nuclei"],
    "wpscan": ["nuclei"],
    
    # SQL injection
    "sqlmap": ["ghauri"],
    
    # Brute force
    "hydra": ["medusa", "ncrack"],
    "medusa": ["hydra", "ncrack"],
    
    # DNS
    "dnsrecon": ["dnsx", "fierce"],
    "fierce": ["dnsrecon"],
}

# Error patterns and suggested fixes
ERROR_PATTERNS: List[Tuple[str, str, Dict[str, Any]]] = [
    # (pattern, suggestion, param_adjustments)
    ("timeout", "Use shorter timeout or scan fewer targets", {"timeout": 120}),
    ("timed out", "Use shorter timeout or scan fewer targets", {"timeout": 120}),
    ("connection refused", "Target may be down or blocking - try with delay", {"delay": 2}),
    ("rate limit", "Rate limited - use slower scan with delays", {"rate_limit": 10, "delay": 1}),
    ("permission denied", "Try with different privileges or ports", {}),
    ("no route to host", "Target unreachable - verify network/host", {}),
    ("name resolution", "DNS resolution failed - check domain", {}),
    ("ssl", "SSL/TLS error - try with different SSL options", {"skip_ssl": True}),
    ("certificate", "Certificate error - try with insecure flag", {"insecure": True}),
    ("not found", "Resource not found - try different path/port", {}),
    ("wordlist", "Wordlist issue - try different wordlist", {"wordlist": "/usr/share/wordlists/dirb/common.txt"}),
    ("memory", "Out of memory - reduce scope or batch size", {"batch_size": 10}),
]


@dataclass
class FallbackSuggestion:
    """Suggestion for handling a failure."""
    fallback_tool: Optional[str] = None
    param_adjustments: Dict[str, Any] = None
    message: str = ""
    should_retry: bool = True
    
    def __post_init__(self):
        if self.param_adjustments is None:
            self.param_adjustments = {}


class FallbackManager:
    """
    Handle failures gracefully.
    
    Usage:
        mgr = FallbackManager()
        
        # Before execution - check if we should even try
        if not mgr.should_retry("nmap", "example.com", attack_memory):
            use_fallback = mgr.get_fallback("nmap")
        
        # After failure - get suggestion
        suggestion = mgr.handle_failure("nmap", error_msg, params, attack_memory)
    """
    
    def __init__(self):
        self._registry = None
    
    @property
    def registry(self):
        """Lazy-load tool registry."""
        if self._registry is None:
            from app.tools.registry import get_registry
            self._registry = get_registry()
        return self._registry
    
    def get_fallback(self, failed_tool: str) -> Optional[str]:
        """
        Get alternative tool for failed one.
        
        Args:
            failed_tool: Tool that failed
            
        Returns:
            Name of available fallback tool, or None
        """
        fallbacks = TOOL_FALLBACKS.get(failed_tool, [])
        
        for fallback in fallbacks:
            if self.registry.is_available(fallback):
                return fallback
        
        return None
    
    def get_all_fallbacks(self, failed_tool: str) -> List[str]:
        """
        Get all available fallback tools.
        
        Args:
            failed_tool: Tool that failed
            
        Returns:
            List of available fallback tools
        """
        fallbacks = TOOL_FALLBACKS.get(failed_tool, [])
        return [t for t in fallbacks if self.registry.is_available(t)]
    
    def should_retry(self, tool: str, target: str, attack_memory=None) -> bool:
        """
        Check if we should retry based on past failures.
        
        Args:
            tool: Tool to check
            target: Target to check
            attack_memory: AttackMemory instance (optional)
            
        Returns:
            True if we should try, False if max retries reached
        """
        if attack_memory is None:
            return True  # No memory = always try
        
        try:
            # Check for past failures
            params = {"target": target, "domain": target}
            hint = attack_memory.get_learning_hint(tool, params)
            
            if hint:
                return hint.get("should_retry", True)
        except Exception:
            pass
        
        return True
    
    def get_retry_params(self, tool: str, error: str, original_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Suggest different params for retry.
        
        Args:
            tool: Tool that failed
            error: Error message
            original_params: Original parameters
            
        Returns:
            Adjusted parameters for retry
        """
        adjusted = original_params.copy()
        error_lower = error.lower()
        
        # Check error patterns
        for pattern, _, adjustments in ERROR_PATTERNS:
            if pattern in error_lower:
                adjusted.update(adjustments)
                break
        
        # Tool-specific adjustments
        if tool in ["nmap", "masscan"]:
            # Reduce ports for timeout errors
            if "timeout" in error_lower:
                # Use fewer ports
                current_ports = original_params.get("ports", "1-1000")
                if isinstance(current_ports, str) and "-" in current_ports:
                    # Reduce range
                    adjusted["ports"] = "1-100"
        
        elif tool in ["gobuster", "ffuf", "dirsearch"]:
            # Try different wordlist
            if "wordlist" in error_lower or "not found" in error_lower:
                wordlists = [
                    "/usr/share/wordlists/dirb/common.txt",
                    "/usr/share/seclists/Discovery/Web-Content/common.txt",
                    "wordlists/common.txt",
                ]
                current = original_params.get("wordlist", "")
                for wl in wordlists:
                    if wl != current:
                        adjusted["wordlist"] = wl
                        break
        
        elif tool == "hydra":
            # Add delay for rate limiting
            if "rate" in error_lower or "too many" in error_lower:
                adjusted["wait"] = 2
                adjusted["tasks"] = 4
        
        return adjusted
    
    def handle_failure(self, tool: str, error: str, params: Dict[str, Any], 
                      attack_memory=None) -> FallbackSuggestion:
        """
        Handle a tool failure and suggest next steps.
        
        Args:
            tool: Tool that failed
            error: Error message
            params: Parameters that were used
            attack_memory: AttackMemory instance (optional)
            
        Returns:
            FallbackSuggestion with recommended action
        """
        suggestion = FallbackSuggestion()
        error_lower = error.lower()
        
        # Record failure for learning
        if attack_memory:
            try:
                target = params.get("target") or params.get("domain") or ""
                attack_memory.record_failure(tool, params, error)
                
                # Check retry count
                hint = attack_memory.get_learning_hint(tool, params)
                if hint and not hint.get("should_retry", True):
                    suggestion.should_retry = False
                    suggestion.message = f"Max retries reached for {tool} on this target"
            except Exception:
                pass
        
        # Get fallback tool
        suggestion.fallback_tool = self.get_fallback(tool)
        
        # Get param adjustments
        suggestion.param_adjustments = self.get_retry_params(tool, error, params)
        
        # Generate message based on error
        for pattern, msg, _ in ERROR_PATTERNS:
            if pattern in error_lower:
                suggestion.message = msg
                break
        
        if not suggestion.message:
            suggestion.message = f"{tool} failed - try with different parameters or alternative tool"
        
        return suggestion
    
    def get_fallback_chain(self, primary_tool: str, task_type: str) -> List[str]:
        """
        Get ordered list of tools to try for a task.
        
        Args:
            primary_tool: First tool to try
            task_type: Type of task (for additional alternatives)
            
        Returns:
            Ordered list of tools to try
        """
        chain = [primary_tool] if self.registry.is_available(primary_tool) else []
        
        # Add direct fallbacks
        chain.extend(self.get_all_fallbacks(primary_tool))
        
        # Add task-based alternatives
        task_tools = {
            "subdomain": ["subfinder", "amass", "assetfinder"],
            "port_scan": ["nmap", "masscan", "rustscan"],
            "directory": ["gobuster", "ffuf", "dirsearch"],
            "vuln_scan": ["nuclei", "nikto"],
            "brute_force": ["hydra", "medusa"],
        }
        
        for alt in task_tools.get(task_type, []):
            if alt not in chain and self.registry.is_available(alt):
                chain.append(alt)
        
        return chain


# Singleton
_fallback_manager: Optional[FallbackManager] = None


def get_fallback_manager() -> FallbackManager:
    """Get or create the fallback manager singleton."""
    global _fallback_manager
    if _fallback_manager is None:
        _fallback_manager = FallbackManager()
    return _fallback_manager
