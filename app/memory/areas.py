"""
Memory Areas Classification for SNODE
=====================================

Memory areas help organize memories by type:
- MAIN: Core findings, targets, important facts
- FRAGMENTS: Small pieces of information
- SOLUTIONS: Solutions to problems, workarounds
- INSTRUMENTS: Tool configurations, custom scripts
"""
from enum import Enum


class MemoryArea(Enum):
    """
    Memory area classification.
    
    Used to organize memories in the vector database
    and improve retrieval accuracy.
    """
    MAIN = "main"
    """Core findings, targets, important facts"""
    
    FRAGMENTS = "fragments"
    """Small pieces of information"""
    
    SOLUTIONS = "solutions"
    """Solutions to problems, workarounds"""
    
    INSTRUMENTS = "instruments"
    """Tool configurations, custom scripts"""


def classify_memory_area(content: str, metadata: dict = None) -> MemoryArea:
    """
    Classify a memory into an area based on content and metadata.
    
    Args:
        content: Memory content text
        metadata: Optional metadata dict
        
    Returns:
        MemoryArea enum value
    """
    content_lower = content.lower()
    
    # Check metadata first (if explicitly set)
    if metadata:
        area_str = metadata.get("area")
        if area_str:
            try:
                return MemoryArea(area_str)
            except ValueError:
                pass
    
    # Classify based on content patterns
    # MAIN: Targets, domains, subdomains, IPs, critical findings
    main_keywords = [
        "target", "domain", "subdomain", "ip address", "host",
        "vulnerability", "cve", "exploit", "critical", "high severity",
        "port", "service", "open", "discovered", "found"
    ]
    if any(kw in content_lower for kw in main_keywords):
        return MemoryArea.MAIN
    
    # SOLUTIONS: How-to, fix, workaround, solution, bypass
    solution_keywords = [
        "solution", "fix", "workaround", "bypass", "how to",
        "method", "technique", "approach", "resolved", "solved"
    ]
    if any(kw in content_lower for kw in solution_keywords):
        return MemoryArea.SOLUTIONS
    
    # INSTRUMENTS: Tool config, script, command, setup
    instrument_keywords = [
        "tool", "script", "command", "config", "setup",
        "wordlist", "payload", "template", "custom"
    ]
    if any(kw in content_lower for kw in instrument_keywords):
        return MemoryArea.INSTRUMENTS
    
    # Default to FRAGMENTS for small/incomplete info
    return MemoryArea.FRAGMENTS
