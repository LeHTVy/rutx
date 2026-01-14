"""
System Resources - SNODE's Self-Knowledge
==========================================

Discovers and indexes system resources like wordlists, tools, configs.
Gives SNODE awareness of what's available on the system.
"""

import os
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class WordlistInfo:
    """Information about a wordlist."""
    name: str
    path: str
    size_bytes: int
    line_count: int
    category: str  # dirs, passwords, subdomains, etc.
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "size": self.size_bytes,
            "lines": self.line_count,
            "category": self.category
        }


@dataclass
class ToolInfo:
    """Information about an installed tool."""
    name: str
    path: str
    available: bool
    version: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "available": self.available,
            "version": self.version
        }


class SystemResources:
    """
    SNODE's self-knowledge about available system resources.
    
    Discovers:
    - Wordlists (local, system, custom)
    - Installed security tools
    - Configuration files
    - Workspace contents
    """
    
    # Common wordlist locations
    WORDLIST_PATHS = [
        Path("wordlists"),                          # Project wordlists
        Path("workspace/wordlists"),                # LLM-generated
        Path("/usr/share/wordlists"),               # Kali Linux
        Path("/usr/share/seclists"),                # SecLists
        Path.home() / ".snode" / "wordlists",       # User custom
    ]
    
    # Wordlist categories based on filename patterns
    WORDLIST_CATEGORIES = {
        "dirs": ["directory", "dir", "path", "common", "web", "raft"],
        "passwords": ["password", "pass", "rockyou", "cred"],
        "subdomains": ["subdomain", "dns", "sub"],
        "usernames": ["user", "name", "login"],
        "files": ["file", "ext", "backup"],
    }
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path(__file__).parent.parent.parent
        self.workspace = self.project_root / "workspace"
        self._wordlist_cache: List[WordlistInfo] = []
        self._tool_cache: Dict[str, ToolInfo] = {}
    
    def get_wordlists(self, category: str = None, refresh: bool = False) -> List[WordlistInfo]:
        """
        Find all wordlists on system.
        
        Args:
            category: Filter by category (dirs, passwords, subdomains, etc.)
            refresh: Force re-scan instead of using cache
            
        Returns:
            List of WordlistInfo objects
        """
        if not self._wordlist_cache or refresh:
            self._scan_wordlists()
        
        if category:
            return [w for w in self._wordlist_cache if w.category == category]
        return self._wordlist_cache
    
    def _scan_wordlists(self):
        """Scan all wordlist locations."""
        self._wordlist_cache = []
        
        for base_path in self.WORDLIST_PATHS:
            # Handle relative paths
            if not base_path.is_absolute():
                base_path = self.project_root / base_path
            
            if not base_path.exists():
                continue
            
            # Find all .txt files
            for txt_file in base_path.rglob("*.txt"):
                try:
                    size = txt_file.stat().st_size
                    # Count lines (efficient for large files)
                    with open(txt_file, 'r', errors='ignore') as f:
                        line_count = sum(1 for _ in f)
                    
                    category = self._categorize_wordlist(txt_file.name)
                    
                    self._wordlist_cache.append(WordlistInfo(
                        name=txt_file.name,
                        path=str(txt_file),
                        size_bytes=size,
                        line_count=line_count,
                        category=category
                    ))
                except Exception:
                    pass  
    
    def _categorize_wordlist(self, filename: str) -> str:
        """Guess wordlist category from filename."""
        filename_lower = filename.lower()
        
        for category, keywords in self.WORDLIST_CATEGORIES.items():
            if any(kw in filename_lower for kw in keywords):
                return category
        
        return "general"
    
    def get_best_wordlist(self, category: str, min_lines: int = 100) -> Optional[WordlistInfo]:
        """Get the best wordlist for a category."""
        wordlists = self.get_wordlists(category)
        
        # Filter by minimum size and sort by line count
        suitable = [w for w in wordlists if w.line_count >= min_lines]
        if suitable:
            return max(suitable, key=lambda w: w.line_count)
        
        # Fallback to any in category
        if wordlists:
            return wordlists[0]
        
        return None
    
    def get_tool(self, name: str) -> ToolInfo:
        """Check if a tool is installed."""
        if name in self._tool_cache:
            return self._tool_cache[name]
        
        path = shutil.which(name)
        info = ToolInfo(
            name=name,
            path=path or "",
            available=path is not None
        )
        
        self._tool_cache[name] = info
        return info
    
    def get_workspace_path(self, subdir: str = None) -> Path:
        """Get path to workspace directory."""
        if subdir:
            return self.workspace / subdir
        return self.workspace
    
    def get_workspace_contents(self) -> Dict[str, List[str]]:
        """List contents of the workspace."""
        contents = {}
        
        for subdir in ["wordlists", "scripts", "payloads", "notes"]:
            path = self.workspace / subdir
            if path.exists():
                contents[subdir] = [f.name for f in path.iterdir() if f.is_file()]
            else:
                contents[subdir] = []
        
        return contents
    
    def get_summary(self) -> str:
        """Get a human-readable summary of available resources."""
        wordlists = self.get_wordlists()
        workspace = self.get_workspace_contents()
        
        summary = "## Available Resources\n\n"
        
        # Wordlists by category
        summary += "### Wordlists\n"
        by_category = {}
        for w in wordlists:
            if w.category not in by_category:
                by_category[w.category] = []
            by_category[w.category].append(w)
        
        for cat, wls in by_category.items():
            summary += f"- **{cat}**: {len(wls)} files\n"
            for w in wls[:3]:  # Show first 3
                summary += f"  - {w.name} ({w.line_count:,} lines)\n"
        
        # Workspace
        summary += "\n### Workspace (Your Sandbox)\n"
        for subdir, files in workspace.items():
            if files:
                summary += f"- **{subdir}/**: {', '.join(files[:5])}\n"
            else:
                summary += f"- **{subdir}/**: (empty)\n"
        
        return summary
    
    def to_prompt_context(self) -> str:
        """Generate context string for LLM prompts."""
        wordlists = self.get_wordlists()
        
        # Format for prompt injection
        lines = ["Available wordlists:"]
        for w in wordlists[:10]:
            lines.append(f"- {w.path} ({w.line_count} lines, {w.category})")
        
        lines.append(f"\nWorkspace path: {self.workspace}")
        lines.append("You can create files in workspace/wordlists/, workspace/scripts/, etc.")
        
        return "\n".join(lines)


# Singleton instance
_resources: Optional[SystemResources] = None


def get_system_resources() -> SystemResources:
    """Get or create the system resources singleton."""
    global _resources
    if _resources is None:
        _resources = SystemResources()
    return _resources
