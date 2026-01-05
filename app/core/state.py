"""
State Management - Subdomain and discovery persistence
"""
from pathlib import Path
from datetime import datetime
from typing import Set, List, Optional
import json

from .config import get_config


class SubdomainState:
    """
    Manages subdomain discovery state and file persistence.
    """
    
    def __init__(self):
        config = get_config()
        self.base_dir = config.discoveries_dir / "subdomains"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._subdomains: Set[str] = set()
        self._current_domain: str = None
    
    def add(self, subdomains: List[str], domain: str) -> Optional[Path]:
        """Add and save subdomains to file (fails silently on permission errors)."""
        if not subdomains:
            return None
        
        domain = domain.lower().strip()
        self._current_domain = domain
        
        for sub in subdomains:
            if sub and isinstance(sub, str):
                self._subdomains.add(sub.lower().strip())
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = domain.replace('.', '_')
        filename = f"{safe_domain}_{timestamp}.txt"
        filepath = self.base_dir / filename
        
        sorted_subs = sorted(self._subdomains)
        
        try:
            with open(filepath, 'w') as f:
                f.write('\n'.join(sorted_subs))
            
            # Update symlinks
            for link_name in [f"latest_{safe_domain}.txt", "latest.txt"]:
                link_path = self.base_dir / link_name
                try:
                    if link_path.exists() or link_path.is_symlink():
                        link_path.unlink()
                    link_path.symlink_to(filepath.name)
                except PermissionError:
                    pass
            
            print(f"  📁 Saved {len(sorted_subs)} subdomains to: {filepath}")
            return filepath
        except PermissionError:
            # Can't save to disk, but return data in memory
            print(f"  ⚠️ Cannot save to disk (permission denied), {len(sorted_subs)} subdomains in memory")
            return None
        except Exception:
            return None
    
    def get_file(self, domain: str = None) -> Optional[Path]:
        """Get path to latest subdomain file."""
        if domain:
            safe_domain = domain.lower().replace('.', '_')
            latest = self.base_dir / f"latest_{safe_domain}.txt"
            if latest.exists():
                return latest
        
        global_latest = self.base_dir / "latest.txt"
        return global_latest if global_latest.exists() else None
    
    def load(self, domain: str = None) -> List[str]:
        """Load subdomains from file."""
        filepath = self.get_file(domain)
        if not filepath or not filepath.exists():
            return []
        
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    def clear(self):
        """Clear current session state."""
        self._subdomains.clear()
        self._current_domain = None


# Global singleton
_state: Optional[SubdomainState] = None

def get_subdomain_state() -> SubdomainState:
    """Get global SubdomainState instance."""
    global _state
    if _state is None:
        _state = SubdomainState()
    return _state


def save_subdomains(subdomains: List[str], domain: str) -> Optional[Path]:
    """Convenience function to save subdomains."""
    return get_subdomain_state().add(subdomains, domain)


def get_subdomain_file(domain: str = None) -> Optional[Path]:
    """Convenience function to get subdomain file path."""
    return get_subdomain_state().get_file(domain)


def load_subdomains(domain: str = None) -> List[str]:
    """Convenience function to load subdomains."""
    return get_subdomain_state().load(domain)
