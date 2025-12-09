"""
Subdomain State Manager

Manages subdomain discovery state and file persistence.
Allows saving subdomains to files and using them for subsequent scans.
"""
import os
from pathlib import Path
from datetime import datetime
from typing import Set, List, Optional
import json


class SubdomainState:
    """
    Manages subdomain discovery state and file persistence.
    
    Subdomains are saved to:
    - ~/.snode/discoveries/subdomains/{domain}_{date}.txt
    - Latest discovery is also symlinked to latest_{domain}.txt
    """
    
    def __init__(self, base_dir: str = None):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            # Use project directory for consistent access
            self.base_dir = Path("/home/hellrazor/rutx/discoveries/subdomains")
        
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._subdomains: Set[str] = set()
        self._current_domain: str = None
    
    def add(self, subdomains: List[str], domain: str) -> Path:
        """
        Add subdomains and save to file.
        
        Args:
            subdomains: List of subdomains found
            domain: The root domain (e.g., 'example.com')
            
        Returns:
            Path to the saved file
        """
        if not subdomains:
            return None
        
        # Normalize domain name
        domain = domain.lower().strip()
        self._current_domain = domain
        
        # Add to internal state
        for sub in subdomains:
            if sub and isinstance(sub, str):
                self._subdomains.add(sub.lower().strip())
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = domain.replace('.', '_')
        filename = f"{safe_domain}_{timestamp}.txt"
        filepath = self.base_dir / filename
        
        # Write subdomains to file (sorted, one per line)
        sorted_subs = sorted(self._subdomains)
        with open(filepath, 'w') as f:
            f.write('\n'.join(sorted_subs))
        
        # Update latest symlink
        latest_link = self.base_dir / f"latest_{safe_domain}.txt"
        if latest_link.exists() or latest_link.is_symlink():
            latest_link.unlink()
        latest_link.symlink_to(filepath.name)
        
        # Also create a global "latest" file
        global_latest = self.base_dir / "latest.txt"
        if global_latest.exists() or global_latest.is_symlink():
            global_latest.unlink()
        global_latest.symlink_to(filepath.name)
        
        print(f"  📁 Saved {len(sorted_subs)} subdomains to: {filepath}")
        
        return filepath
    
    def get_file(self, domain: str = None) -> Optional[Path]:
        """
        Get path to the latest subdomain file for a domain.
        
        Args:
            domain: The domain to get file for (None = most recent)
            
        Returns:
            Path to file, or None if not found
        """
        if domain:
            safe_domain = domain.lower().replace('.', '_')
            latest_link = self.base_dir / f"latest_{safe_domain}.txt"
            if latest_link.exists():
                return latest_link
        else:
            # Return most recent file
            global_latest = self.base_dir / "latest.txt"
            if global_latest.exists():
                return global_latest
        
        return None
    
    def load(self, domain: str = None) -> List[str]:
        """
        Load subdomains from file.
        
        Args:
            domain: The domain to load (None = most recent)
            
        Returns:
            List of subdomains
        """
        filepath = self.get_file(domain)
        if not filepath or not filepath.exists():
            return []
        
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    def get_all(self) -> List[str]:
        """Get all subdomains in current session state"""
        return sorted(self._subdomains)
    
    def clear(self):
        """Clear current session state (files remain)"""
        self._subdomains.clear()
        self._current_domain = None
    
    def get_count(self) -> int:
        """Get count of subdomains in current state"""
        return len(self._subdomains)


# Global singleton instance
_subdomain_state = None

def get_subdomain_state() -> SubdomainState:
    """Get global SubdomainState instance"""
    global _subdomain_state
    if _subdomain_state is None:
        _subdomain_state = SubdomainState()
    return _subdomain_state


def save_subdomains(subdomains: List[str], domain: str) -> Optional[Path]:
    """Convenience function to save subdomains"""
    return get_subdomain_state().add(subdomains, domain)


def get_subdomain_file(domain: str = None) -> Optional[Path]:
    """Convenience function to get subdomain file path"""
    return get_subdomain_state().get_file(domain)


def load_subdomains(domain: str = None) -> List[str]:
    """Convenience function to load subdomains from file"""
    return get_subdomain_state().load(domain)
