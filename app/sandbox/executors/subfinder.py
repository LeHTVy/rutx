"""
Subfinder Executor - Passive subdomain enumeration
"""
import os
import shutil
from pathlib import Path
from typing import List
from dataclasses import dataclass

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from utils.command_runner import CommandRunner


@dataclass
class SubdomainResult:
    """Result from subdomain enumeration"""
    success: bool
    domain: str
    subdomains: List[str]
    error: str = ""
    elapsed_time: float = 0.0


class SubfinderExecutor:
    """
    Subfinder subdomain enumerator.
    
    Fast passive subdomain discovery using online sources.
    """
    
    def __init__(self):
        self.executable = self._find_executable()
    
    def _find_executable(self) -> str:
        """Find subfinder executable"""
        # Check common Go binary paths
        home = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
        if home:
            home = f"/home/{home}"
        else:
            home = os.path.expanduser("~")
        
        paths = [
            f"{home}/go/bin/subfinder",
            "/home/hellrazor/go/bin/subfinder",
            "/root/go/bin/subfinder",
        ]
        
        for p in paths:
            if Path(p).exists():
                return p
        
        path = shutil.which("subfinder")
        return path if path else "subfinder"
    
    def enumerate(self, domain: str, timeout: int = 30) -> SubdomainResult:
        """
        Enumerate subdomains for a domain.
        
        Args:
            domain: Root domain (e.g., "example.com")
            timeout: Max time in seconds
            
        Returns:
            SubdomainResult with found subdomains
        """
        cmd = [
            self.executable,
            "-d", domain,
            "-silent",
            "-max-time", str(timeout),
        ]
        
        result = CommandRunner.run(cmd, timeout=timeout + 30, show_progress=True)
        
        if not result.success:
            return SubdomainResult(
                success=False,
                domain=domain,
                subdomains=[],
                error=result.error or result.stderr
            )
        
        # Parse output - one subdomain per line
        subdomains = [
            line.strip().lower()
            for line in result.stdout.split('\n')
            if line.strip() and '.' in line
        ]
        
        return SubdomainResult(
            success=True,
            domain=domain,
            subdomains=subdomains,
            elapsed_time=result.elapsed_time
        )
