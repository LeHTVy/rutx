"""
Amass Executor - OSINT subdomain enumeration
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


class AmassExecutor:
    """
    Amass subdomain enumerator.
    
    Passive OSINT-based subdomain discovery.
    """
    
    def __init__(self):
        self.executable = self._find_executable()
    
    def _find_executable(self) -> str:
        """Find amass executable"""
        # Check snap first
        if Path("/snap/bin/amass").exists():
            return "/snap/bin/amass"
        
        # Check Go paths
        home = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
        if home:
            home = f"/home/{home}"
        else:
            home = os.path.expanduser("~")
        
        for p in [f"{home}/go/bin/amass", "/root/go/bin/amass"]:
            if Path(p).exists():
                return p
        
        path = shutil.which("amass")
        return path if path else "amass"
    
    def enumerate(self, domain: str) -> SubdomainResult:
        """
        Enumerate subdomains using Amass passive mode.
        
        Args:
            domain: Root domain
            
        Returns:
            SubdomainResult with found subdomains
        """
        cmd = [
            self.executable,
            "enum",
            "-d", domain,
        ]
        
        result = CommandRunner.run(cmd, timeout=300, show_progress=True)
        
        if not result.success:
            return SubdomainResult(
                success=False,
                domain=domain,
                subdomains=[],
                error=result.error or result.stderr
            )
        
        # Parse output - one subdomain per line
        subdomains = []
        for line in result.stdout.split('\n'):
            line = line.strip().lower()
            if line and '.' in line and domain in line:
                # Filter out non-subdomain lines
                if not any(x in line for x in ['[', ']', 'error', 'warning']):
                    subdomains.append(line)
        
        return SubdomainResult(
            success=True,
            domain=domain,
            subdomains=sorted(set(subdomains)),
            elapsed_time=result.elapsed_time
        )
