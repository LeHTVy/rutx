"""
BBOT Executor - Active + passive subdomain enumeration
"""
import os
import shutil
import json
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


class BbotExecutor:
    """
    BBOT subdomain enumerator.
    
    Comprehensive active + passive subdomain discovery.
    """
    
    def __init__(self):
        self.executable = self._find_executable()
    
    def _find_executable(self) -> str:
        """Find bbot executable"""
        # Check project venv first
        project_root = Path(__file__).parent.parent.parent.parent
        venv_bbot = project_root / "venv" / "bin" / "bbot"
        if venv_bbot.exists():
            return str(venv_bbot)
        
        path = shutil.which("bbot")
        return path if path else "bbot"
    
    def enumerate(self, domain: str) -> SubdomainResult:
        """
        Enumerate subdomains using BBOT.
        
        Args:
            domain: Root domain
            
        Returns:
            SubdomainResult with found subdomains
        """
        import tempfile
        from datetime import datetime
        
        # Create unique output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = domain.replace('.', '_')
        output_dir = f"/tmp/bbot_subdomain_{safe_domain}_{timestamp}"
        
        cmd = [
            self.executable,
            "-t", domain,
            "-p", "subdomain-enum",
            "-o", output_dir,
            "-y",  # Non-interactive
        ]
        
        result = CommandRunner.run(cmd, timeout=900, show_progress=True)
        
        subdomains = set()
        
        # Parse output.txt
        output_file = Path(output_dir) / "output.txt"
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and '.' in line and not line.startswith('['):
                        # Extract subdomain from line
                        parts = line.split()
                        for part in parts:
                            if domain in part.lower():
                                subdomains.add(part.lower())
        
        # Also try parsing NDJSON output
        ndjson_dir = Path(output_dir)
        for json_file in ndjson_dir.glob("*.ndjson"):
            try:
                with open(json_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if data.get("type") == "DNS_NAME":
                                host = data.get("data", "")
                                if host and domain in host.lower():
                                    subdomains.add(host.lower())
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue
        
        return SubdomainResult(
            success=len(subdomains) > 0 or result.success,
            domain=domain,
            subdomains=sorted(subdomains),
            error=result.error if not result.success else "",
            elapsed_time=result.elapsed_time
        )
