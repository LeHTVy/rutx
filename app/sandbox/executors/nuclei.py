"""
Nuclei Executor - Vulnerability scanning
"""
import os
import json
import shutil
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from utils.command_runner import CommandRunner


@dataclass
class VulnResult:
    """Vulnerability scan result"""
    success: bool
    target: str
    vulnerabilities: List[Dict[str, Any]]
    error: str = ""
    elapsed_time: float = 0.0


class NucleiExecutor:
    """
    Nuclei vulnerability scanner.
    
    Template-based security scanning.
    """
    
    def __init__(self):
        self.executable = self._find_executable()
    
    def _find_executable(self) -> str:
        """Find nuclei executable"""
        home = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
        if home:
            home = f"/home/{home}"
        else:
            home = os.path.expanduser("~")
        
        for p in [f"{home}/go/bin/nuclei", "/home/hellrazor/go/bin/nuclei", "/root/go/bin/nuclei"]:
            if Path(p).exists():
                return p
        
        path = shutil.which("nuclei")
        if path:
            return path
        
        # Not found
        return None
    
    def scan(self, target: str, severity: str = "critical,high,medium") -> VulnResult:
        """
        Run nuclei scan on target.
        
        Args:
            target: URL or host to scan
            severity: Comma-separated severity levels
            
        Returns:
            VulnResult with findings
        """
        # Check if nuclei is installed
        if not self.executable:
            return VulnResult(
                success=False,
                target=target,
                vulnerabilities=[],
                error="⚠️ TOOL NOT INSTALLED: 'nuclei' not found. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
        
        cmd = [
            self.executable,
            "-u", target,
            "-severity", severity,
            "-json",
            "-silent",
        ]
        
        # show_progress=False to suppress "Command failed" warning for exit code 2
        # (exit code 2 means no vulnerabilities found, not an error)
        result = CommandRunner.run(cmd, timeout=600, show_progress=False)
        
        vulns = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                vulns.append({
                    "template": data.get("template-id", "unknown"),
                    "name": data.get("info", {}).get("name", "Unknown"),
                    "severity": data.get("info", {}).get("severity", "unknown"),
                    "matched": data.get("matched-at", ""),
                    "description": data.get("info", {}).get("description", ""),
                })
            except json.JSONDecodeError:
                continue
        
        # Exit code 2 often means no vulnerabilities found - that's not an error
        if result.returncode == 2 and not vulns:
            return VulnResult(
                success=True,
                target=target,
                vulnerabilities=[],
                error="",
                elapsed_time=result.elapsed_time
            )
        
        # Actual error
        if not result.success and result.returncode not in [0, 2]:
            return VulnResult(
                success=False,
                target=target,
                vulnerabilities=vulns,
                error=result.error or f"Nuclei exited with code {result.returncode}",
                elapsed_time=result.elapsed_time
            )
        
        return VulnResult(
            success=True,
            target=target,
            vulnerabilities=vulns,
            error="",
            elapsed_time=result.elapsed_time
        )
