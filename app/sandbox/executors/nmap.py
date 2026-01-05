"""
Nmap Executor - Port scanning tool
"""
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Import utils from project root
import sys
from pathlib import Path
project_root = Path(__file__).parent.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
from utils.command_runner import CommandRunner


@dataclass
class ScanResult:
    """Result from a scan"""
    success: bool
    target: str
    open_ports: List[Dict[str, Any]]
    raw_output: str = ""
    error: str = ""
    elapsed_time: float = 0.0


class NmapExecutor:
    """
    Nmap port scanner executor.
    
    Clean interface for all nmap operations.
    """
    
    def __init__(self):
        self.executable = self._find_executable()
    
    def _find_executable(self) -> str:
        """Find nmap executable"""
        path = shutil.which("nmap")
        if path:
            return path
        
        # Common paths
        for p in ["/usr/bin/nmap", "/usr/local/bin/nmap"]:
            if Path(p).exists():
                return p
        
        return "nmap"  # Hope it's in PATH
    
    def quick_scan(self, target: str) -> ScanResult:
        """
        Quick port scan on top 100 ports.
        
        Args:
            target: IP or hostname to scan
            
        Returns:
            ScanResult with open ports
        """
        cmd = [
            self.executable,
            "-T4", "--top-ports", "100",
            "-oG", "-",
            target
        ]
        
        result = CommandRunner.run(cmd, timeout=120, show_progress=True)
        
        if not result.success:
            return ScanResult(
                success=False,
                target=target,
                open_ports=[],
                error=result.error or result.stderr
            )
        
        ports = self._parse_grepable(result.stdout)
        
        return ScanResult(
            success=True,
            target=target,
            open_ports=ports,
            raw_output=result.stdout,
            elapsed_time=result.elapsed_time
        )
    
    def service_detection(self, target: str, ports: str = "") -> ScanResult:
        """
        Detailed service version detection.
        
        Args:
            target: IP or hostname
            ports: Optional port specification
            
        Returns:
            ScanResult with service info
        """
        cmd = [self.executable, "-sV", "-T4", "-oG", "-"]
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)
        
        result = CommandRunner.run(cmd, timeout=300, show_progress=True)
        
        if not result.success:
            return ScanResult(
                success=False,
                target=target,
                open_ports=[],
                error=result.error or result.stderr
            )
        
        ports_found = self._parse_grepable(result.stdout)
        
        return ScanResult(
            success=True,
            target=target,
            open_ports=ports_found,
            raw_output=result.stdout,
            elapsed_time=result.elapsed_time
        )
    
    def scan_from_file(self, target_file: str, ports: str = "22,80,443,3389,8080,8443") -> Dict[str, List[int]]:
        """
        Scan multiple targets from a file using -iL.
        
        Args:
            target_file: Path to file with targets (one per line)
            ports: Ports to scan
            
        Returns:
            Dict mapping host -> list of open ports
        """
        if not Path(target_file).exists():
            return {"error": f"File not found: {target_file}"}
        
        # Count targets
        with open(target_file, 'r') as f:
            targets = [l.strip() for l in f if l.strip()]
        
        print(f"  🎯 Scanning {len(targets)} targets")
        print(f"  🔌 Ports: {ports}")
        
        cmd = [
            self.executable,
            "-iL", str(target_file),
            "-p", ports,
            "-sS", "-n", "-T4",
            "--open",
            "-oG", "-",
        ]
        
        result = CommandRunner.run(cmd, timeout=1800, show_progress=True)
        
        if not result.success:
            return {"error": result.error or result.stderr}
        
        # Parse results
        open_ports = {}
        for line in result.stdout.split('\n'):
            if 'Ports:' in line and 'Host:' in line:
                parts = line.split('Ports:')
                if len(parts) >= 2:
                    host = parts[0].replace('Host:', '').strip().split()[0]
                    ports_str = parts[1].strip()
                    
                    port_list = []
                    for port_info in ports_str.split(','):
                        if '/open/' in port_info:
                            p = int(port_info.split('/')[0].strip())
                            port_list.append(p)
                    
                    if port_list:
                        open_ports[host] = port_list
        
        return open_ports
    
    def vuln_scan(self, target: str) -> ScanResult:
        """
        Vulnerability scan using NSE scripts.
        
        Args:
            target: IP or hostname
            
        Returns:
            ScanResult with vulnerability findings
        """
        cmd = [
            self.executable,
            "-sV", "--script=vuln",
            "-T4",
            target
        ]
        
        result = CommandRunner.run(cmd, timeout=600, show_progress=True)
        
        return ScanResult(
            success=result.success,
            target=target,
            open_ports=[],
            raw_output=result.stdout,
            error=result.error or result.stderr,
            elapsed_time=result.elapsed_time
        )
    
    def _parse_grepable(self, output: str) -> List[Dict[str, Any]]:
        """Parse grepable nmap output"""
        ports = []
        
        for line in output.split('\n'):
            if 'Ports:' in line:
                # Format: Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
                parts_str = line.split('Ports:')[1].strip()
                for port_str in parts_str.split(','):
                    parts = port_str.strip().split('/')
                    if len(parts) >= 5 and parts[1] == 'open':
                        ports.append({
                            "port": int(parts[0]),
                            "state": parts[1],
                            "protocol": parts[2],
                            "service": parts[4] if parts[4] else "unknown"
                        })
        
        return ports
