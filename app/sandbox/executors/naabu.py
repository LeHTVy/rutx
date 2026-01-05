"""
Naabu Executor - Fast port scanning
"""
import os
import json
import shutil
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from utils.command_runner import CommandRunner


class NaabuExecutor:
    """
    Naabu port scanner.
    
    Ultra-fast port scanning using SYN/CONNECT probes.
    """
    
    def __init__(self):
        self.executable = self._find_executable()
    
    def _find_executable(self) -> str:
        """Find naabu executable"""
        home = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
        if home:
            home = f"/home/{home}"
        else:
            home = os.path.expanduser("~")
        
        for p in [f"{home}/go/bin/naabu", "/home/hellrazor/go/bin/naabu", "/root/go/bin/naabu"]:
            if Path(p).exists():
                return p
        
        path = shutil.which("naabu")
        return path if path else "naabu"
    
    def scan_from_file(self, target_file: str, ports: str = "22,80,443,8080,8443") -> Dict[str, List[int]]:
        """
        Scan targets from file.
        
        Args:
            target_file: Path to file with targets
            ports: Ports to scan
            
        Returns:
            Dict mapping host -> list of open ports
        """
        if not Path(target_file).exists():
            return {"error": f"File not found: {target_file}"}
        
        with open(target_file, 'r') as f:
            targets = [l.strip() for l in f if l.strip()]
        
        print(f"  🎯 Scanning {len(targets)} targets with naabu")
        print(f"  🔌 Ports: {ports}")
        
        cmd = [
            self.executable,
            "-list", str(target_file),
            "-p", ports,
            "-silent",
            "-json",
        ]
        
        result = CommandRunner.run(cmd, timeout=600, show_progress=True)
        
        if not result.success:
            return {"error": result.error or result.stderr}
        
        open_ports = {}
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                host = data.get('host', data.get('ip', 'unknown'))
                port = data.get('port')
                if host and port:
                    if host not in open_ports:
                        open_ports[host] = []
                    open_ports[host].append(port)
            except json.JSONDecodeError:
                continue
        
        return open_ports
    
    def quick_scan(self, target: str, top: int = 100) -> Dict[str, List[int]]:
        """Quick scan on top N ports"""
        cmd = [
            self.executable,
            "-host", target,
            "-top-ports", str(top),
            "-silent",
            "-json",
        ]
        
        result = CommandRunner.run(cmd, timeout=120, show_progress=True)
        
        ports = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                port = data.get('port')
                if port:
                    ports.append(port)
            except json.JSONDecodeError:
                continue
        
        return {target: ports}
