"""
Masscan Executor - High-speed port scanning
"""
import os
import json
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from utils.command_runner import CommandRunner


class MasscanExecutor:
    """
    Masscan port scanner.
    
    Fastest port scanner - best for large target lists.
    """
    
    def __init__(self):
        self.executable = self._find_executable()
    
    def _find_executable(self) -> str:
        """Find masscan executable"""
        for p in ["/usr/bin/masscan", "/usr/local/bin/masscan"]:
            if Path(p).exists():
                return p
        
        path = shutil.which("masscan")
        return path if path else "masscan"
    
    def scan_from_file(self, target_file: str, ports: str = "22,80,443,8080,8443", rate: int = 1000) -> Dict[str, List[int]]:
        """
        Scan targets from file with masscan.
        
        Args:
            target_file: Path to file with targets
            ports: Ports to scan
            rate: Packets per second
            
        Returns:
            Dict mapping host -> list of open ports
        """
        if not Path(target_file).exists():
            return {"error": f"File not found: {target_file}"}
        
        with open(target_file, 'r') as f:
            targets = [l.strip() for l in f if l.strip()]
        
        print(f"  🎯 Scanning {len(targets)} targets with masscan")
        print(f"  🔌 Ports: {ports}")
        print(f"  ⚡ Rate: {rate} pps")
        
        # Temp output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
            output_file = tf.name
        
        try:
            cmd = [
                self.executable,
                "-iL", str(target_file),
                "-p", ports,
                "--rate", str(rate),
                "-oJ", output_file,
            ]
            
            result = CommandRunner.run(cmd, timeout=600, show_progress=True)
            
            open_ports = {}
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    content = f.read().strip()
                    if content.startswith('['):
                        data = json.loads(content)
                    else:
                        data = [json.loads(line) for line in content.split('\n') if line.strip()]
                    
                    for entry in data:
                        if isinstance(entry, dict):
                            ip = entry.get('ip', 'unknown')
                            for port_info in entry.get('ports', []):
                                port = port_info.get('port')
                                if ip and port:
                                    if ip not in open_ports:
                                        open_ports[ip] = []
                                    open_ports[ip].append(port)
            
            return open_ports
            
        finally:
            if Path(output_file).exists():
                os.unlink(output_file)
