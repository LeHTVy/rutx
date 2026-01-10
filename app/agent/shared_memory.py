"""
SNODE Shared Agent Memory
=========================

Central memory context that all 6 agents share.
Allows agents to communicate findings to each other.
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json


@dataclass
class AgentMemory:
    """
    Shared memory that all agents can read/write.
    
    This is the "message board" where agents post findings
    for other agents to use.
    """
    
    # Target info
    domain: str = ""
    targets: List[str] = field(default_factory=list)
    
    # Phase 1: Recon findings
    subdomains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    asns: List[Dict] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    
    # Phase 2: Scan findings
    open_ports: List[Dict] = field(default_factory=list)  # {port, service, version, host}
    services: List[Dict] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    
    # Phase 3: Vulnerability findings
    vulnerabilities: List[Dict] = field(default_factory=list)  # {type, severity, target, cve}
    misconfigs: List[Dict] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    
    # Phase 4: Exploitation findings
    exploits_attempted: List[Dict] = field(default_factory=list)
    successful_exploits: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)  # {username, password, service}
    shells: List[Dict] = field(default_factory=list)  # {type, host, access_level}
    
    # Phase 5: Post-exploitation findings
    privesc_results: List[Dict] = field(default_factory=list)
    lateral_movement: List[Dict] = field(default_factory=list)
    loot: List[Dict] = field(default_factory=list)  # files, data exfiltrated
    
    # Agent communication log
    agent_messages: List[Dict] = field(default_factory=list)
    
    # Tools run (for all phases)
    tools_run: List[str] = field(default_factory=list)
    
    # Current phase
    current_phase: int = 1
    phase_complete: Dict[int, bool] = field(default_factory=lambda: {1: False, 2: False, 3: False, 4: False, 5: False, 6: False})
    
    def add_finding(self, agent_name: str, finding_type: str, data: Any):
        """Agent adds a finding to shared memory."""
        message = {
            "agent": agent_name,
            "type": finding_type,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }
        self.agent_messages.append(message)
        
        # Auto-categorize common finding types
        if finding_type == "subdomain":
            if isinstance(data, list):
                self.subdomains.extend(data)
            else:
                self.subdomains.append(data)
            self.subdomains = list(set(self.subdomains))
            
        elif finding_type == "ip":
            if isinstance(data, list):
                self.ips.extend(data)
            else:
                self.ips.append(data)
            self.ips = list(set(self.ips))
            
        elif finding_type == "port":
            self.open_ports.append(data) if isinstance(data, dict) else self.open_ports.extend(data)
            
        elif finding_type == "vulnerability":
            self.vulnerabilities.append(data) if isinstance(data, dict) else self.vulnerabilities.extend(data)
            
        elif finding_type == "credential":
            self.credentials.append(data)
            
        elif finding_type == "shell":
            self.shells.append(data)
    
    def get_for_agent(self, agent_name: str) -> Dict[str, Any]:
        """Get context relevant for a specific agent."""
        base = {
            "domain": self.domain,
            "targets": self.targets,
            "tools_run": self.tools_run,
            "current_phase": self.current_phase
        }
        
        if agent_name == "recon":
            return {**base}  # Recon needs minimal context
            
        elif agent_name == "scan":
            return {
                **base,
                "subdomains": self.subdomains,
                "ips": self.ips,
                "subdomain_count": len(self.subdomains)
            }
            
        elif agent_name == "vuln":
            return {
                **base,
                "subdomains": self.subdomains[:20],
                "open_ports": self.open_ports,
                "services": self.services,
                "technologies": self.technologies
            }
            
        elif agent_name == "exploit":
            return {
                **base,
                "vulnerabilities": self.vulnerabilities,
                "cves": self.cves,
                "open_ports": self.open_ports,
                "credentials": self.credentials
            }
            
        elif agent_name == "postexploit":
            return {
                **base,
                "shells": self.shells,
                "credentials": self.credentials,
                "successful_exploits": self.successful_exploits
            }
            
        elif agent_name == "report":
            return self.to_dict()  # Report needs everything
            
        return base
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for JSON serialization / context passing."""
        return {
            "domain": self.domain,
            "last_domain": self.domain,  # Alias for compatibility
            "targets": self.targets,
            "subdomains": self.subdomains,
            "subdomain_count": len(self.subdomains),
            "has_subdomains": len(self.subdomains) > 0,
            "ips": self.ips,
            "ip_count": len(self.ips),
            "asns": self.asns,
            "asn_count": len(self.asns),
            "emails": self.emails,
            "detected_tech": self.technologies,
            "open_ports": self.open_ports,
            "port_count": len(self.open_ports),
            "has_ports": len(self.open_ports) > 0,
            "services": self.services,
            "directories": self.directories,
            "endpoints": self.endpoints,
            "vulns_found": self.vulnerabilities,
            "vuln_count": len(self.vulnerabilities),
            "misconfigs": self.misconfigs,
            "cves": self.cves,
            "exploits_run": self.exploits_attempted,
            "successful_exploits": self.successful_exploits,
            "credentials": self.credentials,
            "shells": self.shells,
            "shell_obtained": len(self.shells) > 0,
            "privesc_results": self.privesc_results,
            "privesc_done": len(self.privesc_results) > 0,
            "lateral_movement": self.lateral_movement,
            "lateral_done": len(self.lateral_movement) > 0,
            "loot": self.loot,
            "tools_run": self.tools_run,
            "current_phase": self.current_phase,
            "phase_complete": self.phase_complete
        }
    
    def update_from_dict(self, data: Dict[str, Any]):
        """Update memory from a context dict (for compatibility)."""
        if data.get("subdomains"):
            self.subdomains = list(set(self.subdomains + data["subdomains"]))
        if data.get("ips"):
            self.ips = list(set(self.ips + data["ips"]))
        if data.get("open_ports"):
            self.open_ports.extend(data["open_ports"])
        if data.get("vulns_found"):
            self.vulnerabilities.extend(data["vulns_found"])
        if data.get("detected_tech"):
            self.technologies = list(set(self.technologies + data["detected_tech"]))
        if data.get("last_domain"):
            self.domain = data["last_domain"]
        if data.get("tools_run"):
            self.tools_run = list(set(self.tools_run + data["tools_run"]))
    
    def get_agent_summary(self) -> str:
        """Get a summary of what each agent has contributed."""
        summary = []
        for msg in self.agent_messages[-10:]:  # Last 10 messages
            summary.append(f"[{msg['agent']}] {msg['type']}: {str(msg['data'])[:50]}...")
        return "\n".join(summary) if summary else "No agent messages yet."


# Singleton shared memory
_shared_memory: Optional[AgentMemory] = None


def get_shared_memory() -> AgentMemory:
    """Get or create the shared agent memory."""
    global _shared_memory
    if _shared_memory is None:
        _shared_memory = AgentMemory()
    return _shared_memory


def reset_shared_memory():
    """Reset shared memory (for new engagement)."""
    global _shared_memory
    _shared_memory = AgentMemory()
