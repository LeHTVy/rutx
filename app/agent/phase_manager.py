"""
Phase Manager - Enforces Pentest Phase Order
=============================================

Ensures users progress through pentest phases in proper order.
Blocks or warns when trying to skip phases.

PTES Phases:
1. Reconnaissance - OSINT, subdomain, DNS
2. Scanning - Port scan, service enum
3. Vulnerability - CVE detection, vuln scan
4. Exploitation - SQLi, RCE, brute force
5. Post-Exploitation - Priv esc, lateral movement
6. Reporting - Generate reports
"""
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum


class PhaseGateAction(Enum):
    """Action to take when phase gate is checked."""
    ALLOW = "allow"      # Proceed normally
    WARN = "warn"        # Warn but allow
    BLOCK = "block"      # Block and suggest remediation


@dataclass
class PhaseGateResult:
    """Result of a phase gate check."""
    action: PhaseGateAction
    current_phase: int
    requested_phase: int
    missing_requirements: List[str] = field(default_factory=list)
    message: str = ""
    remediation: str = ""
    
    @property
    def is_allowed(self) -> bool:
        return self.action in [PhaseGateAction.ALLOW, PhaseGateAction.WARN]
    
    @property
    def is_blocked(self) -> bool:
        return self.action == PhaseGateAction.BLOCK


# Phase names
PHASE_NAMES = {
    1: "Reconnaissance",
    2: "Scanning", 
    3: "Vulnerability Assessment",
    4: "Exploitation",
    5: "Post-Exploitation",
    6: "Reporting"
}

# What tools belong to which phase
TOOL_PHASES = {
    # Phase 1: Reconnaissance
    "amass": 1, "subfinder": 1, "assetfinder": 1, "findomain": 1,
    "whois": 1, "clatscope": 1, "theHarvester": 1, "bbot": 1,
    "dnsrecon": 1, "fierce": 1, "dnsx": 1,
    
    # Phase 2: Scanning
    "nmap": 2, "masscan": 2, "rustscan": 2,
    "httpx": 2, "gobuster": 2, "ffuf": 2, "dirsearch": 2, "feroxbuster": 2,
    "wafw00f": 2, "whatweb": 2,
    
    # Phase 3: Vulnerability Assessment
    "nuclei": 3, "nikto": 3, "wpscan": 3, "droopescan": 3,
    "testssl": 3, "sslyze": 3, "sslscan": 3,
    
    # Phase 4: Exploitation
    "sqlmap": 4, "ghauri": 4, "hydra": 4, "medusa": 4,
    "searchsploit": 4, "msfconsole": 4, "metasploit": 4,
    
    # Phase 5: Post-Exploitation
    "linpeas": 5, "winpeas": 5, "mimikatz": 5,
    "crackmapexec": 5, "bloodhound": 5, "impacket": 5,
    
    # Phase 6: Reporting (always allowed)
    "report": 6,
}

# Requirements for each phase transition
# Uses "any_key_of" to accept multiple context key names for same concept
PHASE_REQUIREMENTS = {
    # To enter Phase 2 (Scanning), need from Phase 1:
    2: {
        "name": "Scanning",
        "requires": [],  # No hard requirements - check any_key_of instead
        "any_key_of": ["target_domain", "last_domain", "domain"],  # Accept any target key
        "any_of": ["subdomains", "ips", "dns_records", "has_subdomains"],  # Need at least one
        "min_counts": {},
        "message": "Need target and initial recon data before scanning",
    },
    
    # To enter Phase 3 (Vuln Assessment), need from Phase 2:
    3: {
        "name": "Vulnerability Assessment",
        "requires": [],
        "any_key_of": ["target_domain", "last_domain", "domain"],
        "any_of": ["open_ports", "web_endpoints", "services_found", "has_ports"],
        "min_counts": {},
        "message": "Need port scan or web enumeration data before vuln scanning",
    },
    
    # To enter Phase 4 (Exploitation), need from Phase 3:
    4: {
        "name": "Exploitation",
        "requires": [],
        "any_key_of": ["target_domain", "last_domain", "domain"],
        "any_of": ["vulns_found", "sqli_points", "attack_surface"],
        "min_counts": {},
        "message": "Need vulnerability scan data before exploitation",
    },
    
    # To enter Phase 5 (Post-Exploitation), need from Phase 4:
    5: {
        "name": "Post-Exploitation",
        "requires": [],
        "any_key_of": [],  # No target needed at this phase
        "any_of": ["shell_obtained", "credentials", "access_gained"],
        "min_counts": {},
        "message": "Need shell access or credentials before post-exploitation",
    },
    
    # Phase 6 (Reporting) - always allowed
    6: {
        "name": "Reporting",
        "requires": [],
        "any_key_of": [],
        "any_of": [],  # Always allowed
        "min_counts": {},
        "message": "Ready to generate report",
    },
}

# Remediation suggestions for each phase
PHASE_REMEDIATION = {
    2: "Run subdomain enumeration (subfinder, amass) or DNS recon first.",
    3: "Run port scanning (nmap) or web enumeration (httpx, gobuster) first.",
    4: "Run vulnerability scanning (nuclei, nikto) to identify exploitable targets first.",
    5: "Successfully exploit a vulnerability to gain access first.",
    6: "Collect findings from any phase to generate a report.",
}


class PhaseManager:
    """
    Manages phase progression and enforces phase gates.
    
    Usage:
        pm = PhaseManager()
        result = pm.check_phase_gate(tool="sqlmap", context=context)
        if result.is_blocked:
            print(result.message)
            print(result.remediation)
    """
    
    def __init__(self, enforcement_mode: str = "guided"):
        """
        Initialize phase manager.
        
        Args:
            enforcement_mode: "strict", "guided", or "permissive"
        """
        self.enforcement_mode = enforcement_mode
    
    def get_current_phase(self, context: Dict[str, Any]) -> int:
        """
        Determine current phase from context.
        
        Returns the CURRENT phase we're in, not the phase we're ready for.
        Phase transitions happen when we actually start using tools from that phase.
        """
        tools_run = context.get("tools_run", [])
        
        # Check for post-exploitation indicators
        if context.get("shell_obtained") or context.get("privesc_done"):
            return 5
        if any(t in tools_run for t in ["linpeas", "winpeas", "mimikatz", "bloodhound"]):
            return 5
        
        # Check for exploitation indicators
        if context.get("exploits_run") or context.get("access_gained"):
            return 4
        if any(t in tools_run for t in ["sqlmap", "hydra", "msfconsole", "searchsploit"]):
            return 4
        
        # Check for vulnerability assessment - running vuln tools
        vulns = context.get("vulns_found", [])
        if vulns or any(t in tools_run for t in ["nuclei", "nikto", "wpscan"]):
            return 3
        
        # Check for scanning - running scan tools
        if context.get("open_ports") or context.get("has_ports"):
            return 2
        if any(t in tools_run for t in ["nmap", "masscan", "rustscan", "httpx", "gobuster", "ffuf"]):
            return 2
        
        # Default: Phase 1 (Reconnaissance)
        # Having subdomains means recon is IN PROGRESS or COMPLETE, not that we're in phase 2
        return 1
    
    def get_tool_phase(self, tool: str) -> int:
        """Get which phase a tool belongs to."""
        return TOOL_PHASES.get(tool.lower(), 1)
    
    def check_phase_gate(self, tool: str, context: Dict[str, Any]) -> PhaseGateResult:
        """
        Check if running a tool is allowed based on current phase.
        
        Args:
            tool: Tool name to check
            context: Current session context
            
        Returns:
            PhaseGateResult with action, message, and remediation
        """
        current_phase = self.get_current_phase(context)
        tool_phase = self.get_tool_phase(tool)
        
        # Same or earlier phase - always allow
        if tool_phase <= current_phase:
            return PhaseGateResult(
                action=PhaseGateAction.ALLOW,
                current_phase=current_phase,
                requested_phase=tool_phase
            )
        
        # Trying to skip phases
        phase_diff = tool_phase - current_phase
        
        # Check requirements for target phase
        missing = self._get_missing_requirements(tool_phase, context)
        
        # Determine action based on mode and phase difference
        if self.enforcement_mode == "permissive":
            action = PhaseGateAction.WARN
        elif self.enforcement_mode == "strict":
            action = PhaseGateAction.BLOCK
        else:  # guided (default)
            # Block if skipping more than 1 phase or missing critical requirements
            if phase_diff > 1 or missing:
                action = PhaseGateAction.BLOCK
            else:
                action = PhaseGateAction.WARN
        
        # Build message
        message = self._build_gate_message(tool, tool_phase, current_phase, missing)
        remediation = self._get_remediation(tool_phase, context)
        
        return PhaseGateResult(
            action=action,
            current_phase=current_phase,
            requested_phase=tool_phase,
            missing_requirements=missing,
            message=message,
            remediation=remediation
        )
    
    def check_phase_ready(self, target_phase: int, context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Check if ready to enter a phase.
        
        Returns:
            Tuple of (is_ready, missing_requirements)
        """
        missing = self._get_missing_requirements(target_phase, context)
        return (len(missing) == 0, missing)
    
    def _get_missing_requirements(self, target_phase: int, context: Dict[str, Any]) -> List[str]:
        """Get list of missing requirements for a phase."""
        if target_phase not in PHASE_REQUIREMENTS:
            return []
        
        reqs = PHASE_REQUIREMENTS[target_phase]
        missing = []
        
        # Check required fields (strict - all must be present)
        for field in reqs.get("requires", []):
            if not context.get(field):
                missing.append(f"Missing: {field}")
        
        # Check any_key_of (need at least one key to have a value - for target aliasing)
        any_key_of = reqs.get("any_key_of", [])
        if any_key_of:
            has_any_key = any(context.get(key) for key in any_key_of)
            if not has_any_key:
                missing.append(f"Missing: target (need one of: {', '.join(any_key_of)})")
        
        # Check any_of fields (need at least one to have data)
        any_of = reqs.get("any_of", [])
        if any_of:
            has_any = any(
                context.get(field) or 
                (isinstance(context.get(field), list) and len(context.get(field, [])) > 0)
                for field in any_of
            )
            if not has_any:
                missing.append(f"Need at least one of: {', '.join(any_of)}")
        
        # Check minimum counts
        for field, min_count in reqs.get("min_counts", {}).items():
            current = len(context.get(field, []))
            if current < min_count:
                missing.append(f"Need {min_count}+ {field} (have {current})")
        
        return missing
    
    def _build_gate_message(self, tool: str, tool_phase: int, current_phase: int, 
                           missing: List[str]) -> str:
        """Build user-facing gate message."""
        tool_phase_name = PHASE_NAMES.get(tool_phase, f"Phase {tool_phase}")
        current_phase_name = PHASE_NAMES.get(current_phase, f"Phase {current_phase}")
        
        msg = f"Cannot run {tool} ({tool_phase_name}) - current phase is {current_phase_name}."
        
        if missing:
            msg += f"\n\nMissing requirements:\n"
            for m in missing:
                msg += f"  • {m}\n"
        
        return msg
    
    def _get_remediation(self, target_phase: int, context: Dict[str, Any]) -> str:
        """Get remediation suggestion."""
        base = PHASE_REMEDIATION.get(target_phase, "Complete earlier phases first.")
        
        # Add specific suggestions based on context
        current_phase = self.get_current_phase(context)
        
        if current_phase == 1 and target_phase >= 2:
            if not context.get("subdomains"):
                return "Run: subfinder -d <domain> to enumerate subdomains first."
        
        if current_phase == 2 and target_phase >= 3:
            if not context.get("open_ports"):
                return "Run: nmap <target> to scan for open ports first."
        
        if current_phase == 3 and target_phase >= 4:
            if not context.get("vulns_found"):
                return "Run: nuclei -u <target> to identify vulnerabilities first."
        
        return base
    
    def get_phase_status(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get current phase status for display.
        
        Returns dict with phase info, progress, and next steps.
        """
        current = self.get_current_phase(context)
        
        # Check readiness for next phase
        next_phase = current + 1 if current < 6 else 6
        is_ready, missing = self.check_phase_ready(next_phase, context)
        
        return {
            "current_phase": current,
            "current_phase_name": PHASE_NAMES.get(current, "Unknown"),
            "next_phase": next_phase,
            "next_phase_name": PHASE_NAMES.get(next_phase, "Complete"),
            "ready_for_next": is_ready,
            "missing_for_next": missing,
            "tools_run": context.get("tools_run", []),
            "progress_summary": self._get_progress_summary(context)
        }
    
    def _get_progress_summary(self, context: Dict[str, Any]) -> str:
        """Build a brief progress summary."""
        parts = []
        
        if context.get("subdomains"):
            parts.append(f"{len(context['subdomains'])} subdomains")
        if context.get("open_ports"):
            parts.append(f"{len(context['open_ports'])} open ports")
        if context.get("vulns_found"):
            parts.append(f"{len(context['vulns_found'])} vulns")
        if context.get("shell_obtained"):
            parts.append("shell obtained")
        
        return ", ".join(parts) if parts else "No findings yet"


# Singleton
_phase_manager: Optional[PhaseManager] = None


def get_phase_manager(enforcement_mode: str = "guided") -> PhaseManager:
    """Get or create phase manager singleton."""
    global _phase_manager
    if _phase_manager is None:
        _phase_manager = PhaseManager(enforcement_mode)
    return _phase_manager
