"""
Session Memory - In-Session Context for LLM & Agents
=====================================================

This module provides VOLATILE memory for the current session:
- Shared context between all 6 agents
- Attack facts and hypotheses
- LLM context window management

This is DIFFERENT from Conversation History (postgres.py) which is PERSISTENT.

Architecture:
- SessionMemory: In-memory context for current session
- AgentContext: Shared findings between agents (recon, scan, vuln, etc.)
- AttackState: Facts and hypotheses from tool outputs
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from uuid import uuid4
import json


# ============================================================
# AGENT CONTEXT - Shared between all 6 agents
# ============================================================

@dataclass
class AgentContext:
    """
    Shared context that all agents can read/write.
    This is the "message board" for inter-agent communication.
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
    dns_records: List[Dict] = field(default_factory=list)
    
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
    
    # Phase 5: Post-exploitation
    privilege_escalations: List[Dict] = field(default_factory=list)
    lateral_movements: List[Dict] = field(default_factory=list)
    persistence: List[Dict] = field(default_factory=list)
    
    # Metadata
    tools_run: List[str] = field(default_factory=list)
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_subdomain(self, subdomain: str):
        """Add a subdomain if not already present."""
        if subdomain and subdomain not in self.subdomains:
            self.subdomains.append(subdomain)
            self._touch()
    
    def add_subdomains(self, subdomains: List[str]):
        """Add multiple subdomains."""
        for s in subdomains:
            self.add_subdomain(s)
    
    def add_ip(self, ip: str):
        """Add an IP if not already present."""
        if ip and ip not in self.ips:
            self.ips.append(ip)
            self._touch()
    
    def add_port(self, host: str, port: int, service: str = "", version: str = ""):
        """Add an open port finding."""
        entry = {"host": host, "port": port, "service": service, "version": version}
        if entry not in self.open_ports:
            self.open_ports.append(entry)
            self._touch()
    
    def add_vulnerability(self, vuln_type: str, target: str, severity: str = "medium", 
                         cve: str = "", details: Dict = None):
        """Add a vulnerability finding."""
        entry = {
            "type": vuln_type,
            "target": target,
            "severity": severity,
            "cve": cve,
            "details": details or {}
        }
        self.vulnerabilities.append(entry)
        if cve and cve not in self.cves:
            self.cves.append(cve)
        self._touch()
    
    def add_technology(self, tech: str):
        """Add detected technology."""
        if tech and tech not in self.technologies:
            self.technologies.append(tech)
            self._touch()
    
    def add_tool_run(self, tool: str):
        """Record that a tool was run."""
        if tool and tool not in self.tools_run:
            self.tools_run.append(tool)
            self._touch()
    
    def _touch(self):
        """Update last_updated timestamp."""
        self.last_updated = datetime.now().isoformat()
    
    def get_targets_for_scanning(self) -> List[str]:
        """Get all targets (domain + subdomains + IPs) for scanning."""
        targets = set()
        if self.domain:
            targets.add(self.domain)
        targets.update(self.subdomains)
        targets.update(self.ips)
        return list(targets)
    
    def get_high_value_targets(self) -> List[str]:
        """Get high-value targets (admin panels, APIs, etc.)."""
        high_value = []
        keywords = ["admin", "api", "login", "auth", "dashboard", "manage", "portal"]
        
        for sub in self.subdomains:
            if any(kw in sub.lower() for kw in keywords):
                high_value.append(sub)
        
        for endpoint in self.endpoints:
            if any(kw in endpoint.lower() for kw in keywords):
                high_value.append(endpoint)
        
        return high_value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "domain": self.domain,
            "targets": self.targets,
            "subdomains": self.subdomains,
            "ips": self.ips,
            "technologies": self.technologies,
            "open_ports": self.open_ports,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "cves": self.cves,
            "tools_run": self.tools_run,
            "last_updated": self.last_updated,
        }
    
    def get_summary(self) -> str:
        """Get a brief summary of findings."""
        parts = []
        if self.domain:
            parts.append(f"Target: {self.domain}")
        if self.subdomains:
            parts.append(f"Subdomains: {len(self.subdomains)}")
        if self.ips:
            parts.append(f"IPs: {len(self.ips)}")
        if self.open_ports:
            parts.append(f"Open ports: {len(self.open_ports)}")
        if self.vulnerabilities:
            parts.append(f"Vulnerabilities: {len(self.vulnerabilities)}")
        if self.tools_run:
            parts.append(f"Tools run: {', '.join(self.tools_run[-5:])}")
        return " | ".join(parts) if parts else "No findings yet"


# ============================================================
# ATTACK FACTS - Structured observations from tools
# ============================================================

@dataclass
class Fact:
    """
    A single normalized observation from a tool.
    Facts are atomic units of knowledge that can be queried.
    """
    id: str
    fact_type: str  # "open_port", "subdomain", "vulnerability", "service", "technology"
    target: str     # IP/domain this fact relates to
    data: Dict[str, Any]  # Structured data
    source_tool: str      # Which tool produced this
    timestamp: str        # ISO format
    confidence: float     # 0.0-1.0
    
    @classmethod
    def create(cls, fact_type: str, target: str, data: Dict[str, Any], 
               source_tool: str, confidence: float = 1.0) -> "Fact":
        """Factory method to create a new fact."""
        return cls(
            id=str(uuid4())[:8],
            fact_type=fact_type,
            target=target,
            data=data,
            source_tool=source_tool,
            timestamp=datetime.now().isoformat(),
            confidence=confidence
        )


@dataclass
class Hypothesis:
    """
    A hypothesis about the target that needs verification.
    Used for intelligent tool suggestions.
    """
    id: str
    description: str
    based_on: List[str]  # Fact IDs
    suggested_tools: List[str]
    priority: int  # 1-5, 5 being highest
    status: str  # "pending", "testing", "confirmed", "rejected"
    
    @classmethod
    def create(cls, description: str, based_on: List[str], 
               suggested_tools: List[str], priority: int = 3) -> "Hypothesis":
        return cls(
            id=str(uuid4())[:8],
            description=description,
            based_on=based_on,
            suggested_tools=suggested_tools,
            priority=priority,
            status="pending"
        )


# ============================================================
# SESSION MEMORY - Main class for in-session context
# ============================================================

class SessionMemory:
    """
    In-session memory manager.
    
    Combines:
    - AgentContext: Shared findings between agents
    - Facts/Hypotheses: Structured attack knowledge
    - LLM Context: Conversation context for LLM
    
    This is VOLATILE - cleared when session ends.
    For persistent storage, use MemoryManager (postgres.py).
    """
    
    def __init__(self):
        self.agent_context = AgentContext()
        self.facts: Dict[str, Fact] = {}
        self.hypotheses: Dict[str, Hypothesis] = {}
        self.llm_messages: List[Dict[str, str]] = []
        self.session_start = datetime.now().isoformat()
        
        # Track failed actions for learning
        self.failed_actions: List[Dict] = []
    
    # ─────────────────────────────────────────────────────────
    # Agent Context Methods
    # ─────────────────────────────────────────────────────────
    
    def set_target(self, domain: str):
        """Set the main target domain."""
        self.agent_context.domain = domain
        self.agent_context.targets.append(domain)
    
    def get_context(self) -> AgentContext:
        """Get the shared agent context."""
        return self.agent_context
    
    def get_context_dict(self) -> Dict[str, Any]:
        """Get context as dictionary (for state serialization)."""
        return self.agent_context.to_dict()
    
    def update_from_dict(self, data: Dict[str, Any]):
        """Update context from dictionary."""
        for key, value in data.items():
            if hasattr(self.agent_context, key):
                setattr(self.agent_context, key, value)
    
    # ─────────────────────────────────────────────────────────
    # Fact Management
    # ─────────────────────────────────────────────────────────
    
    def add_fact(self, fact_type: str, target: str, data: Dict[str, Any],
                 source_tool: str, confidence: float = 1.0) -> Fact:
        """Add a new fact to memory."""
        fact = Fact.create(fact_type, target, data, source_tool, confidence)
        self.facts[fact.id] = fact
        
        # Also update agent context based on fact type
        if fact_type == "subdomain":
            self.agent_context.add_subdomain(data.get("subdomain", target))
        elif fact_type == "ip":
            self.agent_context.add_ip(data.get("ip", target))
        elif fact_type == "open_port":
            self.agent_context.add_port(
                target, 
                data.get("port", 0),
                data.get("service", ""),
                data.get("version", "")
            )
        elif fact_type == "vulnerability":
            self.agent_context.add_vulnerability(
                data.get("type", "unknown"),
                target,
                data.get("severity", "medium"),
                data.get("cve", "")
            )
        elif fact_type == "technology":
            self.agent_context.add_technology(data.get("tech", ""))
        
        self.agent_context.add_tool_run(source_tool)
        return fact
    
    def get_facts(self, fact_type: str = None, target: str = None) -> List[Fact]:
        """Query facts with optional filters."""
        results = list(self.facts.values())
        
        if fact_type:
            results = [f for f in results if f.fact_type == fact_type]
        if target:
            results = [f for f in results if f.target == target]
        
        return results
    
    def get_facts_summary(self) -> Dict[str, int]:
        """Get count of facts by type."""
        summary = {}
        for fact in self.facts.values():
            summary[fact.fact_type] = summary.get(fact.fact_type, 0) + 1
        return summary
    
    def get_facts_for_target(self, target: str) -> List[Fact]:
        """Get all facts related to a target (for backward compat with AttackMemory)."""
        return [f for f in self.facts.values() if f.target == target or target in f.target]
    
    def get_learning_hint(self, tool: str, params: Dict = None) -> Optional[Dict]:
        """Get learning hint from past failures (for backward compat)."""
        # Check if tool failed recently on same target
        target = params.get("domain", "") if params else ""
        for failure in self.failed_actions:
            if failure.get("tool") == tool and target in failure.get("target", ""):
                return {
                    "should_retry": False,
                    "suggestion": failure.get("reason", "Tool failed previously"),
                    "last_error": failure.get("error", "")
                }
        return None
    
    def record_failure(self, tool: str, target: str, error: str, reason: str = ""):
        """Record a failed action for learning."""
        self.failed_actions.append({
            "tool": tool,
            "target": target,
            "error": str(error),
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
    
    # ─────────────────────────────────────────────────────────
    # Hypothesis Management
    # ─────────────────────────────────────────────────────────
    
    def add_hypothesis(self, description: str, based_on: List[str],
                       suggested_tools: List[str], priority: int = 3) -> Hypothesis:
        """Add a new hypothesis."""
        hyp = Hypothesis.create(description, based_on, suggested_tools, priority)
        self.hypotheses[hyp.id] = hyp
        return hyp
    
    def get_pending_hypotheses(self) -> List[Hypothesis]:
        """Get hypotheses that need testing."""
        return [h for h in self.hypotheses.values() if h.status == "pending"]
    
    def update_hypothesis(self, hyp_id: str, status: str):
        """Update hypothesis status."""
        if hyp_id in self.hypotheses:
            self.hypotheses[hyp_id].status = status
    
    # ─────────────────────────────────────────────────────────
    # LLM Context Management
    # ─────────────────────────────────────────────────────────
    
    def add_message(self, role: str, content: str):
        """Add a message to LLM context."""
        self.llm_messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
        
        # Keep last 20 messages to manage context window
        if len(self.llm_messages) > 20:
            self.llm_messages = self.llm_messages[-20:]
    
    def get_llm_context(self, max_messages: int = 10) -> List[Dict[str, str]]:
        """Get recent messages for LLM context."""
        return self.llm_messages[-max_messages:]
    
    def format_context_for_llm(self) -> str:
        """Format full context as string for LLM prompt."""
        parts = []
        
        # Agent context summary
        summary = self.agent_context.get_summary()
        if summary and summary != "No findings yet":
            parts.append(f"## Current Findings\n{summary}")
        
        # Recent conversation
        recent = self.get_llm_context(5)
        if recent:
            parts.append("## Recent Conversation")
            for msg in recent:
                role = "User" if msg["role"] == "user" else "Assistant"
                content = msg["content"][:200]
                parts.append(f"**{role}:** {content}")
        
        # Fact summary
        fact_summary = self.get_facts_summary()
        if fact_summary:
            parts.append(f"## Facts Collected: {fact_summary}")
        
        return "\n\n".join(parts)
    
    # ─────────────────────────────────────────────────────────
    # Failed Action Tracking (for learning)
    # ─────────────────────────────────────────────────────────
    
    def record_failure(self, tool: str, command: str, error: str, context: Dict = None):
        """Record a failed action for learning."""
        self.failed_actions.append({
            "tool": tool,
            "command": command,
            "error": error,
            "context": context or {},
            "timestamp": datetime.now().isoformat()
        })
    
    def get_failures_for_tool(self, tool: str) -> List[Dict]:
        """Get failures for a specific tool."""
        return [f for f in self.failed_actions if f["tool"] == tool]
    
    # ─────────────────────────────────────────────────────────
    # Session Management
    # ─────────────────────────────────────────────────────────
    
    def clear(self):
        """Clear all session memory."""
        self.agent_context = AgentContext()
        self.facts.clear()
        self.hypotheses.clear()
        self.llm_messages.clear()
        self.failed_actions.clear()
        self.session_start = datetime.now().isoformat()
    
    def export(self) -> Dict[str, Any]:
        """Export session data for persistence."""
        return {
            "session_start": self.session_start,
            "agent_context": self.agent_context.to_dict(),
            "facts": {k: {"id": v.id, "type": v.fact_type, "target": v.target, 
                         "data": v.data, "source": v.source_tool} 
                     for k, v in self.facts.items()},
            "hypotheses": {k: {"id": v.id, "description": v.description, 
                              "status": v.status, "priority": v.priority}
                          for k, v in self.hypotheses.items()},
            "message_count": len(self.llm_messages),
            "failure_count": len(self.failed_actions)
        }


# ============================================================
# SINGLETON INSTANCE
# ============================================================

_session_memory: Optional[SessionMemory] = None


def get_session_memory() -> SessionMemory:
    """Get or create the session memory instance."""
    global _session_memory
    if _session_memory is None:
        _session_memory = SessionMemory()
    return _session_memory


def reset_session_memory():
    """Reset session memory (start fresh)."""
    global _session_memory
    if _session_memory:
        _session_memory.clear()
    _session_memory = SessionMemory()


# Aliases for backward compatibility
def get_shared_memory() -> AgentContext:
    """Alias for get_session_memory().get_context()"""
    return get_session_memory().get_context()


def get_attack_memory() -> SessionMemory:
    """Alias for get_session_memory()"""
    return get_session_memory()
