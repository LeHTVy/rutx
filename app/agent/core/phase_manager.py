"""
Phase Manager - LLM-Driven Phase Evaluation
============================================

REDESIGNED: No longer blocks tools based on hardcoded rules.
Uses LLM intelligence to evaluate phase progression and suggest next steps.

PTES Phases (for reference only):
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
    ALLOW = "allow"      # Proceed normally (now always used)
    WARN = "warn"        # Warn but allow
    BLOCK = "block"      # Block and suggest remediation (deprecated)


@dataclass
class PhaseGateResult:
    """Result of a phase gate check."""
    action: PhaseGateAction
    current_phase: int
    requested_phase: int
    missing_requirements: List[str] = field(default_factory=list)
    message: str = ""
    remediation: str = ""
    llm_reasoning: str = ""  # NEW: LLM's reasoning for the decision
    
    @property
    def is_allowed(self) -> bool:
        """Always allowed in autonomous mode."""
        return True
    
    @property
    def is_blocked(self) -> bool:
        """Never blocked in autonomous mode."""
        return False


# Phase names for display only
PHASE_NAMES = {
    1: "Reconnaissance",
    2: "Scanning", 
    3: "Vulnerability Assessment",
    4: "Exploitation",
    5: "Post-Exploitation",
    6: "Reporting"
}

# Map ToolCategory (from tool specs) to PTES phase
# This is a minimal semantic mapping - tools bring their own category via registry
CATEGORY_TO_PHASE = {
    "recon": 1,
    "osint": 1,
    "enumeration": 1,
    "scanning": 2,
    "vulnerability": 3,
    "exploitation": 4,
    "brute_force": 4,
    "utility": 1,
}


def get_tool_phase(tool_name: str) -> int:
    """
    Get phase for a tool using its category from ToolRegistry.
    
    Uses tool metadata dynamically - no hardcoded tool lists.
    """
    try:
        from app.tools.registry import get_registry
        registry = get_registry()
        
        spec = registry.tools.get(tool_name.lower())
        if spec and spec.category:
            category = spec.category.value  # ToolCategory enum -> string
            return CATEGORY_TO_PHASE.get(category, 1)
    except Exception:
        pass
    
    return 1  # Default to recon if unknown


def get_tool_phase_llm(tool_name: str, tool_description: str = "") -> int:
    """
    Use LLM to determine tool's phase based on its metadata.
    
    This is the fully dynamic version - LLM reads tool description
    and determines which PTES phase it belongs to.
    
    Use this when you want maximum flexibility.
    """
    import json
    import re
    
    try:
        from app.llm.client import OllamaClient
        from app.tools.registry import get_registry
        
        registry = get_registry()
        spec = registry.tools.get(tool_name.lower())
        
        if spec:
            tool_description = spec.description
            commands = list(spec.commands.keys()) if spec.commands else []
        else:
            commands = []
        
        llm = OllamaClient()
        
        prompt = f"""Classify this security tool into a PTES pentest phase.

Tool: {tool_name}
Description: {tool_description}
Commands: {', '.join(commands)}

PTES Phases:
1 = Reconnaissance (OSINT, subdomain enum, DNS, info gathering)
2 = Scanning (port scan, service detection, web probing)
3 = Vulnerability Assessment (CVE detection, vuln scanning)
4 = Exploitation (SQLi, RCE, brute force, gaining access)
5 = Post-Exploitation (privesc, lateral movement, persistence)
6 = Reporting (documentation, summary)

Return ONLY a number 1-6:"""

        response = llm.generate(prompt, timeout=10, stream=False)
        
        # Extract number
        match = re.search(r'[1-6]', response)
        if match:
            return int(match.group())
            
    except Exception:
        pass
    
    # Fallback to category-based
    return get_tool_phase(tool_name)


class PhaseManager:
    """
    LLM-driven phase manager for autonomous operation.
    
    REDESIGNED: No longer blocks tools. Uses LLM to:
    - Determine current phase from context
    - Suggest optimal tool sequences
    - Evaluate phase completion
    
    All decisions are made by LLM, not hardcoded rules.
    """
    
    def __init__(self, enforcement_mode: str = "autonomous"):
        """
        Initialize phase manager.
        
        Args:
            enforcement_mode: Always "autonomous" now - LLM decides everything
        """
        self.enforcement_mode = enforcement_mode
        self._llm = None
    
    @property
    def llm(self):
        """Lazy-load LLM client."""
        if self._llm is None:
            from app.llm.client import OllamaClient
            self._llm = OllamaClient()
        return self._llm
    
    def get_current_phase(self, context: Dict[str, Any]) -> int:
        """
        Determine current phase from context.
        
        Uses tool metadata (category) dynamically - NO HARDCODING.
        LLM/Registry provides the tool categorization.
        
        Returns the HIGHEST phase that has been ACTIVELY worked on.
        """
        tools_run = context.get("tools_run", [])
        
        # Check explicit state first
        if context.get("shell_obtained") or context.get("privesc_done"):
            return 5
        if context.get("access_gained") or context.get("exploits_run"):
            return 4
        if context.get("vulns_found") and len(context.get("vulns_found", [])) > 0:
            return 3
        
        # Check tools run - find the HIGHEST phase using tool metadata
        max_phase_from_tools = 0
        for tool in tools_run:
            tool_phase = get_tool_phase(tool)  # Uses registry metadata!
            if tool_phase > max_phase_from_tools:
                max_phase_from_tools = tool_phase
        
        # If we have port scan RESULTS, we're at least in phase 2
        if context.get("open_ports") and len(context.get("open_ports", [])) > 0:
            return max(2, max_phase_from_tools)
        
        # If subdomains found but no ports yet
        if context.get("subdomains") and len(context.get("subdomains", [])) > 0:
            # Check if any scanning tools ran
            if max_phase_from_tools >= 2:
                return 2
            # Otherwise still in recon
            return 1
        
        # Default based on max tool phase or 1
        return max(1, max_phase_from_tools)
    
    def check_phase_gate(self, tool: str, context: Dict[str, Any]) -> PhaseGateResult:
        """
        Check if running a tool is allowed.
        
        REDESIGNED: Always returns ALLOW. LLM provides reasoning only.
        No blocking - the AI agent is autonomous.
        
        Args:
            tool: Tool name to check
            context: Current session context
            
        Returns:
            PhaseGateResult with ALLOW action and LLM reasoning
        """
        current_phase = self.get_current_phase(context)
        
        # Always allow - autonomous mode
        return PhaseGateResult(
            action=PhaseGateAction.ALLOW,
            current_phase=current_phase,
            requested_phase=current_phase,
            missing_requirements=[],
            message=f"Running {tool} (autonomous mode)",
            remediation="",
            llm_reasoning="Autonomous mode - LLM decides tool selection"
        )
    
    def evaluate_phase_with_llm(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use LLM to evaluate current phase status and suggest next steps.
        
        Returns:
            Dict with phase info, completion status, and suggestions
        """
        import json
        import re
        
        current_phase = self.get_current_phase(context)
        phase_name = PHASE_NAMES.get(current_phase, f"Phase {current_phase}")
        
        # Build context summary
        summary_parts = []
        if context.get("target_domain") or context.get("last_domain"):
            summary_parts.append(f"Target: {context.get('target_domain') or context.get('last_domain')}")
        if context.get("subdomains"):
            summary_parts.append(f"Subdomains: {len(context['subdomains'])}")
        if context.get("ips"):
            summary_parts.append(f"IPs: {len(context['ips'])}")
        if context.get("open_ports"):
            summary_parts.append(f"Open ports: {len(context['open_ports'])}")
        if context.get("vulns_found"):
            summary_parts.append(f"Vulnerabilities: {len(context['vulns_found'])}")
        if context.get("tools_run"):
            summary_parts.append(f"Tools run: {', '.join(context['tools_run'][-5:])}")
        
        context_summary = "; ".join(summary_parts) if summary_parts else "No data yet"
        
        prompt = f"""You are evaluating a pentest phase.

Current Phase: {current_phase} ({phase_name})
Context: {context_summary}

Evaluate:
1. Is this phase complete enough to proceed?
2. What should happen next?

Return JSON only:
{{"phase_complete": true/false, "confidence": 0.0-1.0, "next_phase": 1-6, "suggested_tools": ["tool1", "tool2"], "reasoning": "brief explanation"}}"""

        try:
            response = self.llm.generate(prompt, timeout=30, stream=False)
            
            # Extract JSON
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return {
                    "current_phase": current_phase,
                    "current_phase_name": phase_name,
                    "phase_complete": data.get("phase_complete", False),
                    "confidence": data.get("confidence", 0.5),
                    "next_phase": data.get("next_phase", current_phase),
                    "next_phase_name": PHASE_NAMES.get(data.get("next_phase", current_phase), ""),
                    "suggested_tools": data.get("suggested_tools", []),
                    "reasoning": data.get("reasoning", "")
                }
        except Exception:
            pass
        
        # Fallback
        return {
            "current_phase": current_phase,
            "current_phase_name": phase_name,
            "phase_complete": False,
            "confidence": 0.5,
            "next_phase": current_phase,
            "next_phase_name": phase_name,
            "suggested_tools": [],
            "reasoning": "Evaluation pending"
        }
    
    def check_phase_ready(self, target_phase: int, context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Check if ready to enter a phase using LLM.
        
        Returns:
            Tuple of (is_ready, suggestions)
        """
        evaluation = self.evaluate_phase_with_llm(context)
        is_ready = evaluation.get("phase_complete", False) or target_phase <= evaluation.get("current_phase", 1)
        suggestions = evaluation.get("suggested_tools", [])
        return (is_ready, suggestions)
    
    def get_phase_status(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get current phase status for display.
        
        Returns dict with phase info, progress, and next steps.
        """
        current = self.get_current_phase(context)
        
        return {
            "current_phase": current,
            "current_phase_name": PHASE_NAMES.get(current, "Unknown"),
            "next_phase": min(current + 1, 6),
            "next_phase_name": PHASE_NAMES.get(min(current + 1, 6), "Complete"),
            "ready_for_next": True,  # Always ready in autonomous mode
            "missing_for_next": [],
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
    
    def suggest_next_tools(self, context: Dict[str, Any]) -> List[str]:
        """
        Use LLM to suggest next tools based on current context.
        
        Returns:
            List of suggested tool names
        """
        evaluation = self.evaluate_phase_with_llm(context)
        return evaluation.get("suggested_tools", [])


# Singleton
_phase_manager: Optional[PhaseManager] = None


def get_phase_manager(enforcement_mode: str = "autonomous") -> PhaseManager:
    """Get or create phase manager singleton."""
    global _phase_manager
    if _phase_manager is None:
        _phase_manager = PhaseManager(enforcement_mode)
    return _phase_manager
