"""
Phase Analyzer - LLM-Driven Phase Completion Detection
=======================================================

Analyzes current pentest phase to determine if it's complete
and suggests transition to next phase.
"""

import json
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class PhaseAnalysisResult:
    """Result of phase completion analysis."""
    phase_complete: bool
    confidence: float
    summary: str
    missing: List[str]
    next_phase: int
    next_phase_name: str
    suggested_tools: List[str]
    suggested_action: str
    
    def to_suggestion_message(self) -> str:
        """Format as user-facing suggestion message."""
        if self.phase_complete:
            # Phase complete - suggest transition
            lines = [
                f"\n📊 **Phase Analysis**: Current phase appears complete",
                f"   {self.summary}",
                "",
                f"💡 **Ready for Phase {self.next_phase} ({self.next_phase_name})?**",
                f"   Suggested: {self.suggested_action}",
                f"   Tools: {', '.join(self.suggested_tools)}",
            ]
        else:
            # Phase incomplete
            lines = [
                f"\n📊 **Phase Analysis**: More work needed",
                f"   {self.summary}",
            ]
            if self.missing:
                lines.append(f"   Missing: {', '.join(self.missing)}")
            lines.extend([
                "",
                f"💡 **Suggested next step:**",
                f"   {self.suggested_action}",
            ])
        
        return "\n".join(lines)


# Phase names for display
PHASE_NAMES = {
    1: "Reconnaissance",
    2: "Scanning",
    3: "Vulnerability Assessment",
    4: "Exploitation",
    5: "Post-Exploitation",
    6: "Reporting"
}


class PhaseAnalyzer:
    """
    LLM-driven phase completion analyzer.
    
    After each tool execution, analyzes the accumulated data
    to determine if the current phase is complete and what
    should happen next.
    """
    
    def __init__(self):
        self._llm = None
    
    @property
    def llm(self):
        """Lazy-load LLM client."""
        if self._llm is None:
            from app.llm.client import OllamaClient
            self._llm = OllamaClient()
        return self._llm
    
    def analyze(self, context: Dict[str, Any]) -> PhaseAnalysisResult:
        """
        Analyze current phase completion status.
        
        Args:
            context: Current execution context with findings
            
        Returns:
            PhaseAnalysisResult with completion status and suggestions
        """
        from app.agent.prompts import format_prompt
        from app.agent.phase_manager import get_phase_manager
        
        # Get current phase
        phase_mgr = get_phase_manager()
        phase_status = phase_mgr.get_phase_status(context)
        current_phase = phase_status["current_phase"]
        phase_name = PHASE_NAMES.get(current_phase, f"Phase {current_phase}")
        
        # Build context for analysis
        target = context.get("target_domain") or context.get("last_domain") or "unknown"
        
        # Count findings
        subdomains = context.get("subdomains", [])
        ips = context.get("ips", [])
        open_ports = context.get("open_ports", [])
        vulns = context.get("vulns_found", [])
        tools_run = context.get("tools_run", [])
        detected_tech = context.get("detected_tech", [])
        dns_records = context.get("dns_records", [])
        
        try:
            prompt = format_prompt(
                "phase_analyzer",
                current_phase=current_phase,
                phase_name=phase_name,
                target=target,
                subdomain_count=len(subdomains),
                ip_count=len(ips),
                dns_count=len(dns_records) if isinstance(dns_records, list) else 0,
                tech_count=len(detected_tech),
                port_count=len(open_ports),
                service_count=len([p for p in open_ports if p.get("service")]),
                vuln_count=len(vulns),
                critical_count=len([v for v in vulns if v.get("severity") == "critical"]),
                tools_run=", ".join(tools_run[-10:]) if tools_run else "none"
            )
            
            # Get LLM analysis
            response = self.llm.generate(prompt, timeout=30, stream=False)
            
            # Parse JSON from response
            result = self._parse_response(response, current_phase)
            return result
            
        except Exception as e:
            # Fallback to heuristic-based analysis
            return self._fallback_analysis(context, current_phase, phase_name)
    
    def _parse_response(self, response: str, current_phase: int) -> PhaseAnalysisResult:
        """Parse LLM JSON response into PhaseAnalysisResult."""
        # Try to extract JSON from response
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        
        if json_match:
            try:
                data = json.loads(json_match.group())
                return PhaseAnalysisResult(
                    phase_complete=data.get("phase_complete", False),
                    confidence=data.get("confidence", 0.5),
                    summary=data.get("summary", "Analysis complete"),
                    missing=data.get("missing", []),
                    next_phase=data.get("next_phase", current_phase),
                    next_phase_name=data.get("next_phase_name", PHASE_NAMES.get(current_phase, "")),
                    suggested_tools=data.get("suggested_tools", []),
                    suggested_action=data.get("suggested_action", "Continue with current phase")
                )
            except json.JSONDecodeError:
                pass
        
        # If JSON parsing fails, try to infer from text
        return self._infer_from_text(response, current_phase)
    
    def _infer_from_text(self, response: str, current_phase: int) -> PhaseAnalysisResult:
        """Infer analysis result from text response."""
        response_lower = response.lower()
        
        phase_complete = any(word in response_lower for word in ["complete", "ready", "proceed", "move on"])
        next_phase = current_phase + 1 if phase_complete else current_phase
        
        return PhaseAnalysisResult(
            phase_complete=phase_complete,
            confidence=0.5,
            summary="Based on current findings",
            missing=[],
            next_phase=next_phase,
            next_phase_name=PHASE_NAMES.get(next_phase, f"Phase {next_phase}"),
            suggested_tools=[],
            suggested_action="Continue assessment"
        )
    
    def _fallback_analysis(self, context: Dict, current_phase: int, phase_name: str) -> PhaseAnalysisResult:
        """Heuristic-based fallback when LLM fails."""
        subdomains = context.get("subdomains", [])
        ips = context.get("ips", [])
        open_ports = context.get("open_ports", [])
        vulns = context.get("vulns_found", [])
        
        # Phase-specific heuristics
        if current_phase == 1:  # Recon
            complete = len(subdomains) >= 5 or len(ips) >= 3
            next_tools = ["nmap", "httpx"]
            action = "Run port scan on discovered hosts"
        elif current_phase == 2:  # Scanning
            complete = len(open_ports) >= 3
            next_tools = ["nuclei", "nikto"]
            action = "Run vulnerability scans on open services"
        elif current_phase == 3:  # Vuln
            complete = len(vulns) >= 1
            next_tools = ["sqlmap", "metasploit"]
            action = "Attempt exploitation of found vulnerabilities"
        else:
            complete = False
            next_tools = []
            action = "Continue current phase"
        
        next_phase = current_phase + 1 if complete else current_phase
        
        return PhaseAnalysisResult(
            phase_complete=complete,
            confidence=0.6,
            summary=f"Heuristic analysis of {phase_name}",
            missing=[] if complete else ["More data needed"],
            next_phase=next_phase,
            next_phase_name=PHASE_NAMES.get(next_phase, ""),
            suggested_tools=next_tools,
            suggested_action=action
        )
    
    def should_suggest_transition(self, context: Dict[str, Any]) -> bool:
        """Quick check if we should even run full analysis."""
        # Don't suggest transition if very little data
        tools_run = context.get("tools_run", [])
        return len(tools_run) >= 1


# Singleton
_analyzer: Optional[PhaseAnalyzer] = None


def get_phase_analyzer() -> PhaseAnalyzer:
    """Get or create phase analyzer singleton."""
    global _analyzer
    if _analyzer is None:
        _analyzer = PhaseAnalyzer()
    return _analyzer


def analyze_phase_completion(context: Dict[str, Any]) -> Optional[PhaseAnalysisResult]:
    """
    Convenience function to analyze phase completion.
    
    Returns None if analysis not needed or failed.
    """
    analyzer = get_phase_analyzer()
    
    if not analyzer.should_suggest_transition(context):
        return None
    
    return analyzer.analyze(context)
