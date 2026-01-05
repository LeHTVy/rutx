"""
Evidence Capture - Forensic-Grade Proof for Pentest Findings
=============================================================

Non-negotiable for real penetration tests: every finding must have proof.
Captures commands, timestamps, outputs, and organizes by finding.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from uuid import uuid4
import json
import hashlib

from app.core.config import get_config


@dataclass
class Evidence:
    """
    Proof of a security finding.
    
    Every piece of evidence links to a finding and contains
    everything needed to reproduce and verify the result.
    """
    id: str
    finding_id: Optional[str]  # Links to vulnerability/finding (None if no finding)
    tool: str                  # Tool that produced this
    command: str               # Exact command executed
    timestamp: str             # ISO format
    output_snippet: str        # Relevant output (truncated for display)
    full_output_hash: str      # SHA256 of full output for integrity
    full_output_path: Optional[str]  # Path to full output file
    target: str                # Target that was tested
    confidence: str            # "low", "medium", "high"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def create(
        cls,
        tool: str,
        command: str,
        output: str,
        target: str,
        finding_id: Optional[str] = None,
        confidence: str = "medium",
        metadata: Optional[Dict] = None
    ) -> "Evidence":
        """Factory method to create evidence with auto-generated fields."""
        # Create hash of full output for integrity verification
        output_hash = hashlib.sha256(output.encode()).hexdigest()[:16]
        
        # Truncate output for snippet
        snippet = output[:1000] if len(output) > 1000 else output
        if len(output) > 1000:
            snippet += f"\n... [truncated, {len(output)} total chars]"
        
        return cls(
            id=str(uuid4())[:8],
            finding_id=finding_id,
            tool=tool,
            command=command,
            timestamp=datetime.now().isoformat(),
            output_snippet=snippet,
            full_output_hash=output_hash,
            full_output_path=None,  # Set by EvidenceStore
            target=target,
            confidence=confidence,
            metadata=metadata or {}
        )
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: Dict) -> "Evidence":
        return cls(**d)
    
    def to_markdown(self) -> str:
        """Format evidence as markdown for reports."""
        lines = [
            f"### Evidence: {self.id}",
            f"",
            f"**Tool:** {self.tool}",
            f"**Target:** {self.target}",
            f"**Timestamp:** {self.timestamp}",
            f"**Confidence:** {self.confidence}",
            f"",
            f"**Command:**",
            f"```bash",
            f"{self.command}",
            f"```",
            f"",
            f"**Output:**",
            f"```",
            f"{self.output_snippet}",
            f"```",
        ]
        
        if self.finding_id:
            lines.insert(2, f"**Finding ID:** {self.finding_id}")
        
        return "\n".join(lines)


@dataclass
class Finding:
    """
    A security finding with associated evidence.
    
    Findings represent confirmed or suspected vulnerabilities,
    misconfigurations, or security issues.
    """
    id: str
    title: str
    description: str
    severity: str  # "info", "low", "medium", "high", "critical"
    target: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence_ids: List[str] = field(default_factory=list)
    status: str = "unconfirmed"  # "unconfirmed", "confirmed", "false_positive"
    timestamp: str = ""
    remediation: Optional[str] = None
    
    @classmethod
    def create(
        cls,
        title: str,
        description: str,
        severity: str,
        target: str,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None
    ) -> "Finding":
        return cls(
            id=str(uuid4())[:8],
            title=title,
            description=description,
            severity=severity,
            target=target,
            cve_id=cve_id,
            cvss_score=cvss_score,
            timestamp=datetime.now().isoformat()
        )
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: Dict) -> "Finding":
        return cls(**d)


class EvidenceStore:
    """
    Capture and manage evidence for pentest reports.
    
    Features:
    - Automatic evidence capture from tool execution
    - Finding management with evidence linking
    - Export to JSON/Markdown formats
    - Persistent storage with integrity verification
    """
    
    def __init__(self, persist: bool = True):
        self.evidence: List[Evidence] = []
        self.findings: List[Finding] = []
        self.persist = persist
        
        # Setup directories
        config = get_config()
        self.evidence_dir = config.discoveries_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.outputs_dir = self.evidence_dir / "outputs"
        self.outputs_dir.mkdir(parents=True, exist_ok=True)
        
        self.evidence_file = self.evidence_dir / "evidence_index.json"
        self.findings_file = self.evidence_dir / "findings.json"
        
        if persist:
            self.load()
    
    # ========== Evidence Capture ==========
    
    def capture(
        self,
        tool: str,
        command: str,
        output: str,
        target: str,
        finding_id: Optional[str] = None,
        confidence: str = "medium",
        metadata: Optional[Dict] = None
    ) -> Evidence:
        """
        Capture evidence from a tool execution.
        
        Args:
            tool: Name of the tool that was executed
            command: The exact command that was run
            output: Full output from the tool
            target: Target that was tested
            finding_id: Optional link to a finding
            confidence: Confidence level ("low", "medium", "high")
            metadata: Additional context
        
        Returns:
            The created Evidence object
        """
        evidence = Evidence.create(
            tool=tool,
            command=command,
            output=output,
            target=target,
            finding_id=finding_id,
            confidence=confidence,
            metadata=metadata
        )
        
        # Save full output to file
        if output and len(output) > 500:
            output_filename = f"{evidence.id}_{tool}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            output_path = self.outputs_dir / output_filename
            with open(output_path, 'w') as f:
                f.write(f"Tool: {tool}\n")
                f.write(f"Command: {command}\n")
                f.write(f"Target: {target}\n")
                f.write(f"Timestamp: {evidence.timestamp}\n")
                f.write(f"{'='*60}\n\n")
                f.write(output)
            evidence.full_output_path = str(output_path)
        
        self.evidence.append(evidence)
        
        if self.persist:
            self._save_evidence()
        
        return evidence
    
    def capture_from_execution(
        self,
        action: str,
        action_input: Dict[str, Any],
        result: str,
        success: bool = True
    ) -> Evidence:
        """
        Convenience method to capture evidence from agentic loop execution.
        
        Automatically extracts target and builds command string.
        """
        # Extract target from input
        target = (
            action_input.get("target") or
            action_input.get("domain") or
            action_input.get("url") or
            action_input.get("file") or
            "unknown"
        )
        
        # Build command string representation
        params_str = " ".join(f"--{k}={v}" for k, v in action_input.items() if v)
        command = f"{action} {params_str}".strip()
        
        # Determine confidence based on success
        confidence = "high" if success else "low"
        
        return self.capture(
            tool=action,
            command=command,
            output=result,
            target=target,
            confidence=confidence,
            metadata={"success": success, "input": action_input}
        )
    
    # ========== Finding Management ==========
    
    def create_finding(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        evidence: Optional[Evidence] = None,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None
    ) -> Finding:
        """Create a finding and optionally link evidence."""
        finding = Finding.create(
            title=title,
            description=description,
            severity=severity,
            target=target,
            cve_id=cve_id,
            cvss_score=cvss_score
        )
        
        if evidence:
            finding.evidence_ids.append(evidence.id)
            evidence.finding_id = finding.id
        
        self.findings.append(finding)
        
        if self.persist:
            self._save_findings()
            self._save_evidence()
        
        return finding
    
    def link_evidence_to_finding(self, evidence_id: str, finding_id: str) -> bool:
        """Link an existing evidence to a finding."""
        evidence = self.get_evidence_by_id(evidence_id)
        finding = self.get_finding_by_id(finding_id)
        
        if evidence and finding:
            evidence.finding_id = finding_id
            if evidence_id not in finding.evidence_ids:
                finding.evidence_ids.append(evidence_id)
            
            if self.persist:
                self._save_evidence()
                self._save_findings()
            return True
        
        return False
    
    def confirm_finding(self, finding_id: str) -> None:
        """Mark a finding as confirmed."""
        finding = self.get_finding_by_id(finding_id)
        if finding:
            finding.status = "confirmed"
            if self.persist:
                self._save_findings()
    
    def mark_false_positive(self, finding_id: str) -> None:
        """Mark a finding as false positive."""
        finding = self.get_finding_by_id(finding_id)
        if finding:
            finding.status = "false_positive"
            if self.persist:
                self._save_findings()
    
    # ========== Query Methods ==========
    
    def get_evidence_by_id(self, evidence_id: str) -> Optional[Evidence]:
        for e in self.evidence:
            if e.id == evidence_id:
                return e
        return None
    
    def get_finding_by_id(self, finding_id: str) -> Optional[Finding]:
        for f in self.findings:
            if f.id == finding_id:
                return f
        return None
    
    def get_evidence_for_finding(self, finding_id: str) -> List[Evidence]:
        return [e for e in self.evidence if e.finding_id == finding_id]
    
    def get_evidence_for_target(self, target: str) -> List[Evidence]:
        return [e for e in self.evidence if e.target == target or target in e.target]
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]
    
    def get_confirmed_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == "confirmed"]
    
    # ========== Export ==========
    
    def export_report(self, format: str = "markdown") -> str:
        """Export all findings and evidence as a report."""
        if format == "json":
            return self._export_json()
        else:
            return self._export_markdown()
    
    def _export_markdown(self) -> str:
        """Export as markdown report."""
        lines = [
            "# Penetration Test Report",
            "",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**Total Findings:** {len(self.findings)}",
            f"**Total Evidence Items:** {len(self.evidence)}",
            "",
            "---",
            "",
        ]
        
        # Summary by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        lines.append("## Executive Summary\n")
        for sev in severity_order:
            count = len(self.get_findings_by_severity(sev))
            if count > 0:
                lines.append(f"- **{sev.upper()}:** {count}")
        lines.append("")
        
        # Detailed findings
        lines.append("## Detailed Findings\n")
        
        for sev in severity_order:
            findings = self.get_findings_by_severity(sev)
            if not findings:
                continue
            
            lines.append(f"### {sev.upper()} Severity\n")
            
            for finding in findings:
                lines.append(f"#### {finding.title}")
                lines.append(f"")
                lines.append(f"**Target:** {finding.target}")
                lines.append(f"**Status:** {finding.status}")
                if finding.cve_id:
                    lines.append(f"**CVE:** {finding.cve_id}")
                if finding.cvss_score:
                    lines.append(f"**CVSS:** {finding.cvss_score}")
                lines.append(f"")
                lines.append(finding.description)
                lines.append("")
                
                # Evidence for this finding
                evidence = self.get_evidence_for_finding(finding.id)
                if evidence:
                    lines.append("**Evidence:**\n")
                    for e in evidence:
                        lines.append(e.to_markdown())
                        lines.append("")
                
                lines.append("---\n")
        
        return "\n".join(lines)
    
    def _export_json(self) -> str:
        """Export as JSON."""
        data = {
            "generated": datetime.now().isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "evidence": [e.to_dict() for e in self.evidence]
        }
        return json.dumps(data, indent=2)
    
    # ========== Persistence ==========
    
    def save(self) -> None:
        """Save all data to disk (fails silently on permission errors)."""
        self._save_evidence()
        self._save_findings()
    
    def load(self) -> None:
        """Load data from disk."""
        self._load_evidence()
        self._load_findings()
    
    def _save_evidence(self) -> None:
        try:
            with open(self.evidence_file, 'w') as f:
                json.dump([e.to_dict() for e in self.evidence], f, indent=2)
        except PermissionError:
            pass
        except Exception:
            pass
    
    def _load_evidence(self) -> None:
        if self.evidence_file.exists():
            try:
                with open(self.evidence_file, 'r') as f:
                    data = json.load(f)
                    self.evidence = [Evidence.from_dict(d) for d in data]
            except (json.JSONDecodeError, KeyError, TypeError, PermissionError):
                self.evidence = []
    
    def _save_findings(self) -> None:
        try:
            with open(self.findings_file, 'w') as f:
                json.dump([f.to_dict() for f in self.findings], f, indent=2)
        except PermissionError:
            pass
        except Exception:
            pass
    
    def _load_findings(self) -> None:
        if self.findings_file.exists():
            try:
                with open(self.findings_file, 'r') as f:
                    data = json.load(f)
                    self.findings = [Finding.from_dict(d) for d in data]
            except (json.JSONDecodeError, KeyError, TypeError, PermissionError):
                self.findings = []
    
    def clear_all(self) -> None:
        """Clear all evidence and findings."""
        self.evidence.clear()
        self.findings.clear()
        if self.persist:
            self.save()
    
    def __len__(self) -> int:
        return len(self.evidence)
    
    def __repr__(self) -> str:
        return f"EvidenceStore(evidence={len(self.evidence)}, findings={len(self.findings)})"
