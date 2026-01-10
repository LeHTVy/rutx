"""
Report Agent - Specializes in Report Generation
================================================

Handles Phase 4 operations:
- Summarizing findings
- Generating vulnerability reports
- Formatting output for documentation
"""
from typing import List, Dict, Any
from .base_agent import BaseAgent


class ReportAgent(BaseAgent):
    """Specialized agent for report generation and documentation."""
    
    AGENT_NAME = "report"
    AGENT_DESCRIPTION = "Report specialist - summarize findings, generate reports"
    SPECIALIZED_TOOLS = []  # No external tools, uses LLM only
    PENTEST_PHASES = [4]  # Reporting phase only
    
    # Keywords that suggest report tasks
    REPORT_KEYWORDS = [
        "report", "summary", "summarize", "findings", "document", "export",
        "what did we find", "show results", "list vulnerabilities", "conclusion"
    ]
    
    def plan(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan report generation based on query and context.
        
        No tools needed - uses LLM to generate reports from context.
        """
        report_type = self._classify_report_type(query.lower())
        
        return {
            "agent": self.AGENT_NAME,
            "tools": [],  # No tools, LLM-only
            "commands": {},
            "reasoning": f"Generating {report_type} report from findings",
            "report_type": report_type
        }
    
    def _classify_report_type(self, query: str) -> str:
        """Classify the type of report needed."""
        if "executive" in query:
            return "executive"
        if "technical" in query or "detailed" in query:
            return "technical"
        if "vulnerability" in query or "vuln" in query:
            return "vulnerability"
        if "summary" in query:
            return "summary"
        return "summary"
    
    def generate_report(self, context: Dict[str, Any], report_type: str = "summary") -> str:
        """Generate a report based on context and type."""
        
        # Gather all findings
        domain = context.get("last_domain", "Unknown")
        subdomains = context.get("subdomains", [])
        open_ports = context.get("open_ports", [])
        vulns = context.get("vulns_found", [])
        detected_tech = context.get("detected_tech", [])
        tools_run = context.get("tools_run", [])
        
        if report_type == "executive":
            return self._executive_report(domain, subdomains, open_ports, vulns)
        elif report_type == "technical":
            return self._technical_report(domain, subdomains, open_ports, vulns, detected_tech, tools_run)
        elif report_type == "vulnerability":
            return self._vulnerability_report(domain, vulns)
        else:
            return self._summary_report(domain, subdomains, open_ports, vulns, detected_tech)
    
    def _executive_report(self, domain: str, subdomains: List, ports: List, vulns: List) -> str:
        """Generate executive summary for management."""
        
        risk_level = self._calculate_risk(vulns, ports)
        
        report = f"""# Executive Summary - {domain}

## Risk Assessment: {risk_level}

### Key Findings
- **Attack Surface**: {len(subdomains)} subdomains discovered
- **Open Services**: {len(ports)} ports exposed
- **Vulnerabilities**: {len(vulns)} identified

### Recommendations
"""
        if vulns:
            report += "1. **Critical**: Address identified vulnerabilities immediately\n"
        if len(subdomains) > 10:
            report += "2. Review subdomain exposure and consolidate where possible\n"
        if not vulns and not ports:
            report += "- Continue periodic security assessments\n"
        
        return report
    
    def _technical_report(self, domain: str, subdomains: List, ports: List, 
                         vulns: List, tech: List, tools: List) -> str:
        """Generate detailed technical report."""
        
        report = f"""# Technical Penetration Test Report

## Target: {domain}

## Methodology
Tools used: {', '.join(tools[:10]) if tools else 'None recorded'}

## Findings

### Subdomain Enumeration
Found {len(subdomains)} subdomains:
"""
        # List first 10 subdomains
        for sub in subdomains[:10]:
            report += f"- {sub}\n"
        if len(subdomains) > 10:
            report += f"- ... and {len(subdomains) - 10} more\n"
        
        report += f"""
### Port Analysis
Open ports: {ports[:10] if ports else 'None found'}

### Technology Stack
Detected: {', '.join(tech[:5]) if tech else 'None identified'}

### Vulnerabilities
"""
        if vulns:
            for vuln in vulns[:10]:
                report += f"- {vuln}\n"
        else:
            report += "No critical vulnerabilities identified.\n"
        
        return report
    
    def _vulnerability_report(self, domain: str, vulns: List) -> str:
        """Generate vulnerability-focused report."""
        
        report = f"""# Vulnerability Report - {domain}

## Summary
Total vulnerabilities found: {len(vulns)}

## Vulnerability List
"""
        if vulns:
            for i, vuln in enumerate(vulns[:20], 1):
                report += f"{i}. {vuln}\n"
        else:
            report += "No vulnerabilities found during this assessment.\n"
        
        return report
    
    def _summary_report(self, domain: str, subdomains: List, ports: List, 
                       vulns: List, tech: List) -> str:
        """Generate quick summary report."""
        
        return f"""# Scan Summary - {domain}

| Metric | Count |
|--------|-------|
| Subdomains | {len(subdomains)} |
| Open Ports | {len(ports)} |
| Vulnerabilities | {len(vulns)} |
| Technologies | {len(tech)} |

## Next Steps
{"- Address vulnerabilities" if vulns else "- Expand scanning scope"}
"""
    
    def _calculate_risk(self, vulns: List, ports: List) -> str:
        """Calculate overall risk level."""
        if len(vulns) > 10:
            return "🔴 CRITICAL"
        if len(vulns) > 5:
            return "🟠 HIGH"
        if len(vulns) > 0 or len(ports) > 10:
            return "🟡 MEDIUM"
        return "🟢 LOW"
    
    def analyze_results(self, results: Dict[str, Any], context: Dict[str, Any]) -> str:
        """For report agent, this generates the report."""
        return self.generate_report(context)
    
    def can_handle(self, phase: int, query: str) -> bool:
        """Check if this is a report task."""
        if phase == 4:
            return True
        
        query_lower = query.lower()
        return any(kw in query_lower for kw in self.REPORT_KEYWORDS)
