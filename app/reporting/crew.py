"""
CrewAI Report Generation Module
================================

Multi-agent crew for generating professional pentest reports.

Agents:
1. Security Analyst - Analyzes findings, assigns CVSS scores
2. Report Writer - Creates technical report
3. Executive Summarizer - Business impact summary
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
import os

from crewai import Agent, Task, Crew, Process


# ============================================================
# LLM CONFIG
# ============================================================

def get_ollama_llm():
    """Get Ollama LLM for CrewAI agents using litellm."""
    from crewai import LLM
    from app.agent.graph import get_current_model
    
    model = get_current_model()
    
    # Use litellm's ollama_chat provider
    return LLM(
        model=f"ollama_chat/{model}",
        base_url="http://localhost:11434",
        temperature=0.3
    )


# ============================================================
# AGENTS
# ============================================================

def create_security_analyst() -> Agent:
    """Security analyst agent - analyzes vulnerabilities."""
    return Agent(
        role="Senior Security Analyst",
        goal="Analyze security scan results, identify vulnerabilities, and assign risk levels",
        backstory="""You are a senior penetration tester with 10+ years of experience.
        You excel at analyzing raw tool outputs and identifying security issues.
        You use CVSS scoring to prioritize vulnerabilities.""",
        llm=get_ollama_llm(),
        verbose=True,
        allow_delegation=False
    )


def create_report_writer() -> Agent:
    """Technical report writer agent."""
    return Agent(
        role="Technical Report Writer",
        goal="Create comprehensive, professional penetration testing reports",
        backstory="""You are an expert technical writer specializing in cybersecurity reports.
        You document findings clearly with evidence, impact analysis, and remediation steps.
        Your reports follow industry standards like PTES and OWASP.""",
        llm=get_ollama_llm(),
        verbose=True,
        allow_delegation=False
    )


def create_executive_summarizer() -> Agent:
    """Executive summary agent."""
    return Agent(
        role="Executive Communication Specialist",
        goal="Translate technical findings into business impact summaries",
        backstory="""You specialize in communicating technical risks to non-technical stakeholders.
        You focus on business impact, risk levels, and actionable recommendations.
        You avoid jargon and use clear, concise language.""",
        llm=get_ollama_llm(),
        verbose=True,
        allow_delegation=False
    )


# ============================================================
# TASKS
# ============================================================

def create_analysis_task(agent: Agent, scan_data: Dict[str, Any]) -> Task:
    """Task for security analysis."""
    
    # Format scan data for analysis
    findings_text = format_scan_data(scan_data)
    
    return Task(
        description=f"""Analyze the following security scan results and create a COMPREHENSIVE vulnerability assessment.

SCAN RESULTS:
{findings_text}

ANALYZE FOR EACH OF THESE VULNERABILITY TYPES:

1. **EXPOSED ADMIN PANELS** (CRITICAL):
   - cPanel (ports 2082, 2083)
   - WHM/WebHost Manager (ports 2086, 2087)
   - Webmail (ports 2095, 2096)
   - phpMyAdmin, Plesk, DirectAdmin
   - WordPress wp-admin, Joomla administrator

2. **INFORMATION DISCLOSURE** (HIGH):
   - Azure/Microsoft Tenant IDs (in OpenID Connect endpoints)
   - OAuth endpoints with token URLs
   - Email addresses found
   - Internal IP addresses (10.x, 172.16.x, 192.168.x)
   - Directory listings

3. **VULNERABLE TECHNOLOGIES** (HIGH):
   - WordPress installations (wp-content, wp-includes)
   - Joomla installations
   - Microsoft Exchange (check for ProxyLogon/ProxyShell)
   - Microsoft IIS (check version)
   - Apache, nginx (check versions)

4. **OPEN PORTS AND SERVICES** (MEDIUM-HIGH):
   - SSH (22), FTP (21), RDP (3389)
   - Databases: MySQL (3306), PostgreSQL (5432), MongoDB (27017)
   - Mail: SMTP (25/587), POP3 (110), IMAP (143)

5. **MISCONFIGURATIONS** (MEDIUM):
   - HTTP 521 errors (Cloudflare origin down)
   - HTTP 403/500 errors
   - Open redirects (302 to arbitrary URLs)
   - Missing security headers

6. **RECONNAISSANCE DATA** (INFO):
   - All discovered subdomains
   - DNS records (MX, TXT, NS)
   - SSL certificates
   - Social media profiles found

FOR EACH FINDING, PROVIDE:
- Detailed description
- CVSS 3.1 score with vector
- Risk level (Critical/High/Medium/Low/Info)
- Affected assets (exact URLs, IPs, ports)
- Evidence from scan data
- Potential attack scenarios
- Remediation steps

Be THOROUGH. Do not skip any findings. Include ALL discovered data.""",
        expected_output="Comprehensive vulnerability assessment with all findings, CVSS scores, and detailed analysis",
        agent=agent
    )


def create_report_task(agent: Agent, analysis_task: Task) -> Task:
    """Task for report writing - depends on analysis task."""
    return Task(
        description="""Based on the security analysis, create a DETAILED professional penetration testing report.

Include ALL of the following sections with FULL DETAIL:

## 1. Executive Summary
- Overall risk level with justification
- Total vulnerabilities by severity (Critical/High/Medium/Low/Info)
- Most critical findings (top 5)
- Immediate actions required

## 2. Scope and Methodology
- Target domain and all tested subdomains
- IP addresses scanned
- Ports and services tested
- Tools used: amass, bbot, nmap, nuclei, wpscan, gobuster, etc.
- Testing methodology (PTES, OWASP)
- Date and duration of testing

## 3. Findings (DETAILED)
For EACH vulnerability found:
- **Title** with severity badge
- **Description** - what was found
- **CVSS Score** - with full vector string
- **Affected Assets** - exact URLs, IPs, ports
- **Evidence** - raw output snippets proving the finding
- **Impact** - what an attacker could do
- **Remediation** - specific steps to fix
- **References** - CVE IDs, external links

## 4. Remediation Summary
- Priority matrix (Critical→Low)
- Estimated effort for each fix
- Quick wins vs long-term fixes

## 5. Technical Appendix
- Full subdomain list
- Port scan results
- Technology fingerprints
- All discovered endpoints
- Raw tool outputs (summarized)

Use markdown formatting with:
- Severity badges: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low, 🔵 Info
- Code blocks for evidence
- Tables for organized data

DO NOT LIMIT the report length. Be as detailed as necessary to capture all findings.""",
        expected_output="Complete detailed markdown penetration testing report with all findings and evidence",
        agent=agent,
        context=[analysis_task]
    )


def create_summary_task(agent: Agent, report_task: Task) -> Task:
    """Task for executive summary - depends on report task."""
    return Task(
        description="""Create a comprehensive executive summary for stakeholders.

Include ALL of the following:

## Overall Risk Assessment
- Risk level: Critical/High/Medium/Low
- Confidence level in assessment
- Comparison to industry benchmarks if applicable

## Key Findings Summary
List ALL critical and high findings in plain language:
- What was found
- Why it matters to the business
- What could happen if exploited

## Business Impact Analysis
For each major finding:
- Financial risk (potential losses)
- Reputation risk
- Legal/compliance risk (GDPR, PCI-DSS, etc.)
- Operational risk

## Priority Actions
Ranked list of remediation actions:
1. **Immediate (24 hours)** - Critical items
2. **Short-term (1 week)** - High priority items
3. **Medium-term (1 month)** - Medium priority items
4. **Long-term (ongoing)** - Security improvements

## Resource Requirements
- Estimated time for remediation
- Skills required
- Potential costs

## Conclusion
- Summary of security posture
- Recommendations for follow-up testing
- Suggested security improvements

Write in clear business language but DO NOT omit important details.
Include specific examples and data to support conclusions.""",
        expected_output="Comprehensive executive summary with business impact analysis and prioritized actions",
        agent=agent,
        context=[report_task]
    )


# ============================================================
# CREW
# ============================================================

class ReportCrew:
    """CrewAI-powered report generation."""
    
    def __init__(self):
        self.analyst = create_security_analyst()
        self.writer = create_report_writer()
        self.summarizer = create_executive_summarizer()
    
    def generate_report(
        self,
        context: Dict[str, Any],
        results: Dict[str, Any],
        output_dir: str = "reports"
    ) -> Dict[str, str]:
        """
        Generate full penetration testing report.
        
        Returns:
            Dict with 'analysis', 'report', 'summary', 'file_path'
        """
        print("  🤖 Starting CrewAI report generation...")
        
        # Prepare scan data
        scan_data = {
            "target": context.get("last_domain", "Unknown"),
            "subdomains": context.get("subdomains", []),
            "subdomain_count": context.get("subdomain_count", 0),
            "has_ports": context.get("has_ports", False),
            "results": results
        }
        
        # Create tasks with proper chaining
        analysis_task = create_analysis_task(self.analyst, scan_data)
        report_task = create_report_task(self.writer, analysis_task)
        summary_task = create_summary_task(self.summarizer, report_task)
        
        # Run all tasks in single Crew
        print("  � Running Security Analyst → Report Writer → Executive Summarizer...")
        
        crew = Crew(
            agents=[self.analyst, self.writer, self.summarizer],
            tasks=[analysis_task, report_task, summary_task],
            process=Process.sequential,
            verbose=True
        )
        
        final_result = crew.kickoff()
        
        # Extract individual results
        analysis_result = str(analysis_task.output) if analysis_task.output else ""
        report_result = str(report_task.output) if report_task.output else ""
        summary_result = str(final_result)
        
        # Save report
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        target_name = context.get("last_domain", "unknown").replace(".", "_")
        
        file_path = f"{output_dir}/{target_name}_{timestamp}.md"
        
        full_report = f"""# Penetration Testing Report
**Target:** {context.get("last_domain", "Unknown")}
**Date:** {datetime.now().strftime("%Y-%m-%d")}

---

## Executive Summary

{summary_result}

---

## Technical Report

{report_result}

---

## Detailed Analysis

{analysis_result}

---

## Appendix: Raw Tool Evidence

*Full untruncated tool output for forensic evidence*

"""
        
        # Add raw tool output for evidence
        for tool, data in results.items():
            if isinstance(data, dict) and data.get("success"):
                output = data.get("output", "")
                full_report += f"""### {tool.upper()}

```
{output}
```

"""
        
        with open(file_path, 'w') as f:
            f.write(full_report)
        
        print(f"  ✅ Report saved to: {file_path}")
        
        return {
            "analysis": str(analysis_result),
            "report": str(report_result),
            "summary": str(summary_result),
            "file_path": file_path
        }


# ============================================================
# UTILITIES
# ============================================================

def format_scan_data(scan_data: Dict[str, Any]) -> str:
    """Format scan data for LLM analysis - NO LIMITS for comprehensive reports."""
    parts = []
    
    # Target info
    parts.append(f"Target: {scan_data.get('target', 'Unknown')}")
    
    # Context data
    context = scan_data.get("context", {})
    if context:
        parts.append(f"\nContext:")
        if context.get("detected_tech"):
            parts.append(f"  Detected Technologies: {', '.join(context.get('detected_tech', []))}")
        if context.get("subdomain_count"):
            parts.append(f"  Subdomain Count: {context.get('subdomain_count')}")
        if context.get("has_ports"):
            parts.append(f"  Ports Scanned: Yes")
    
    # ALL Subdomains - no limit
    subdomains = scan_data.get("subdomains", [])
    if subdomains:
        parts.append(f"\nALL Subdomains Found ({len(subdomains)}):")
        for sub in subdomains:  
            parts.append(f"  - {sub}")
    
    # Tool results - extended output
    results = scan_data.get("results", {})
    if results:
        parts.append("\n" + "="*60)
        parts.append("FULL TOOL OUTPUTS")
        parts.append("="*60)
        for tool, data in results.items():
            if isinstance(data, dict):
                success = data.get("success", False)
                # Include up to 10000 chars of each tool output for comprehensive analysis
                output = data.get("output", "")[:10000]
                parts.append(f"\n### {tool.upper()}: {'SUCCESS' if success else 'FAILED'}")
                parts.append("-" * 40)
                if output:
                    parts.append(output)
                else:
                    parts.append("(No output)")
    
    return "\n".join(parts)


# Factory function
def create_report_crew() -> ReportCrew:
    return ReportCrew()
