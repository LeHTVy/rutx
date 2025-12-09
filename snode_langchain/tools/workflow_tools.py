"""
Workflow Tools - LangGraph workflows exposed as LLM-choosable tools

This allows the LLM to decide when to use complex workflows instead of
relying on keyword detection.
"""
import json
from typing import Dict, Any


def vuln_assessment_workflow(target: str) -> Dict[str, Any]:
    """
    Run comprehensive vulnerability assessment on a target.
    
    This workflow uses multiple tools in parallel:
    - httpx: Probe target and detect technologies
    - nuclei: Vulnerability scanning with CVE templates
    - nikto: Web server vulnerability scanning  
    - dalfox: XSS vulnerability detection
    - CVE RAG: Search for potential CVEs based on detected technologies
    
    Best for: Full security assessment of websites, finding vulnerabilities.
    
    Args:
        target: URL or domain to scan (e.g., "https://example.com" or "example.com")
    
    Returns:
        Dictionary with vulnerability findings, severity counts, and LLM analysis.
    """
    try:
        from snode_langchain.orchestration.langgraph_vuln import VulnAssessmentGraph
        # We need an agent reference for LLM analysis, but can pass None for tool-only mode
        
        # Import agent singleton if available
        agent = None
        try:
            from snode_langchain.agent import _current_agent
            agent = _current_agent
        except:
            pass
        
        workflow = VulnAssessmentGraph(agent)
        
        # Ensure target has protocol
        if not target.startswith("http"):
            target = f"https://{target}"
        
        print(f"\n🔴 Starting Vulnerability Assessment Workflow for {target}")
        result = workflow.run(target)
        
        # Format summary for LLM
        summary = {
            "success": True,
            "target": target,
            "is_alive": result.get("is_alive", False),
            "technologies": result.get("technologies", [])[:10],
            "vulnerability_summary": {
                "critical": result.get("critical_count", 0),
                "high": result.get("high_count", 0),
                "medium": result.get("medium_count", 0),
                "low": result.get("low_count", 0),
                "total": len(result.get("all_vulnerabilities", [])),
            },
            "top_vulnerabilities": [
                {
                    "name": v.get("name", ""),
                    "severity": v.get("severity", ""),
                    "cve": v.get("cve", ""),
                    "source": v.get("source", ""),
                }
                for v in result.get("all_vulnerabilities", [])[:10]
            ],
            "analysis": result.get("analysis", ""),
            "recommendations": result.get("recommendations", []),
            "tools_used": result.get("tools_completed", []),
            "errors": result.get("errors", []),
        }
        
        return summary
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "target": target,
        }


def subdomain_enum_workflow(domain: str) -> Dict[str, Any]:
    """
    Enumerate subdomains of a domain using multiple tools in parallel.
    
    This workflow uses:
    - amass: Comprehensive subdomain enumeration
    - subfinder: Fast subdomain discovery
    - bbot: Recursive subdomain scanning
    
    Results are deduplicated and analyzed by LLM for high-value targets.
    
    Best for: Discovering attack surface, finding hidden subdomains.
    
    Args:
        domain: Root domain to enumerate (e.g., "example.com")
    
    Returns:
        Dictionary with subdomains found, high-value targets, and analysis.
    """
    try:
        from snode_langchain.orchestration.langgraph_subdomain import SubdomainEnumGraph
        
        # Import agent singleton if available
        agent = None
        try:
            from snode_langchain.agent import _current_agent
            agent = _current_agent
        except:
            pass
        
        workflow = SubdomainEnumGraph(agent)
        
        # Clean domain
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        
        print(f"\n🌐 Starting Subdomain Enumeration Workflow for {domain}")
        result = workflow.run(domain)
        
        # Format summary for LLM
        summary = {
            "success": True,
            "domain": domain,
            "total_subdomains": result.get("total_subdomains", 0),
            "unique_subdomains": result.get("unique_subdomains", [])[:50],
            "high_value_targets": result.get("high_value_targets", [])[:10],
            "analysis": result.get("analysis", ""),
            "tools_used": result.get("tools_completed", []),
            "errors": result.get("errors", []),
        }
        
        return summary
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "domain": domain,
        }


# ─────────────────────────────────────────────────────────────────
# Tool Definitions for Agent
# ─────────────────────────────────────────────────────────────────

WORKFLOW_TOOLS = [
    {
        "name": "vuln_assessment_workflow",
        "description": """Run comprehensive vulnerability assessment on a target using multiple tools in parallel (httpx, nuclei, nikto, dalfox, CVE database).
Best for: Full security assessment, finding CVEs, vulnerability scanning.
Use when user wants to: scan for vulnerabilities, security assessment, find CVEs, check for exploits.
Args: target (URL or domain like "https://example.com")""",
        "parameters": {
            "target": "URL or domain to scan (required)",
        },
        "function": vuln_assessment_workflow,
    },
    {
        "name": "subdomain_enum_workflow",
        "description": """Enumerate subdomains using amass, subfinder, and bbot in parallel with deduplication.
Best for: Attack surface discovery, finding hidden subdomains.
Use when user wants to: find subdomains, enumerate domains, discover attack surface.
Args: domain (root domain like "example.com")""",
        "parameters": {
            "domain": "Root domain to enumerate (required)",
        },
        "function": subdomain_enum_workflow,
    },
]


def get_workflow_tool_descriptions() -> str:
    """Get formatted descriptions for all workflow tools"""
    lines = []
    for tool in WORKFLOW_TOOLS:
        lines.append(f"- {tool['name']}: {tool['description']}")
        for param, desc in tool.get("parameters", {}).items():
            lines.append(f"    - {param}: {desc}")
    return "\n".join(lines)
