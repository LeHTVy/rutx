"""
LangGraph Vulnerability Assessment Workflow

A comprehensive vulnerability scanning workflow:
- Node 1: httpx_probe (check if target is alive, detect tech)
- Node 2: nuclei_scan (vulnerability scanning in parallel)
- Node 3: nikto_scan (web server vulnerabilities in parallel)
- Node 4: dalfox_xss (XSS scanning - conditional)
- Node 5: Merge & LLM Analysis

Graph Structure:
                    ┌─→ [nuclei_scan] ──┐
                    │                   │
    [START] → [httpx] ───────────────────┼─→ [Merge] → [Analyze] → [END]
                    │                   │
                    └─→ [nikto_scan] ───┘
                              ↓
                    [dalfox_xss] (if params found)
"""
from datetime import datetime
from typing import Any, Dict, List, Optional, Annotated
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
import operator
import re


# ─────────────────────────────────────────────────────────────────
# State Definition with Reducers for Parallel Merging
# ─────────────────────────────────────────────────────────────────

def merge_lists(left: List[Any], right: List[Any]) -> List[Any]:
    """Reducer: Merge two lists"""
    if not left:
        return right or []
    if not right:
        return left
    return left + right


def merge_dicts(left: Dict, right: Dict) -> Dict:
    """Reducer: Merge two dicts"""
    if not left:
        return right or {}
    if not right:
        return left
    return {**left, **right}


class VulnAssessmentState(TypedDict):
    """State for vulnerability assessment workflow"""
    # Input
    target: str
    
    # httpx results
    is_alive: bool
    technologies: Annotated[List[str], merge_lists]
    status_code: int
    
    # Vulnerability results from each tool
    nuclei_vulns: Annotated[List[Dict], merge_lists]
    nikto_vulns: Annotated[List[Dict], merge_lists]
    xss_vulns: Annotated[List[Dict], merge_lists]
    
    # CVE RAG results (potential CVEs based on technologies)
    cve_rag_results: Annotated[List[Dict], merge_lists]
    
    # All merged vulnerabilities
    all_vulnerabilities: Annotated[List[Dict], merge_lists]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    
    # LLM Analysis
    analysis: str
    recommendations: Annotated[List[str], merge_lists]
    
    # Tracking
    tools_completed: Annotated[List[str], operator.add]
    errors: Annotated[List[str], operator.add]
    start_time: str
    end_time: Optional[str]


# ─────────────────────────────────────────────────────────────────
# Node Functions
# ─────────────────────────────────────────────────────────────────

def httpx_node(state: VulnAssessmentState, agent) -> dict:
    """Node 1: Check if target is alive and detect technologies"""
    print("🔍 [httpx] Probing target...")
    
    is_alive = False
    technologies = []
    status_code = 0
    tools_completed = []
    errors = []
    
    try:
        from snode_langchain.tools.advanced_tools import httpx_probe
        result = httpx_probe(state["target"])
        
        if result.get("success") and result.get("hosts_found", 0) > 0:
            is_alive = True
            # Get first result
            if result.get("results"):
                first = result["results"][0]
                status_code = first.get("status_code", 0)
                technologies = first.get("technologies", [])
            
            print(f"   ✓ Target alive | Status: {status_code} | Tech: {', '.join(technologies[:5])}")
            tools_completed.append("httpx")
        else:
            print(f"   ✗ Target not responding")
            errors.append("httpx: Target not responding")
            
    except Exception as e:
        errors.append(f"httpx: {str(e)}")
        print(f"   ✗ httpx error: {e}")
    
    return {
        "is_alive": is_alive,
        "technologies": technologies,
        "status_code": status_code,
        "tools_completed": tools_completed,
        "errors": errors,
    }


def nuclei_node(state: VulnAssessmentState, agent) -> dict:
    """Node 2: Nuclei vulnerability scanning (runs in parallel)"""
    print("🔍 [Parallel] Running Nuclei...")
    
    vulns = []
    tools_completed = []
    errors = []
    
    # Skip if target not alive
    if not state.get("is_alive", True):
        print("   ⚠ Skipping nuclei - target not alive")
        return {"nuclei_vulns": [], "tools_completed": [], "errors": []}
    
    try:
        from snode_langchain.tools.advanced_tools import nuclei_scan
        result = nuclei_scan(state["target"], severity="critical,high,medium")
        
        if result.get("success"):
            vulns = result.get("vulnerabilities", [])
            print(f"   ✓ Nuclei found {len(vulns)} vulnerabilities")
            tools_completed.append("nuclei")
        else:
            errors.append(f"nuclei: {result.get('error', 'Unknown error')}")
            print(f"   ✗ Nuclei error: {result.get('error')}")
            
    except Exception as e:
        errors.append(f"nuclei: {str(e)}")
        print(f"   ✗ Nuclei error: {e}")
    
    return {
        "nuclei_vulns": vulns,
        "tools_completed": tools_completed,
        "errors": errors,
    }


def nikto_node(state: VulnAssessmentState, agent) -> dict:
    """Node 3: Nikto web server scanning (runs in parallel)"""
    print("🔍 [Parallel] Running Nikto...")
    
    vulns = []
    tools_completed = []
    errors = []
    
    # Skip if target not alive
    if not state.get("is_alive", True):
        print("   ⚠ Skipping nikto - target not alive")
        return {"nikto_vulns": [], "tools_completed": [], "errors": []}
    
    try:
        from snode_langchain.tools.advanced_tools import nikto_scan
        result = nikto_scan(state["target"], timeout=300)
        
        if result.get("success"):
            vulns = result.get("vulnerabilities", [])
            print(f"   ✓ Nikto found {len(vulns)} findings")
            tools_completed.append("nikto")
        else:
            errors.append(f"nikto: {result.get('error', 'Unknown error')}")
            print(f"   ✗ Nikto error: {result.get('error')}")
            
    except Exception as e:
        errors.append(f"nikto: {str(e)}")
        print(f"   ✗ Nikto error: {e}")
    
    return {
        "nikto_vulns": vulns,
        "tools_completed": tools_completed,
        "errors": errors,
    }


def dalfox_node(state: VulnAssessmentState, agent) -> dict:
    """Node 4: XSS scanning with dalfox (conditional - if has params)"""
    print("🔍 [Dalfox] Checking for XSS...")
    
    vulns = []
    tools_completed = []
    errors = []
    
    # Only run if target has parameters
    target = state["target"]
    if "?" not in target and "=" not in target:
        # Try adding common params
        test_url = f"{target}?id=1&page=test"
    else:
        test_url = target
    
    try:
        from snode_langchain.tools.advanced_tools import dalfox_xss
        result = dalfox_xss(test_url, timeout=180)
        
        if result.get("success"):
            vulns = result.get("vulnerabilities", [])
            print(f"   ✓ Dalfox found {len(vulns)} XSS issues")
            tools_completed.append("dalfox")
        else:
            print(f"   ⚠ Dalfox: {result.get('error', 'No XSS found')}")
            
    except Exception as e:
        errors.append(f"dalfox: {str(e)}")
        print(f"   ✗ Dalfox error: {e}")
    
    return {
        "xss_vulns": vulns,
        "tools_completed": tools_completed,
        "errors": errors,
    }


def cve_enrichment_node(state: VulnAssessmentState, agent) -> dict:
    """CVE RAG Node: Search for potential CVEs based on detected technologies"""
    print("📚 [CVE RAG] Searching for potential vulnerabilities...")
    
    cve_results = []
    tools_completed = []
    errors = []
    
    technologies = state.get("technologies", [])
    
    if not technologies:
        print("   ⚠ No technologies detected, skipping CVE RAG")
        return {"cve_rag_results": [], "tools_completed": [], "errors": []}
    
    try:
        from snode_langchain.tools.cve_rag import search_cves, lookup_cve, CHROMADB_AVAILABLE
        
        if not CHROMADB_AVAILABLE:
            print("   ⚠ ChromaDB not available")
            return {"cve_rag_results": [], "tools_completed": [], "errors": ["ChromaDB not installed"]}
        
        # Search for CVEs based on each detected technology
        searched_techs = set()
        for tech in technologies[:5]:  # Limit to first 5 technologies
            # Clean up technology name
            tech_clean = tech.split("/")[0].split(":")[0].strip()
            
            if tech_clean.lower() in searched_techs or len(tech_clean) < 3:
                continue
            searched_techs.add(tech_clean.lower())
            
            print(f"   → Searching CVEs for: {tech_clean}")
            result = search_cves(query=f"{tech_clean} vulnerability", n_results=5, severity="critical,high")
            
            if result.get("success") and result.get("cves"):
                for cve in result["cves"]:
                    cve["matched_technology"] = tech_clean
                    cve["source"] = "cve_rag"
                    cve_results.append(cve)
        
        # Also search based on target domain (for specific product CVEs)
        target = state.get("target", "")
        if "." in target:
            domain_parts = target.replace("https://", "").replace("http://", "").split("/")[0].split(".")
            if len(domain_parts) >= 2:
                main_name = domain_parts[-2]  # e.g., "apache" from "apache.org"
                if len(main_name) > 3 and main_name not in searched_techs:
                    print(f"   → Searching CVEs for domain: {main_name}")
                    result = search_cves(query=f"{main_name} security vulnerability", n_results=5, severity="critical,high")
                    if result.get("success") and result.get("cves"):
                        for cve in result["cves"]:
                            cve["matched_technology"] = main_name
                            cve["source"] = "cve_rag"
                            cve_results.append(cve)
        
        if cve_results:
            print(f"   ✓ Found {len(cve_results)} potential CVEs from database")
            tools_completed.append("cve_rag")
        else:
            print("   ⚠ No matching CVEs found in database")
            
    except Exception as e:
        errors.append(f"cve_rag: {str(e)}")
        print(f"   ✗ CVE RAG error: {e}")
    
    return {
        "cve_rag_results": cve_results,
        "tools_completed": tools_completed,
        "errors": errors,
    }


def merge_node(state: VulnAssessmentState, agent) -> dict:
    """Merge node: Combine all vulnerability results"""
    print("📊 [Merge] Combining vulnerability results...")
    
    all_vulns = []
    real_cves = []  # Track real CVEs from nuclei
    
    # Merge nuclei vulns - extract real CVE IDs
    for vuln in state.get("nuclei_vulns", []):
        template_id = vuln.get("template", "")
        name = vuln.get("name", template_id)
        
        # Extract CVE if present in template ID or name
        import re
        cve_match = re.search(r'CVE-\d{4}-\d+', f"{template_id} {name}", re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None
        
        if cve_id:
            real_cves.append(cve_id)
        
        all_vulns.append({
            "source": "nuclei",
            "name": name,
            "template": template_id,
            "cve": cve_id,  # Actual CVE from nuclei template
            "severity": vuln.get("severity", "unknown"),
            "matched": vuln.get("matched", ""),
            "type": vuln.get("type", ""),
            "is_real_finding": True,
        })
    
    # Merge nikto vulns
    for vuln in state.get("nikto_vulns", []):
        msg = vuln.get("msg", vuln.get("id", "Unknown"))
        
        # Nikto sometimes includes CVEs in messages
        import re
        cve_match = re.search(r'CVE-\d{4}-\d+', msg, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None
        
        if cve_id:
            real_cves.append(cve_id)
        
        all_vulns.append({
            "source": "nikto",
            "name": msg,
            "cve": cve_id,
            "severity": "medium",  # Nikto doesn't have severity
            "matched": vuln.get("url", ""),
            "type": "web_server",
            "is_real_finding": True,
        })
    
    # Merge XSS vulns
    for vuln in state.get("xss_vulns", []):
        all_vulns.append({
            "source": "dalfox",
            "name": "XSS Vulnerability",
            "cve": None,
            "severity": "high",
            "matched": str(vuln),
            "type": "xss",
            "is_real_finding": True,
        })
    
    # Merge CVE RAG potential vulnerabilities (from database search)
    cve_rag_results = state.get("cve_rag_results", [])
    potential_cves = []
    for cve in cve_rag_results:
        cve_id = cve.get("cve_id", "")
        # Skip if already in real findings
        if cve_id and any(v.get("cve") == cve_id for v in all_vulns):
            continue
        potential_cves.append({
            "source": "cve_rag",
            "name": f"{cve.get('title', cve_id)[:60]}",
            "cve": cve_id,
            "severity": cve.get("severity", "unknown"),
            "matched": f"Matched technology: {cve.get('matched_technology', '')}",
            "type": "potential",
            "is_real_finding": False,  # Not confirmed, just potential based on tech detection
            "relevance_score": cve.get("relevance_score", 0),
        })
    
    if potential_cves:
        print(f"   📚 Added {len(potential_cves)} potential CVEs from database")
    
    # Count by severity (only real findings)
    critical = len([v for v in all_vulns if v.get("severity", "").lower() == "critical"])
    high = len([v for v in all_vulns if v.get("severity", "").lower() == "high"])
    medium = len([v for v in all_vulns if v.get("severity", "").lower() == "medium"])
    low = len([v for v in all_vulns if v.get("severity", "").lower() in ["low", "info"]])
    
    # Add potential CVEs to all_vulns for display
    all_vulns.extend(potential_cves)
    
    # Deduplicate CVEs
    real_cves = list(set(real_cves))
    
    print(f"   ✓ Total: {len(all_vulns)} vulns (Critical: {critical}, High: {high}, Medium: {medium}, Low: {low})")
    if real_cves:
        print(f"   ✓ Real CVEs detected: {', '.join(real_cves[:5])}{'...' if len(real_cves) > 5 else ''}")
    
    return {
        "all_vulnerabilities": all_vulns,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
    }


def analyze_node(state: VulnAssessmentState, agent) -> dict:
    """Analysis node: Use LLM to analyze and prioritize vulnerabilities"""
    print("🧠 [Analyze] LLM analyzing vulnerabilities...")
    
    all_vulns = state.get("all_vulnerabilities", [])
    technologies = state.get("technologies", [])
    
    if not all_vulns:
        print("   ⚠ No vulnerabilities to analyze")
        return {
            "analysis": "No vulnerabilities found during scanning.",
            "recommendations": ["Consider manual testing", "Check for authentication bypass"],
            "end_time": datetime.now().isoformat(),
        }
    
    # Extract real CVEs
    real_cves = [v.get('cve') for v in all_vulns if v.get('cve')]
    real_cves = list(set(real_cves))
    
    # Build vulnerability summary for LLM - clearly label as REAL findings
    vuln_summary = "\n".join([
        f"  - [{v.get('severity', 'unknown').upper()}] {v.get('name')} "
        f"{'('+v.get('cve')+')' if v.get('cve') else ''} "
        f"[Source: {v.get('source')}]"
        for v in all_vulns[:30]
    ])
    
    cve_section = ""
    if real_cves:
        cve_section = f"\n**REAL CVEs Detected by Tools:** {', '.join(real_cves)}\n"
    
    tech_str = ", ".join(technologies) if technologies else "Unknown"
    
    analysis_prompt = f"""Analyze this REAL vulnerability scan data for {state['target']}:

**Target Technologies (detected by httpx):** {tech_str}
{cve_section}
**ACTUAL Vulnerabilities Found by Tools ({len(all_vulns)} total):**
{vuln_summary}

**Summary:**
- Critical: {state.get('critical_count', 0)}
- High: {state.get('high_count', 0)}
- Medium: {state.get('medium_count', 0)}
- Low: {state.get('low_count', 0)}

⚠️ CRITICAL INSTRUCTION:
- ONLY discuss the vulnerabilities listed above
- DO NOT invent or guess CVE numbers
- DO NOT assume vulnerabilities that were not detected
- If you mention CVEs, they MUST be from the list above
- Clearly state "detected by nuclei/nikto/dalfox" for each finding

**Provide:**
1. **Executive Summary** - 2-3 sentences on what the scans ACTUALLY found
2. **Top Priority Issues** - Rank the DETECTED findings by exploitation potential
3. **Exploitation Guidance** - How to exploit the DETECTED vulnerabilities
4. **Remediation** - Fixes for the DETECTED vulnerabilities only
5. **Next Steps** - Additional manual testing to find more issues

Be precise and only reference what the tools actually detected."""

    analysis_text = ""
    recommendations = []
    
    try:
        if hasattr(agent, 'llm') and agent.llm:
            response = agent.llm.invoke(analysis_prompt)
            analysis_text = response.content if hasattr(response, 'content') else str(response)
            
            # Extract recommendations based on actual findings
            recommendations = []
            if state.get('critical_count', 0) > 0:
                recommendations.append(f"🔴 URGENT: Investigate {state.get('critical_count')} critical vulnerabilities immediately")
            if state.get('high_count', 0) > 0:
                recommendations.append(f"🟠 Review {state.get('high_count')} high-severity findings")
            if real_cves:
                recommendations.append(f"📋 Research CVEs: {', '.join(real_cves[:5])}")
            recommendations.append("🔍 Perform manual verification of automated findings")
            recommendations.append("🔐 Check for authentication/authorization issues")
            
            print(f"   ✓ Analysis complete")
        else:
            analysis_text = "LLM not available for analysis."
            
    except Exception as e:
        analysis_text = f"Analysis failed: {str(e)}"
        print(f"   ✗ Analysis error: {e}")
    
    return {
        "analysis": analysis_text,
        "recommendations": recommendations,
        "end_time": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────
# Workflow Graph Class
# ─────────────────────────────────────────────────────────────────

class VulnAssessmentGraph:
    """LangGraph workflow for vulnerability assessment"""
    
    def __init__(self, agent):
        self.agent = agent
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        
        # Create graph with state schema
        graph = StateGraph(VulnAssessmentState)
        
        # Add nodes with agent context
        graph.add_node("httpx", lambda state: httpx_node(state, self.agent))
        graph.add_node("nuclei", lambda state: nuclei_node(state, self.agent))
        graph.add_node("nikto", lambda state: nikto_node(state, self.agent))
        graph.add_node("dalfox", lambda state: dalfox_node(state, self.agent))
        graph.add_node("cve_enrich", lambda state: cve_enrichment_node(state, self.agent))
        graph.add_node("merge", lambda state: merge_node(state, self.agent))
        graph.add_node("analyze", lambda state: analyze_node(state, self.agent))
        
        # Define edges:
        # START → httpx (check if alive first)
        graph.add_edge(START, "httpx")
        
        # httpx → parallel (nuclei, nikto, cve_enrich)
        graph.add_edge("httpx", "nuclei")
        graph.add_edge("httpx", "nikto")
        graph.add_edge("httpx", "cve_enrich")  # CVE RAG runs in parallel too
        
        # Parallel tools → merge
        graph.add_edge("nuclei", "merge")
        graph.add_edge("nikto", "merge")
        graph.add_edge("cve_enrich", "merge")
        
        # Also run dalfox after httpx
        graph.add_edge("httpx", "dalfox")
        graph.add_edge("dalfox", "merge")
        
        # merge → analyze → END
        graph.add_edge("merge", "analyze")
        graph.add_edge("analyze", END)
        
        return graph.compile()
    
    def run(self, target: str) -> VulnAssessmentState:
        """Execute the vulnerability assessment workflow"""
        print(f"\n{'='*60}")
        print(f"🔴 VULNERABILITY ASSESSMENT WORKFLOW")
        print(f"   Target: {target}")
        print(f"{'='*60}\n")
        
        initial_state = {
            "target": target,
            "is_alive": True,
            "technologies": [],
            "status_code": 0,
            "nuclei_vulns": [],
            "nikto_vulns": [],
            "xss_vulns": [],
            "cve_rag_results": [],  # CVE RAG potential vulnerabilities
            "all_vulnerabilities": [],
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "analysis": "",
            "recommendations": [],
            "tools_completed": [],
            "errors": [],
            "start_time": datetime.now().isoformat(),
            "end_time": None,
        }
        
        result = self.graph.invoke(initial_state)
        return result
    
    def format_results(self, state: VulnAssessmentState) -> str:
        """Format the results for display"""
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append("🔴 VULNERABILITY ASSESSMENT RESULTS")
        lines.append(f"{'='*60}")
        lines.append(f"Target: {state['target']}")
        lines.append(f"Status: {'🟢 Alive' if state.get('is_alive') else '🔴 Not responding'}")
        lines.append(f"Technologies: {', '.join(state.get('technologies', [])[:10]) or 'Unknown'}")
        lines.append("")
        
        # Vulnerability summary
        lines.append("📊 VULNERABILITY SUMMARY")
        lines.append(f"   🔴 Critical: {state.get('critical_count', 0)}")
        lines.append(f"   🟠 High: {state.get('high_count', 0)}")
        lines.append(f"   🟡 Medium: {state.get('medium_count', 0)}")
        lines.append(f"   🟢 Low/Info: {state.get('low_count', 0)}")
        lines.append(f"   Total: {len(state.get('all_vulnerabilities', []))}")
        lines.append("")
        
        # Top vulnerabilities
        vulns = state.get("all_vulnerabilities", [])
        real_cves = [v.get('cve') for v in vulns if v.get('cve')]
        real_cves = list(set(real_cves))
        
        # Show real CVEs first
        if real_cves:
            lines.append("🔐 REAL CVEs DETECTED (from tools):")
            for cve in real_cves[:10]:
                lines.append(f"   • {cve}")
            lines.append("")
        
        if vulns:
            lines.append("🎯 TOP VULNERABILITIES (Real Tool Findings)")
            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x.get("severity", "").lower(), 5))
            for vuln in sorted_vulns[:15]:
                sev = vuln.get("severity", "unknown").upper()
                name = vuln.get("name", "Unknown")[:50]
                source = vuln.get("source", "")
                cve = f" ({vuln.get('cve')})" if vuln.get('cve') else ""
                lines.append(f"   [{sev}] {name}{cve} [detected by {source}]")
            lines.append("")
        
        # LLM Analysis - clearly labeled
        if state.get("analysis"):
            lines.append("🧠 LLM ANALYSIS (AI interpretation of tool results)")
            lines.append("⚠️  Note: CVEs below are ONLY from tool detections, not AI guesses")
            lines.append("-" * 40)
            lines.append(state["analysis"])
            lines.append("")
        
        # Tools completed
        lines.append(f"✅ Tools: {', '.join(state.get('tools_completed', []))}")
        
        if state.get("errors"):
            lines.append(f"⚠️ Errors: {', '.join(state.get('errors', []))}")
        
        lines.append(f"{'='*60}\n")
        
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Query Detection
# ─────────────────────────────────────────────────────────────────

def is_vuln_assessment_query(query: str) -> bool:
    """Detect if query is a vulnerability assessment request"""
    query_lower = query.lower()
    
    vuln_patterns = [
        "scan vulnerabilities",
        "vulnerability scan",
        "vuln scan",
        "find vulnerabilities",
        "security scan",
        "pentest",
        "penetration test",
        "find vulns",
        "check vulnerabilities",
        "vulnerability assessment",
        "vuln assessment",
        "security assessment",
    ]
    
    return any(pattern in query_lower for pattern in vuln_patterns)


def extract_target_from_query(query: str) -> str:
    """Extract target URL/domain from query"""
    import re
    
    # Try to find URL
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, query)
    if urls:
        return urls[0]
    
    # Try to find domain
    domain_pattern = r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, query)
    if domains:
        # Return with https:// prefix
        return f"https://{domains[0]}"
    
    return None
