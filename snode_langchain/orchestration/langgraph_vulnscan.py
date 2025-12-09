"""
LangGraph Vulnerability Scanning Workflow

Multi-node workflow for vulnerability assessment:
- Node 1: Port scan (discover open ports/services)
- Node 2: Vulnerability scan (NSE scripts)
- Node 3: CVE enrichment (lookup CVE details)
- Node 4: Report generation

Conditional routing based on discovered services.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from .registry import get_tools_for_capability


# ─────────────────────────────────────────────────────────────────
# State Definition
# ─────────────────────────────────────────────────────────────────

class VulnScanState(TypedDict):
    """State for vulnerability scanning workflow"""
    # Input
    target: str
    
    # Port scan results
    open_ports: List[int]
    services: Dict[int, str]  # port -> service name
    
    # Vulnerability results
    vulnerabilities: List[Dict[str, Any]]
    cves: List[str]
    
    # Severity counts
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    
    # Tracking
    phases_completed: List[str]
    errors: List[str]
    start_time: str
    end_time: Optional[str]


# ─────────────────────────────────────────────────────────────────
# Node Functions
# ─────────────────────────────────────────────────────────────────

def port_scan_node(state: VulnScanState, agent) -> VulnScanState:
    """Node 1: Discover open ports and services"""
    print("🔌 [Node 1] Port Scanning...")
    
    tools = get_tools_for_capability("port_scanning", agent)
    print(f"   Using tools: {tools}")
    
    all_ports = set()
    services = {}
    
    for tool_name in tools:
        if tool_name in agent.tool_map:
            try:
                print(f"   Running {tool_name}...")
                tool = agent.tool_map[tool_name]
                result = tool.invoke({"target": state["target"]})
                
                if isinstance(result, dict):
                    if "ports" in result:
                        all_ports.update(result["ports"])
                    if "services" in result:
                        services.update(result["services"])
                
                print(f"   ✓ {tool_name} found {len(all_ports)} ports")
            except Exception as e:
                state["errors"].append(f"{tool_name}: {str(e)}")
    
    state["open_ports"] = sorted(all_ports)
    state["services"] = services
    state["phases_completed"].append("port_scan")
    
    print(f"   ✓ Total ports: {len(state['open_ports'])}")
    return state


def vuln_scan_node(state: VulnScanState, agent) -> VulnScanState:
    """Node 2: Run vulnerability scans on discovered services"""
    print("🔍 [Node 2] Vulnerability Scanning...")
    
    if not state["open_ports"]:
        print("   ⚠ No open ports, skipping")
        return state
    
    tools = get_tools_for_capability("vulnerability_scanning", agent)
    print(f"   Using tools: {tools}")
    
    vulnerabilities = []
    cves = set()
    
    for tool_name in tools:
        if tool_name in agent.tool_map:
            try:
                print(f"   Running {tool_name}...")
                tool = agent.tool_map[tool_name]
                result = tool.invoke({"target": state["target"]})
                
                if isinstance(result, dict):
                    if "vulnerabilities" in result:
                        vulnerabilities.extend(result["vulnerabilities"])
                    if "cves" in result:
                        cves.update(result["cves"])
                
                print(f"   ✓ {tool_name} complete")
            except Exception as e:
                state["errors"].append(f"{tool_name}: {str(e)}")
    
    state["vulnerabilities"] = vulnerabilities
    state["cves"] = list(cves)
    state["phases_completed"].append("vuln_scan")
    
    print(f"   ✓ Found {len(vulnerabilities)} vulnerabilities")
    return state


def severity_analysis_node(state: VulnScanState, agent) -> VulnScanState:
    """Node 3: Analyze and categorize by severity"""
    print("📊 [Node 3] Severity Analysis...")
    
    critical = high = medium = low = 0
    
    for vuln in state["vulnerabilities"]:
        severity = vuln.get("severity", "").lower()
        if severity == "critical":
            critical += 1
        elif severity == "high":
            high += 1
        elif severity == "medium":
            medium += 1
        else:
            low += 1
    
    state["critical_count"] = critical
    state["high_count"] = high
    state["medium_count"] = medium
    state["low_count"] = low
    state["phases_completed"].append("severity_analysis")
    
    print(f"   Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}")
    return state


def report_node(state: VulnScanState, agent) -> VulnScanState:
    """Node 4: Generate final report"""
    print("📋 [Node 4] Generating Report...")
    state["end_time"] = datetime.now().isoformat()
    state["phases_completed"].append("report")
    return state


# ─────────────────────────────────────────────────────────────────
# Routing
# ─────────────────────────────────────────────────────────────────

def route_after_port_scan(state: VulnScanState) -> str:
    """Decide if we should proceed with vuln scan"""
    if state["open_ports"]:
        return "vuln_scan"
    return "report"


# ─────────────────────────────────────────────────────────────────
# Main Graph Class
# ─────────────────────────────────────────────────────────────────

class VulnScanGraph:
    """
    LangGraph workflow for vulnerability scanning.
    
    Graph structure:
    
    [Port Scan] →─┬─→ [Vuln Scan] → [Severity] → [Report] → [End]
                  │
                  └─→ [Report] (if no ports)
    """
    
    def __init__(self, agent, checkpointer=None):
        self.agent = agent
        self.checkpointer = checkpointer or MemorySaver()
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build the vulnerability scan graph"""
        
        workflow = StateGraph(VulnScanState)
        
        # Add nodes
        workflow.add_node("port_scan", lambda s: port_scan_node(s, self.agent))
        workflow.add_node("vuln_scan", lambda s: vuln_scan_node(s, self.agent))
        workflow.add_node("severity", lambda s: severity_analysis_node(s, self.agent))
        workflow.add_node("report", lambda s: report_node(s, self.agent))
        
        # Entry point
        workflow.set_entry_point("port_scan")
        
        # Conditional: if ports found → vuln scan, else → report
        workflow.add_conditional_edges(
            "port_scan",
            route_after_port_scan,
            {
                "vuln_scan": "vuln_scan",
                "report": "report",
            }
        )
        
        # Sequential flow after vuln scan
        workflow.add_edge("vuln_scan", "severity")
        workflow.add_edge("severity", "report")
        workflow.add_edge("report", END)
        
        return workflow.compile(checkpointer=self.checkpointer)
    
    def run(self, target: str) -> VulnScanState:
        """Run vulnerability scan on target"""
        
        initial_state: VulnScanState = {
            "target": target,
            "open_ports": [],
            "services": {},
            "vulnerabilities": [],
            "cves": [],
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "phases_completed": [],
            "errors": [],
            "start_time": datetime.now().isoformat(),
            "end_time": None,
        }
        
        print(f"\n🛡️ Vulnerability Scan for {target}")
        print("=" * 50)
        
        config = {"configurable": {"thread_id": f"vulnscan_{target}"}}
        final_state = self.graph.invoke(initial_state, config)
        
        print("=" * 50)
        print(f"✅ Vuln Scan Complete!")
        print(f"   Vulnerabilities: {len(final_state['vulnerabilities'])}")
        print(f"   Critical: {final_state['critical_count']}, High: {final_state['high_count']}")
        
        return final_state
    
    def format_results(self, state: VulnScanState) -> str:
        """Format results for display"""
        lines = [
            f"🛡️ **Vulnerability Scan Results**",
            f"   Target: {state['target']}",
            "",
            f"**Open Ports:** {len(state['open_ports'])}",
        ]
        
        if state['open_ports']:
            lines.append(f"   {', '.join(map(str, state['open_ports'][:20]))}")
        
        lines.extend([
            "",
            f"**Vulnerabilities:** {len(state['vulnerabilities'])}",
            f"   🔴 Critical: {state['critical_count']}",
            f"   🟠 High: {state['high_count']}",
            f"   🟡 Medium: {state['medium_count']}",
            f"   🟢 Low: {state['low_count']}",
        ])
        
        if state['cves']:
            lines.append(f"\n**CVEs Found:** {', '.join(state['cves'][:10])}")
        
        return "\n".join(lines)


# Intent detection
VULNSCAN_KEYWORDS = [
    "vulnerability", "vulnerabilities", "vuln", "vulns",
    "vuln scan", "vulnerability scan", "security scan",
    "find vulnerabilities", "check vulnerabilities",
]

def is_vulnscan_query(query: str) -> bool:
    """Check if query is about vulnerability scanning"""
    query_lower = query.lower()
    return any(keyword in query_lower for keyword in VULNSCAN_KEYWORDS)
