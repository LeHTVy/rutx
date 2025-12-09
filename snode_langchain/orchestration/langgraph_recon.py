"""
LangGraph-based Smart Reconnaissance Workflow

Features:
- Conditional branching based on scan results
- Parallel execution where possible
- State persistence via checkpointing
- Dynamic routing (e.g., if SMB port found → run SMB enum)
"""
from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional, TypedDict
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from .registry import get_tools_for_capability


# ─────────────────────────────────────────────────────────────────
# State Definition
# ─────────────────────────────────────────────────────────────────

class ReconState(TypedDict):
    """State that flows through the recon graph"""
    # Input
    target: str
    options: Dict[str, Any]
    
    # Discovered assets
    subdomains: List[str]
    hosts: List[str]
    
    # Port scan results: {host: [ports]}
    open_ports: Dict[str, List[int]]
    
    # Services found: {host: {port: service_info}}
    services: Dict[str, Dict[int, str]]
    
    # Vulnerabilities found
    vulnerabilities: List[Dict[str, Any]]
    
    # Web technologies
    technologies: List[str]
    
    # Workflow tracking
    phases_completed: List[str]
    errors: List[str]
    
    # Timing
    start_time: str
    end_time: Optional[str]


# ─────────────────────────────────────────────────────────────────
# Node Functions
# ─────────────────────────────────────────────────────────────────

def subdomain_enum_node(state: ReconState, agent) -> ReconState:
    """Phase 1: Subdomain enumeration using all available tools"""
    print("📡 [Phase 1] Subdomain Enumeration...")
    
    tools = get_tools_for_capability("subdomain_enumeration", agent)
    all_subdomains = set()
    
    for tool_name in tools:
        if tool_name in agent.tool_map:
            try:
                print(f"   Running {tool_name}...")
                tool = agent.tool_map[tool_name]
                result = tool.invoke({"domain": state["target"]})
                
                # Extract subdomains from result
                if isinstance(result, dict) and "subdomains" in result:
                    all_subdomains.update(result["subdomains"])
                elif isinstance(result, str):
                    # Parse text output for domains
                    import re
                    pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(state["target"])
                    found = re.findall(pattern, result)
                    all_subdomains.update(found)
                    
                print(f"   ✓ {tool_name}: found {len(all_subdomains)} total")
            except Exception as e:
                state["errors"].append(f"{tool_name}: {str(e)}")
    
    state["subdomains"] = sorted(all_subdomains)
    state["hosts"] = list(all_subdomains)[:20]  # Limit for port scanning
    state["phases_completed"].append("subdomain_enum")
    
    print(f"   ✓ Total unique subdomains: {len(state['subdomains'])}")
    return state


def port_scan_node(state: ReconState, agent) -> ReconState:
    """Phase 2: Port scanning using ALL available port scanning tools"""
    print("🔌 [Phase 2] Port Scanning...")
    
    if not state["hosts"]:
        print("   ⚠ No hosts to scan")
        return state
    
    open_ports = {}
    
    # Use registry to get ALL port scanning tools
    port_tools = get_tools_for_capability("port_scanning", agent)
    print(f"   Using tools: {port_tools}")
    
    for host in state["hosts"][:10]:  # Limit hosts
        host_ports = set()
        for tool_name in port_tools:
            if tool_name in agent.tool_map:
                try:
                    print(f"   Scanning {host} with {tool_name}...")
                    tool = agent.tool_map[tool_name]
                    result = tool.invoke({"target": host})
                    if isinstance(result, dict) and "ports" in result:
                        host_ports.update(result["ports"])
                except Exception as e:
                    state["errors"].append(f"Port scan {host}: {str(e)}")
        if host_ports:
            open_ports[host] = list(host_ports)
    
    state["open_ports"] = open_ports
    state["phases_completed"].append("port_scan")
    
    total_ports = sum(len(ports) for ports in open_ports.values())
    print(f"   ✓ Found {total_ports} open ports across {len(open_ports)} hosts")
    return state


def web_scan_node(state: ReconState, agent) -> ReconState:
    """Phase 3a: Web fingerprinting using ALL available web tools"""
    print("🌐 [Phase 3a] Web Fingerprinting...")
    
    # Find hosts with web ports
    web_ports = {80, 443, 8080, 8443}
    web_hosts = [
        host for host, ports in state["open_ports"].items()
        if any(p in web_ports for p in ports)
    ]
    
    if not web_hosts:
        print("   ⚠ No web ports found, skipping")
        return state
    
    technologies = set()
    
    # Use registry to get ALL web fingerprinting tools  
    web_tools = get_tools_for_capability("web_fingerprinting", agent)
    print(f"   Using tools: {web_tools}")
    
    for host in web_hosts[:5]:
        for tool_name in web_tools:
            if tool_name in agent.tool_map:
                try:
                    print(f"   Scanning {host} with {tool_name}...")
                    tool = agent.tool_map[tool_name]
                    result = tool.invoke({"target": host})
                    if isinstance(result, dict) and "technologies" in result:
                        technologies.update(result["technologies"])
                except Exception as e:
                    state["errors"].append(f"Web scan {host}: {str(e)}")
    
    state["technologies"] = list(technologies)
    state["phases_completed"].append("web_scan")
    print(f"   ✓ Found {len(state['technologies'])} technologies")
    return state


def smb_scan_node(state: ReconState, agent) -> ReconState:
    """Phase 3b: SMB enumeration (if port 445 found)"""
    print("📁 [Phase 3b] SMB Enumeration...")
    
    # Find hosts with SMB port
    smb_hosts = [
        host for host, ports in state["open_ports"].items()
        if 445 in ports or 139 in ports
    ]
    
    if not smb_hosts:
        print("   ⚠ No SMB ports found, skipping")
        return state
    
    # Would run SMB enum tools here
    print(f"   Found {len(smb_hosts)} hosts with SMB: {smb_hosts[:5]}")
    state["phases_completed"].append("smb_scan")
    return state


def vuln_scan_node(state: ReconState, agent) -> ReconState:
    """Phase 4: Vulnerability scanning using ALL available vuln tools"""
    print("🔍 [Phase 4] Vulnerability Scanning...")
    
    vulnerabilities = []
    
    # Use registry to get ALL vulnerability scanning tools
    vuln_tools = get_tools_for_capability("vulnerability_scanning", agent)
    print(f"   Using tools: {vuln_tools}")
    
    # Scan top hosts
    for host in list(state["open_ports"].keys())[:5]:
        for tool_name in vuln_tools:
            if tool_name in agent.tool_map:
                try:
                    print(f"   Scanning {host} with {tool_name}...")
                    tool = agent.tool_map[tool_name]
                    result = tool.invoke({"target": host})
                    if isinstance(result, dict) and "vulnerabilities" in result:
                        vulnerabilities.extend(result["vulnerabilities"])
                except Exception as e:
                    state["errors"].append(f"Vuln scan {host}: {str(e)}")
    
    state["vulnerabilities"] = vulnerabilities
    state["phases_completed"].append("vuln_scan")
    print(f"   ✓ Found {len(vulnerabilities)} potential vulnerabilities")
    return state


def report_node(state: ReconState, agent) -> ReconState:
    """Final node: Generate report"""
    print("📋 [Final] Generating Report...")
    state["end_time"] = datetime.now().isoformat()
    state["phases_completed"].append("report")
    return state


# ─────────────────────────────────────────────────────────────────
# Routing Functions
# ─────────────────────────────────────────────────────────────────

def route_after_port_scan(state: ReconState) -> List[str]:
    """
    Decide which scans to run based on discovered ports.
    Returns list of next nodes to run (can be multiple for parallel).
    """
    next_nodes = []
    
    all_ports = []
    for ports in state["open_ports"].values():
        all_ports.extend(ports)
    all_ports = set(all_ports)
    
    # Check for web ports
    web_ports = {80, 443, 8080, 8443, 8000, 3000}
    if any(p in all_ports for p in web_ports):
        next_nodes.append("web_scan")
    
    # Check for SMB
    if 445 in all_ports or 139 in all_ports:
        next_nodes.append("smb_scan")
    
    # Always do vuln scan if we have ports
    if all_ports:
        next_nodes.append("vuln_scan")
    
    # If nothing to do, go to report
    if not next_nodes:
        return ["report"]
    
    return next_nodes


def should_continue_to_vuln(state: ReconState) -> str:
    """After web/smb scans, go to report"""
    return "report"


# ─────────────────────────────────────────────────────────────────
# Graph Builder
# ─────────────────────────────────────────────────────────────────

class SmartReconGraph:
    """
    LangGraph-based smart reconnaissance workflow.
    Dynamically routes based on discovered services.
    """
    
    def __init__(self, agent, checkpointer=None):
        self.agent = agent
        self.checkpointer = checkpointer or MemorySaver()
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        
        # Create graph with state type
        workflow = StateGraph(ReconState)
        
        # Add nodes (wrap to pass agent)
        workflow.add_node("subdomain_enum", 
                          lambda s: subdomain_enum_node(s, self.agent))
        workflow.add_node("port_scan", 
                          lambda s: port_scan_node(s, self.agent))
        workflow.add_node("web_scan", 
                          lambda s: web_scan_node(s, self.agent))
        workflow.add_node("smb_scan", 
                          lambda s: smb_scan_node(s, self.agent))
        workflow.add_node("vuln_scan", 
                          lambda s: vuln_scan_node(s, self.agent))
        workflow.add_node("report", 
                          lambda s: report_node(s, self.agent))
        
        # Set entry point
        workflow.set_entry_point("subdomain_enum")
        
        # Add edges
        workflow.add_edge("subdomain_enum", "port_scan")
        
        # Conditional routing after port scan
        workflow.add_conditional_edges(
            "port_scan",
            route_after_port_scan,
            {
                "web_scan": "web_scan",
                "smb_scan": "smb_scan", 
                "vuln_scan": "vuln_scan",
                "report": "report",
            }
        )
        
        # After specialized scans, go to report
        workflow.add_edge("web_scan", "report")
        workflow.add_edge("smb_scan", "report")
        workflow.add_edge("vuln_scan", "report")
        
        # End at report
        workflow.add_edge("report", END)
        
        return workflow.compile(checkpointer=self.checkpointer)
    
    def run(self, target: str, **options) -> ReconState:
        """Execute the smart recon workflow"""
        
        initial_state: ReconState = {
            "target": target,
            "options": options,
            "subdomains": [],
            "hosts": [],
            "open_ports": {},
            "services": {},
            "vulnerabilities": [],
            "technologies": [],
            "phases_completed": [],
            "errors": [],
            "start_time": datetime.now().isoformat(),
            "end_time": None,
        }
        
        print(f"\n🚀 Starting Smart Recon on {target}")
        print("=" * 50)
        
        # Run the graph
        config = {"configurable": {"thread_id": f"recon_{target}"}}
        final_state = self.graph.invoke(initial_state, config)
        
        print("=" * 50)
        print(f"✅ Smart Recon Complete!")
        print(f"   Phases: {', '.join(final_state['phases_completed'])}")
        print(f"   Subdomains: {len(final_state['subdomains'])}")
        print(f"   Open Ports: {sum(len(p) for p in final_state['open_ports'].values())}")
        print(f"   Vulnerabilities: {len(final_state['vulnerabilities'])}")
        
        return final_state
    
    def get_graph_diagram(self) -> str:
        """Get Mermaid diagram of the graph"""
        return """
```mermaid
graph TD
    A[Start] --> B[Subdomain Enum]
    B --> C[Port Scan]
    C -->|Web ports| D[Web Scan]
    C -->|SMB ports| E[SMB Scan]
    C -->|Any ports| F[Vuln Scan]
    C -->|No ports| G[Report]
    D --> G
    E --> G
    F --> G
    G --> H[End]
```
"""
