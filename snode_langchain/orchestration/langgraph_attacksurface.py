"""
LangGraph Attack Surface Mapping Workflow

Comprehensive attack surface analysis:
- Node 1: Asset discovery (subdomains, IPs)
- Node 2: Port/service enumeration
- Node 3: Web technology fingerprinting
- Node 4: Misconfiguration checks
- Node 5: Attack surface report

Parallel execution where possible, conditional routing based on findings.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from .registry import get_tools_for_capability


# ─────────────────────────────────────────────────────────────────
# State Definition
# ─────────────────────────────────────────────────────────────────

class AttackSurfaceState(TypedDict):
    """State for attack surface mapping workflow"""
    # Input
    target: str
    
    # Discovered assets
    subdomains: List[str]
    ip_addresses: List[str]
    
    # Infrastructure
    open_ports: Dict[str, List[int]]  # host -> ports
    services: Dict[str, Dict[int, str]]  # host -> {port: service}
    
    # Web layer
    web_hosts: List[str]
    technologies: List[str]
    endpoints: List[str]
    
    # Attack surface metrics
    total_assets: int
    exposed_services: int
    attack_vectors: List[str]
    
    # Tracking
    phases_completed: List[str]
    errors: List[str]
    start_time: str
    end_time: Optional[str]


# ─────────────────────────────────────────────────────────────────
# Node Functions
# ─────────────────────────────────────────────────────────────────

def asset_discovery_node(state: AttackSurfaceState, agent) -> AttackSurfaceState:
    """Node 1: Discover all assets (subdomains, IPs)"""
    print("🔍 [Node 1] Asset Discovery...")
    
    tools = get_tools_for_capability("subdomain_enumeration", agent)
    print(f"   Using tools: {tools}")
    
    all_subdomains = set()
    
    for tool_name in tools:
        if tool_name in agent.tool_map:
            try:
                print(f"   Running {tool_name}...")
                tool = agent.tool_map[tool_name]
                result = tool.invoke({"domain": state["target"]})
                
                if isinstance(result, dict) and "subdomains" in result:
                    all_subdomains.update(result["subdomains"])
                elif isinstance(result, str):
                    import re
                    pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(state["target"])
                    all_subdomains.update(re.findall(pattern, result))
                
            except Exception as e:
                state["errors"].append(f"{tool_name}: {str(e)}")
    
    state["subdomains"] = sorted(all_subdomains)
    state["total_assets"] = len(all_subdomains)
    state["phases_completed"].append("asset_discovery")
    
    print(f"   ✓ Found {len(state['subdomains'])} assets")
    return state


def port_enum_node(state: AttackSurfaceState, agent) -> AttackSurfaceState:
    """Node 2: Enumerate ports on discovered assets"""
    print("🔌 [Node 2] Port Enumeration...")
    
    if not state["subdomains"]:
        print("   ⚠ No assets to scan")
        return state
    
    tools = get_tools_for_capability("port_scanning", agent)
    print(f"   Using tools: {tools}")
    
    open_ports = {}
    services = {}
    
    # Scan top hosts
    for host in state["subdomains"][:10]:
        host_ports = set()
        host_services = {}
        
        for tool_name in tools:
            if tool_name in agent.tool_map:
                try:
                    print(f"   Scanning {host}...")
                    tool = agent.tool_map[tool_name]
                    result = tool.invoke({"target": host})
                    
                    if isinstance(result, dict):
                        if "ports" in result:
                            host_ports.update(result["ports"])
                        if "services" in result:
                            host_services.update(result["services"])
                except Exception as e:
                    state["errors"].append(f"{tool_name} on {host}: {str(e)}")
        
        if host_ports:
            open_ports[host] = list(host_ports)
            services[host] = host_services
    
    state["open_ports"] = open_ports
    state["services"] = services
    state["exposed_services"] = sum(len(p) for p in open_ports.values())
    state["phases_completed"].append("port_enum")
    
    print(f"   ✓ Found {state['exposed_services']} exposed services")
    return state


def web_fingerprint_node(state: AttackSurfaceState, agent) -> AttackSurfaceState:
    """Node 3: Fingerprint web technologies"""
    print("🌐 [Node 3] Web Fingerprinting...")
    
    # Find hosts with web ports
    web_ports = {80, 443, 8080, 8443}
    web_hosts = [
        host for host, ports in state["open_ports"].items()
        if any(p in web_ports for p in ports)
    ]
    
    if not web_hosts:
        print("   ⚠ No web hosts found")
        return state
    
    state["web_hosts"] = web_hosts
    
    tools = get_tools_for_capability("web_fingerprinting", agent)
    print(f"   Using tools: {tools}")
    
    technologies = set()
    
    for host in web_hosts[:5]:
        for tool_name in tools:
            if tool_name in agent.tool_map:
                try:
                    tool = agent.tool_map[tool_name]
                    result = tool.invoke({"target": host})
                    if isinstance(result, dict) and "technologies" in result:
                        technologies.update(result["technologies"])
                except Exception as e:
                    state["errors"].append(f"Web fingerprint {host}: {str(e)}")
    
    state["technologies"] = list(technologies)
    state["phases_completed"].append("web_fingerprint")
    
    print(f"   ✓ Found {len(technologies)} technologies")
    return state


def attack_vector_node(state: AttackSurfaceState, agent) -> AttackSurfaceState:
    """Node 4: Identify potential attack vectors"""
    print("⚔️ [Node 4] Attack Vector Analysis...")
    
    vectors = []
    
    # Analyze based on ports
    all_ports = set()
    for ports in state["open_ports"].values():
        all_ports.update(ports)
    
    if 22 in all_ports:
        vectors.append("SSH brute force potential")
    if 21 in all_ports:
        vectors.append("FTP anonymous access check")
    if 445 in all_ports or 139 in all_ports:
        vectors.append("SMB enumeration (EternalBlue, shares)")
    if 3389 in all_ports:
        vectors.append("RDP brute force / BlueKeep")
    if 80 in all_ports or 443 in all_ports:
        vectors.append("Web application testing (SQLi, XSS, etc.)")
    if 3306 in all_ports:
        vectors.append("MySQL exposure")
    if 5432 in all_ports:
        vectors.append("PostgreSQL exposure")
    if 27017 in all_ports:
        vectors.append("MongoDB exposure (auth bypass)")
    if 6379 in all_ports:
        vectors.append("Redis exposure (unauthenticated)")
    
    # Analyze based on technologies
    for tech in state["technologies"]:
        tech_lower = tech.lower()
        if "wordpress" in tech_lower:
            vectors.append("WordPress vulnerabilities (WPScan)")
        if "joomla" in tech_lower:
            vectors.append("Joomla vulnerabilities")
        if "apache" in tech_lower:
            vectors.append("Apache misconfigurations")
        if "nginx" in tech_lower:
            vectors.append("Nginx misconfigurations")
    
    state["attack_vectors"] = vectors
    state["phases_completed"].append("attack_vectors")
    
    print(f"   ✓ Identified {len(vectors)} attack vectors")
    return state


def report_node(state: AttackSurfaceState, agent) -> AttackSurfaceState:
    """Node 5: Generate attack surface report"""
    print("📋 [Node 5] Generating Report...")
    state["end_time"] = datetime.now().isoformat()
    state["phases_completed"].append("report")
    return state


# ─────────────────────────────────────────────────────────────────
# Routing
# ─────────────────────────────────────────────────────────────────

def route_after_port_enum(state: AttackSurfaceState) -> str:
    """Route based on what we found"""
    # Check for web ports
    web_ports = {80, 443, 8080, 8443}
    has_web = any(
        any(p in web_ports for p in ports)
        for ports in state["open_ports"].values()
    )
    if has_web:
        return "web_fingerprint"
    return "attack_vectors"


# ─────────────────────────────────────────────────────────────────
# Main Graph Class
# ─────────────────────────────────────────────────────────────────

class AttackSurfaceGraph:
    """
    LangGraph workflow for attack surface mapping.
    
    Graph structure:
    
    [Asset Discovery] → [Port Enum] →─┬─→ [Web Fingerprint] → [Attack Vectors] → [Report]
                                       │
                                       └─→ [Attack Vectors] (if no web)
    """
    
    def __init__(self, agent, checkpointer=None):
        self.agent = agent
        self.checkpointer = checkpointer or MemorySaver()
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build the attack surface graph"""
        
        workflow = StateGraph(AttackSurfaceState)
        
        # Add nodes
        workflow.add_node("asset_discovery", lambda s: asset_discovery_node(s, self.agent))
        workflow.add_node("port_enum", lambda s: port_enum_node(s, self.agent))
        workflow.add_node("web_fingerprint", lambda s: web_fingerprint_node(s, self.agent))
        workflow.add_node("attack_vectors", lambda s: attack_vector_node(s, self.agent))
        workflow.add_node("report", lambda s: report_node(s, self.agent))
        
        # Entry point
        workflow.set_entry_point("asset_discovery")
        
        # Edges
        workflow.add_edge("asset_discovery", "port_enum")
        
        # Conditional: web ports → fingerprint, else → attack vectors
        workflow.add_conditional_edges(
            "port_enum",
            route_after_port_enum,
            {
                "web_fingerprint": "web_fingerprint",
                "attack_vectors": "attack_vectors",
            }
        )
        
        workflow.add_edge("web_fingerprint", "attack_vectors")
        workflow.add_edge("attack_vectors", "report")
        workflow.add_edge("report", END)
        
        return workflow.compile(checkpointer=self.checkpointer)
    
    def run(self, target: str) -> AttackSurfaceState:
        """Run attack surface mapping"""
        
        initial_state: AttackSurfaceState = {
            "target": target,
            "subdomains": [],
            "ip_addresses": [],
            "open_ports": {},
            "services": {},
            "web_hosts": [],
            "technologies": [],
            "endpoints": [],
            "total_assets": 0,
            "exposed_services": 0,
            "attack_vectors": [],
            "phases_completed": [],
            "errors": [],
            "start_time": datetime.now().isoformat(),
            "end_time": None,
        }
        
        print(f"\n🎯 Attack Surface Mapping for {target}")
        print("=" * 50)
        
        config = {"configurable": {"thread_id": f"attacksurface_{target}"}}
        final_state = self.graph.invoke(initial_state, config)
        
        print("=" * 50)
        print(f"✅ Attack Surface Mapping Complete!")
        print(f"   Assets: {final_state['total_assets']}")
        print(f"   Exposed Services: {final_state['exposed_services']}")
        print(f"   Attack Vectors: {len(final_state['attack_vectors'])}")
        
        return final_state
    
    def format_results(self, state: AttackSurfaceState) -> str:
        """Format results for display"""
        lines = [
            f"🎯 **Attack Surface Report**",
            f"   Target: {state['target']}",
            "",
            f"**Assets Discovered:** {state['total_assets']}",
            f"**Exposed Services:** {state['exposed_services']}",
            f"**Web Technologies:** {len(state['technologies'])}",
            f"**Attack Vectors:** {len(state['attack_vectors'])}",
            "",
            "**Subdomains:**",
        ]
        
        for sub in state['subdomains'][:10]:
            lines.append(f"   • {sub}")
        if len(state['subdomains']) > 10:
            lines.append(f"   ... and {len(state['subdomains']) - 10} more")
        
        if state['attack_vectors']:
            lines.append("\n**Potential Attack Vectors:**")
            for vector in state['attack_vectors']:
                lines.append(f"   ⚠️ {vector}")
        
        return "\n".join(lines)


# Intent detection
ATTACKSURFACE_KEYWORDS = [
    "attack surface", "attack-surface", "attacksurface",
    "surface mapping", "map attack", "exposure",
    "external footprint", "asset discovery",
]

def is_attacksurface_query(query: str) -> bool:
    """Check if query is about attack surface mapping"""
    query_lower = query.lower()
    return any(keyword in query_lower for keyword in ATTACKSURFACE_KEYWORDS)
