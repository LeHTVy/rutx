"""
LangGraph Subdomain Enumeration Workflow (PARALLEL)

A fan-out/fan-in graph for subdomain discovery:
- Node 1: Amass (OSINT/passive)
- Node 2: BBOT (active + passive)  
- Node 3: Subfinder (passive)

All 3 nodes run in TRUE PARALLEL, results are merged in the merge node.

Graph Structure:
                    ┌─→ [Amass] ────┐
                    │               │
    [START] ────────┼─→ [BBOT] ─────┼─→ [Merge] → [Analyze] → [END]
                    │               │
                    └─→ [Subfinder] ┘
"""
from datetime import datetime
from typing import Any, Dict, List, Optional, Annotated
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
import operator


# ─────────────────────────────────────────────────────────────────
# State Definition with Reducers for Parallel Merging
# ─────────────────────────────────────────────────────────────────

def merge_lists(left: List[str], right: List[str]) -> List[str]:
    """Reducer: Merge two lists, keeping unique values"""
    if not left:
        return right
    if not right:
        return left
    return list(set(left) | set(right))


class SubdomainState(TypedDict):
    """State for subdomain enumeration workflow
    
    Uses Annotated types with reducers to handle parallel node merging.
    When multiple nodes write to the same field, the reducer combines them.
    """
    # Input (doesn't change)
    target: str
    
    # Results from each tool - use reducers to merge from parallel nodes
    amass_subdomains: Annotated[List[str], merge_lists]
    bbot_subdomains: Annotated[List[str], merge_lists]
    subfinder_subdomains: Annotated[List[str], merge_lists]
    
    # Merged results
    all_subdomains: Annotated[List[str], merge_lists]
    unique_count: int
    
    # LLM Analysis results
    high_value_subdomains: Annotated[List[str], merge_lists]
    analysis: str
    
    # Tracking - use operator.add to concatenate lists from parallel nodes
    tools_completed: Annotated[List[str], operator.add]
    errors: Annotated[List[str], operator.add]
    start_time: str
    end_time: Optional[str]


# ─────────────────────────────────────────────────────────────────
# Node Functions (Return PARTIAL state updates for parallel merge)
# ─────────────────────────────────────────────────────────────────

def amass_node(state: SubdomainState, agent) -> dict:
    """Node 1: Amass subdomain enumeration (runs in parallel)"""
    print("🔍 [Parallel] Running Amass...")
    
    subdomains = []
    tools_completed = []
    errors = []
    tool_name = "amass_enum"
    
    if tool_name in agent.tool_map:
        try:
            tool = agent.tool_map[tool_name]
            result = tool.invoke({"domain": state["target"]})
            
            if isinstance(result, dict) and "subdomains" in result:
                subdomains = result["subdomains"]
            elif isinstance(result, str):
                import re
                pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(state["target"])
                subdomains = re.findall(pattern, result)
            
            print(f"   ✓ Amass found {len(subdomains)} subdomains")
            tools_completed.append("amass")
        except Exception as e:
            errors.append(f"amass: {str(e)}")
            print(f"   ✗ Amass error: {e}")
    else:
        print("   ⚠ Amass not available")
    
    # Return PARTIAL state update (will be merged with other parallel nodes)
    return {
        "amass_subdomains": subdomains,
        "tools_completed": tools_completed,
        "errors": errors,
    }


def bbot_node(state: SubdomainState, agent) -> dict:
    """Node 2: BBOT subdomain enumeration (runs in parallel)"""
    print("🔍 [Parallel] Running BBOT...")
    
    subdomains = []
    tools_completed = []
    errors = []
    tool_name = "bbot_subdomain_enum"
    
    if tool_name in agent.tool_map:
        try:
            tool = agent.tool_map[tool_name]
            result = tool.invoke({"domain": state["target"]})
            
            if isinstance(result, dict) and "subdomains" in result:
                subdomains = result["subdomains"]
            elif isinstance(result, str):
                import re
                pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(state["target"])
                subdomains = re.findall(pattern, result)
            
            print(f"   ✓ BBOT found {len(subdomains)} subdomains")
            tools_completed.append("bbot")
        except Exception as e:
            errors.append(f"bbot: {str(e)}")
            print(f"   ✗ BBOT error: {e}")
    else:
        print("   ⚠ BBOT not available")
    
    return {
        "bbot_subdomains": subdomains,
        "tools_completed": tools_completed,
        "errors": errors,
    }


def subfinder_node(state: SubdomainState, agent) -> dict:
    """Node 3: Subfinder subdomain enumeration (runs in parallel)"""
    print("🔍 [Parallel] Running Subfinder...")
    
    subdomains = []
    tools_completed = []
    errors = []
    tool_name = "subfinder_enum"
    
    if tool_name in agent.tool_map:
        try:
            tool = agent.tool_map[tool_name]
            result = tool.invoke({"domain": state["target"]})
            
            if isinstance(result, dict) and "subdomains" in result:
                subdomains = result["subdomains"]
            elif isinstance(result, str):
                import re
                pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(state["target"])
                subdomains = re.findall(pattern, result)
            
            print(f"   ✓ Subfinder found {len(subdomains)} subdomains")
            tools_completed.append("subfinder")
        except Exception as e:
            errors.append(f"subfinder: {str(e)}")
            print(f"   ✗ Subfinder error: {e}")
    else:
        print("   ⚠ Subfinder not available")
    
    return {
        "subfinder_subdomains": subdomains,
        "tools_completed": tools_completed,
        "errors": errors,
    }


def merge_node(state: SubdomainState, agent) -> dict:
    """Merge node: Combine and deduplicate all results from parallel nodes"""
    print("📊 [Merge] Combining results from parallel nodes...")
    
    all_subs = set()
    
    # Merge from all sources (already populated by parallel nodes)
    for sub in state.get("amass_subdomains", []):
        all_subs.add(sub.lower().strip())
    for sub in state.get("bbot_subdomains", []):
        all_subs.add(sub.lower().strip())
    for sub in state.get("subfinder_subdomains", []):
        all_subs.add(sub.lower().strip())
    
    sorted_subs = sorted(all_subs)
    
    print(f"   ✓ Total unique subdomains: {len(sorted_subs)}")
    
    # SAVE MERGED FILE: This is the definitive list for port scanning
    target = state.get("target", "unknown")
    if sorted_subs:
        try:
            from snode_langchain.state import save_subdomains
            filepath = save_subdomains(sorted_subs, target)
            print(f"   📁 Merged subdomains saved: {filepath}")
        except Exception as e:
            print(f"   ⚠ Could not save merged subdomains: {e}")
    
    return {
        "all_subdomains": sorted_subs,
        "unique_count": len(sorted_subs),
        "end_time": datetime.now().isoformat(),
    }



def analyze_node(state: SubdomainState, agent) -> dict:
    """Analysis node: Use LLM to identify high-value subdomains"""
    print("🧠 [Analyze] LLM analyzing high-value targets...")
    
    subdomains = state.get("all_subdomains", [])
    if not subdomains:
        print("   ⚠ No subdomains to analyze")
        return {
            "analysis": "No subdomains found to analyze.",
            "high_value_subdomains": [],
        }
    
    # Build the analysis prompt
    subdomain_list = "\n".join(f"  - {sub}" for sub in subdomains)
    
    analysis_prompt = f"""Analyze these subdomains for {state['target']} and identify HIGH-VALUE targets for security assessment.

**Subdomains ({len(subdomains)} total):**
{subdomain_list}

**Categorize and prioritize based on:**

1. **🔴 Critical Priority** - Admin panels, control panels, management interfaces
   - Examples: admin.*, dashboard.*, portal.*, manage.*, cp.*, panel.*

2. **🟠 High Priority** - API endpoints, development/staging environments  
   - Examples: api.*, dev.*, staging.*, test.*, uat.*, sandbox.*

3. **🟡 Medium Priority** - Database/storage, internal tools, CI/CD
   - Examples: db.*, mysql.*, redis.*, jenkins.*, gitlab.*, jira.*

4. **🟢 Lower Priority** - Static content, CDN, marketing
   - Examples: cdn.*, static.*, www.*, mail.*, blog.*

**Output format:**
For each category that has matches, list the subdomains with a brief note on why they're interesting.
Conclude with a **Top 5 Targets** recommendation for initial investigation.

Be concise but thorough. Focus on actionable intelligence for penetration testing."""

    analysis_text = ""
    high_value = []
    
    try:
        # Use the agent's LLM for analysis
        if hasattr(agent, 'llm') and agent.llm:
            response = agent.llm.invoke(analysis_prompt)
            analysis_text = response.content if hasattr(response, 'content') else str(response)
            
            # Extract high-value subdomains based on patterns
            high_value_patterns = [
                'admin', 'dashboard', 'portal', 'manage', 'panel', 'cp',
                'api', 'dev', 'staging', 'test', 'uat', 'sandbox',
                'db', 'mysql', 'redis', 'jenkins', 'gitlab', 'jira',
                'vpn', 'internal', 'intranet', 'secure', 'login'
            ]
            for sub in subdomains:
                sub_prefix = sub.split('.')[0].lower()
                if any(pattern in sub_prefix for pattern in high_value_patterns):
                    high_value.append(sub)
            
            print(f"   ✓ Analysis complete - {len(high_value)} high-value targets identified")
        else:
            analysis_text = "LLM not available for analysis."
            print("   ⚠ LLM not available for analysis")
            
    except Exception as e:
        analysis_text = f"Analysis failed: {str(e)}"
        print(f"   ✗ Analysis error: {e}")
        return {
            "analysis": analysis_text,
            "high_value_subdomains": high_value,
            "errors": [f"analysis: {str(e)}"],
        }
    
    return {
        "analysis": analysis_text,
        "high_value_subdomains": high_value,
    }


# ─────────────────────────────────────────────────────────────────
# Main Graph Class with TRUE PARALLEL Execution
# ─────────────────────────────────────────────────────────────────

class SubdomainGraph:
    """
    LangGraph workflow for subdomain enumeration with PARALLEL execution.
    
    Graph structure (Fan-out/Fan-in):
    
                    ┌─→ [Amass] ────┐
                    │               │
        [START] ────┼─→ [BBOT] ─────┼─→ [Merge] → [Analyze] → [END]
                    │               │
                    └─→ [Subfinder] ┘
    
    All 3 tools run in TRUE PARALLEL, results are merged via reducers.
    """
    
    def __init__(self, agent, checkpointer=None):
        self.agent = agent
        self.checkpointer = checkpointer or MemorySaver()
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build the parallel subdomain enumeration graph"""
        
        workflow = StateGraph(SubdomainState)
        
        # Add nodes
        workflow.add_node("amass", lambda s: amass_node(s, self.agent))
        workflow.add_node("bbot", lambda s: bbot_node(s, self.agent))
        workflow.add_node("subfinder", lambda s: subfinder_node(s, self.agent))
        workflow.add_node("merge", lambda s: merge_node(s, self.agent))
        workflow.add_node("analyze", lambda s: analyze_node(s, self.agent))
        
        # ═══════════════════════════════════════════════════════════
        # FAN-OUT: START triggers all 3 tools in PARALLEL
        # ═══════════════════════════════════════════════════════════
        workflow.add_edge(START, "amass")
        workflow.add_edge(START, "bbot")
        workflow.add_edge(START, "subfinder")
        
        # ═══════════════════════════════════════════════════════════
        # FAN-IN: All 3 tools feed into merge (waits for all to complete)
        # ═══════════════════════════════════════════════════════════
        workflow.add_edge("amass", "merge")
        workflow.add_edge("bbot", "merge")
        workflow.add_edge("subfinder", "merge")
        
        # Sequential: merge → analyze → end
        workflow.add_edge("merge", "analyze")
        workflow.add_edge("analyze", END)
        
        return workflow.compile(checkpointer=self.checkpointer)
    
    def run(self, target: str) -> SubdomainState:
        """Run subdomain enumeration on target domain"""
        
        initial_state: SubdomainState = {
            "target": target,
            "amass_subdomains": [],
            "bbot_subdomains": [],
            "subfinder_subdomains": [],
            "all_subdomains": [],
            "unique_count": 0,
            "high_value_subdomains": [],
            "analysis": "",
            "tools_completed": [],
            "errors": [],
            "start_time": datetime.now().isoformat(),
            "end_time": None,
        }
        
        print(f"\n🚀 Subdomain Enumeration for {target}")
        print("=" * 50)
        print("Running: [Amass | BBOT | Subfinder] → Merge → Analyze")
        print("         ^^^^^^^^^^^^^^^^^^^^^^^^")
        print("              (PARALLEL)")
        print("=" * 50)
        
        config = {"configurable": {"thread_id": f"subdomain_{target}"}}
        final_state = self.graph.invoke(initial_state, config)
        
        print("=" * 50)
        print(f"✅ Complete! Found {final_state['unique_count']} unique subdomains")
        print(f"   Sources: {', '.join(final_state['tools_completed'])}")
        
        if final_state['errors']:
            print(f"   ⚠ Errors: {len(final_state['errors'])}")
        
        return final_state
    
    def format_results(self, state: SubdomainState) -> str:
        """Format results for display"""
        lines = [
            f"📡 **Subdomain Enumeration Results**",
            f"   Target: {state['target']}",
            f"   Total unique: {state['unique_count']}",
            "",
            f"**By source:**",
            f"   • Amass: {len(state.get('amass_subdomains', []))}",
            f"   • BBOT: {len(state.get('bbot_subdomains', []))}",
            f"   • Subfinder: {len(state.get('subfinder_subdomains', []))}",
            "",
        ]
        
        # Add high-value targets section
        high_value = state.get('high_value_subdomains', [])
        if high_value:
            lines.append(f"🎯 **High-Value Targets ({len(high_value)}):**")
            for sub in high_value[:10]:
                lines.append(f"   • {sub}")
            if len(high_value) > 10:
                lines.append(f"   ... and {len(high_value) - 10} more")
            lines.append("")
        
        # Add LLM analysis
        analysis = state.get('analysis', '')
        if analysis:
            lines.append("🧠 **LLM Security Analysis:**")
            lines.append(analysis)
            lines.append("")
        
        lines.append("**All Subdomains found:**")
        for sub in state.get('all_subdomains', [])[:30]:
            lines.append(f"   • {sub}")
        
        if len(state.get('all_subdomains', [])) > 30:
            lines.append(f"   ... and {len(state.get('all_subdomains', [])) - 30} more")
        
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Intent Detection - Trigger for subdomain queries
# ─────────────────────────────────────────────────────────────────

SUBDOMAIN_KEYWORDS = [
    "subdomain", "subdomains",
    "find subdomain", "enumerate subdomain",
    "discover subdomain", "list subdomain",
    "subdomain enumeration", "subdomain discovery",
]

def is_subdomain_query(query: str) -> bool:
    """Check if user query is about subdomain enumeration"""
    query_lower = query.lower()
    return any(keyword in query_lower for keyword in SUBDOMAIN_KEYWORDS)


def extract_domain_from_query(query: str) -> Optional[str]:
    """Extract domain from user query"""
    import re
    # Match domain patterns like example.com, sub.example.co.uk
    pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}'
    matches = re.findall(pattern, query)
    if matches:
        # Reconstruct full domain from last match
        domain_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}', query)
        if domain_match:
            return domain_match.group(0)
    return None
