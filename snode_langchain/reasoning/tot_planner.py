"""
Tree of Thought (ToT) Planner for SNODE

This module implements Tree of Thought reasoning for intelligent tool selection
and attack planning. Instead of linear tool selection, ToT explores multiple
strategies, evaluates them, and picks the best approach with backtracking.

Reference: "Tree of Thoughts: Deliberate Problem Solving with Large Language Models"
"""
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum


class StrategyType(Enum):
    """Types of attack strategies"""
    FAST = "fast"           # Quick results, less thorough
    THOROUGH = "thorough"   # Complete coverage, slower
    STEALTHY = "stealthy"   # Low noise, evade detection
    TARGETED = "targeted"   # Focus on specific vulns


@dataclass
class Strategy:
    """A single attack/scan strategy"""
    name: str
    type: StrategyType
    tools: List[str]        # Ordered list of tools to use
    description: str
    estimated_time: int     # Minutes
    
    # Evaluation scores (0-10)
    speed_score: float = 0.0
    coverage_score: float = 0.0
    stealth_score: float = 0.0
    success_probability: float = 0.0
    overall_score: float = 0.0
    
    # Execution state
    executed: bool = False
    success: bool = False
    results: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class ToTState:
    """State for Tree of Thought planning"""
    goal: str
    target: str
    strategies: List[Strategy] = field(default_factory=list)
    current_strategy_idx: int = 0
    backtrack_count: int = 0
    final_result: Optional[Dict] = None


# ─────────────────────────────────────────────────────────────────
# Strategy Templates
# ─────────────────────────────────────────────────────────────────

STRATEGY_TEMPLATES = {
    "vulnerability_scan": [
        Strategy(
            name="Quick Vuln Check",
            type=StrategyType.FAST,
            tools=["httpx_probe", "nuclei_scan"],
            description="Fast tech detection + nuclei CVE scan",
            estimated_time=5,
        ),
        Strategy(
            name="Thorough Assessment",
            type=StrategyType.THOROUGH,
            tools=["httpx_probe", "nmap_service_detection", "nuclei_scan", "nikto_scan", "dalfox_xss"],
            description="Complete assessment with port scan, vuln scan, and web checks",
            estimated_time=30,
        ),
        Strategy(
            name="Stealthy Probe",
            type=StrategyType.STEALTHY,
            tools=["nmap_quick_scan", "httpx_probe", "nuclei_scan"],
            description="Low-noise scan with limited templates",
            estimated_time=15,
        ),
    ],
    "subdomain_enum": [
        Strategy(
            name="Fast Subdomain Discovery",
            type=StrategyType.FAST,
            tools=["subfinder_enum"],
            description="Quick passive subdomain discovery",
            estimated_time=2,
        ),
        Strategy(
            name="Comprehensive Enum",
            type=StrategyType.THOROUGH,
            tools=["subfinder_enum", "amass_enum", "bbot_subdomain_enum"],
            description="All tools in parallel with deduplication",
            estimated_time=15,
        ),
    ],
    "port_scan": [
        Strategy(
            name="Detailed File Scan",
            type=StrategyType.THOROUGH,
            tools=["nmap_scan_from_file"],
            description="Scan subdomain file with nmap - detailed service info",
            estimated_time=10,
        ),
        Strategy(
            name="Fast File Scan",
            type=StrategyType.FAST,
            tools=["naabu_scan_from_file"],
            description="Ultra-fast scan with naabu - less detail",
            estimated_time=2,
        ),
        Strategy(
            name="High-Speed Scan",
            type=StrategyType.FAST,
            tools=["masscan_scan_from_file"],
            description="Fastest scan with masscan - basic port detection",
            estimated_time=1,
        ),
        Strategy(
            name="Single Target Deep",
            type=StrategyType.THOROUGH,
            tools=["nmap_service_detection"],
            description="Deep scan single target with service detection",
            estimated_time=15,
        ),
    ],
    "web_recon": [
        Strategy(
            name="Quick Directory Scan",
            type=StrategyType.FAST,
            tools=["gobuster_dir"],
            description="Fast directory bruteforce",
            estimated_time=5,
        ),
        Strategy(
            name="Full Web Recon",
            type=StrategyType.THOROUGH,
            tools=["httpx_probe", "katana_crawl", "gau_urls", "ffuf_fuzz"],
            description="Crawling + historical URLs + fuzzing",
            estimated_time=25,
        ),
    ],
}


# ─────────────────────────────────────────────────────────────────
# ToT Planner Class
# ─────────────────────────────────────────────────────────────────

class ToTPlanner:
    """
    Tree of Thought Planner for intelligent tool selection.
    
    Flow:
    1. Analyze goal → determine task type
    2. Generate multiple strategies
    3. Evaluate each strategy
    4. Execute best strategy
    5. On failure → backtrack → try next
    """
    
    def __init__(self, llm=None, tool_map: Dict[str, Callable] = None):
        self.llm = llm
        self.tool_map = tool_map or {}
        self.max_backtrack = 3
    
    def classify_goal(self, goal: str) -> str:
        """Classify the user's goal into a task type"""
        goal_lower = goal.lower()
        
        # Vulnerability scanning
        if any(kw in goal_lower for kw in ["vuln", "vulnerability", "cve", "exploit", "security scan", "assessment"]):
            return "vulnerability_scan"
        
        # Subdomain enumeration
        if any(kw in goal_lower for kw in ["subdomain", "enum", "discover domain", "find domain"]):
            return "subdomain_enum"
        
        # Port scanning
        if any(kw in goal_lower for kw in ["port", "service", "open port", "nmap", "scan port"]):
            return "port_scan"
        
        # Web reconnaissance
        if any(kw in goal_lower for kw in ["directory", "crawl", "url", "endpoint", "fuzz", "web recon"]):
            return "web_recon"
        
        # Default to vulnerability scan for security-related queries
        if any(kw in goal_lower for kw in ["scan", "hack", "pentest", "attack"]):
            return "vulnerability_scan"
        
        return "vulnerability_scan"  # Default
    
    def generate_strategies(self, goal: str, target: str) -> List[Strategy]:
        """Generate multiple strategies for the goal"""
        task_type = self.classify_goal(goal)
        
        # Get template strategies
        templates = STRATEGY_TEMPLATES.get(task_type, STRATEGY_TEMPLATES["vulnerability_scan"])
        
        # Clone templates (don't modify originals)
        strategies = []
        for template in templates:
            strategy = Strategy(
                name=template.name,
                type=template.type,
                tools=template.tools.copy(),
                description=template.description,
                estimated_time=template.estimated_time,
            )
            strategies.append(strategy)
        
        return strategies
    
    def evaluate_strategy(self, strategy: Strategy, goal: str) -> Strategy:
        """Evaluate a strategy and assign scores"""
        
        # Speed score (inverse of time)
        if strategy.estimated_time <= 5:
            strategy.speed_score = 9
        elif strategy.estimated_time <= 15:
            strategy.speed_score = 7
        elif strategy.estimated_time <= 30:
            strategy.speed_score = 5
        else:
            strategy.speed_score = 3
        
        # Coverage score (based on number and type of tools)
        num_tools = len(strategy.tools)
        if num_tools >= 4:
            strategy.coverage_score = 9
        elif num_tools >= 3:
            strategy.coverage_score = 7
        elif num_tools >= 2:
            strategy.coverage_score = 5
        else:
            strategy.coverage_score = 3
        
        # Stealth score (based on strategy type)
        stealth_map = {
            StrategyType.STEALTHY: 9,
            StrategyType.TARGETED: 7,
            StrategyType.FAST: 5,
            StrategyType.THOROUGH: 3,
        }
        strategy.stealth_score = stealth_map.get(strategy.type, 5)
        
        # Success probability (check if tools exist)
        available = sum(1 for t in strategy.tools if t in self.tool_map)
        strategy.success_probability = (available / len(strategy.tools)) * 10 if strategy.tools else 0
        
        # Overall score (weighted average)
        # For security: coverage > speed > stealth
        strategy.overall_score = (
            strategy.coverage_score * 0.4 +
            strategy.speed_score * 0.3 +
            strategy.stealth_score * 0.1 +
            strategy.success_probability * 0.2
        )
        
        return strategy
    
    def rank_strategies(self, strategies: List[Strategy]) -> List[Strategy]:
        """Sort strategies by overall score (descending)"""
        return sorted(strategies, key=lambda s: s.overall_score, reverse=True)
    
    def plan(self, goal: str, target: str) -> ToTState:
        """
        Main planning method - generates and evaluates strategies.
        
        Returns a ToTState with ranked strategies ready for execution.
        """
        # Generate strategies
        strategies = self.generate_strategies(goal, target)
        
        # Evaluate each
        for strategy in strategies:
            self.evaluate_strategy(strategy, goal)
        
        # Rank by score
        ranked = self.rank_strategies(strategies)
        
        # Print plan
        print(f"\n🌳 Tree of Thought Planning")
        print(f"   Goal: {goal}")
        print(f"   Target: {target}")
        print(f"\n📊 Strategies (ranked by score):")
        for i, s in enumerate(ranked):
            status = "→" if i == 0 else " "
            print(f"   {status} [{i+1}] {s.name} (score: {s.overall_score:.1f})")
            print(f"       Tools: {' → '.join(s.tools)}")
            print(f"       Time: ~{s.estimated_time}min | Coverage: {s.coverage_score}/10")
        
        return ToTState(
            goal=goal,
            target=target,
            strategies=ranked,
            current_strategy_idx=0,
        )
    
    def execute_strategy(self, state: ToTState, strategy: Strategy) -> bool:
        """
        Execute a single strategy.
        
        Returns True if successful, False if should backtrack.
        """
        print(f"\n🔄 Executing: {strategy.name}")
        
        all_results = {}
        
        for tool_name in strategy.tools:
            if tool_name not in self.tool_map:
                print(f"   ⚠ Tool not found: {tool_name}")
                continue
            
            print(f"   → Running {tool_name}...")
            try:
                tool = self.tool_map[tool_name]
                
                # Determine args based on tool type
                if "domain" in tool_name or "subdomain" in tool_name or "enum" in tool_name:
                    args = {"domain": state.target}
                else:
                    args = {"target": state.target}
                
                # Execute tool
                if hasattr(tool, 'invoke'):
                    result = tool.invoke(args)
                elif callable(tool):
                    result = tool(**args)
                else:
                    result = {"error": f"Tool {tool_name} not callable"}
                
                all_results[tool_name] = result
                
                # Check for failure
                if isinstance(result, dict) and result.get("error"):
                    print(f"   ✗ {tool_name} failed: {result.get('error')}")
                else:
                    print(f"   ✓ {tool_name} completed")
                    
            except Exception as e:
                print(f"   ✗ {tool_name} error: {e}")
                all_results[tool_name] = {"error": str(e)}
        
        # Determine if strategy succeeded (at least one tool worked)
        successes = sum(1 for r in all_results.values() 
                       if isinstance(r, dict) and not r.get("error"))
        
        strategy.executed = True
        strategy.results = all_results
        strategy.success = successes > 0
        
        return strategy.success
    
    def execute_with_backtrack(self, state: ToTState) -> ToTState:
        """
        Execute strategies with automatic backtracking on failure.
        """
        while state.current_strategy_idx < len(state.strategies):
            strategy = state.strategies[state.current_strategy_idx]
            
            success = self.execute_strategy(state, strategy)
            
            if success:
                print(f"\n✅ Strategy '{strategy.name}' succeeded")
                state.final_result = strategy.results
                return state
            
            # Backtrack
            state.backtrack_count += 1
            state.current_strategy_idx += 1
            
            if state.current_strategy_idx < len(state.strategies):
                print(f"\n↩ Backtracking... trying next strategy")
            
            if state.backtrack_count >= self.max_backtrack:
                print(f"\n⚠ Max backtrack limit reached ({self.max_backtrack})")
                break
        
        print(f"\n❌ All strategies exhausted")
        state.final_result = {"error": "All strategies failed"}
        return state
    
    def format_results(self, state: ToTState) -> str:
        """Format the ToT execution results for display"""
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append("🌳 TREE OF THOUGHT RESULTS")
        lines.append(f"{'='*60}")
        lines.append(f"Goal: {state.goal}")
        lines.append(f"Target: {state.target}")
        lines.append(f"Strategies tried: {state.current_strategy_idx + 1}/{len(state.strategies)}")
        lines.append(f"Backtracks: {state.backtrack_count}")
        
        # Show executed strategies
        for i, s in enumerate(state.strategies):
            if s.executed:
                status = "✅" if s.success else "❌"
                lines.append(f"\n{status} {s.name}:")
                for tool, result in s.results.items():
                    if isinstance(result, dict):
                        if result.get("error"):
                            lines.append(f"   ✗ {tool}: {result['error']}")
                        else:
                            # Summarize result
                            lines.append(f"   ✓ {tool}: OK")
        
        lines.append(f"{'='*60}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Integration function for agent
# ─────────────────────────────────────────────────────────────────

def should_use_tot(query: str) -> bool:
    """Determine if query should use Tree of Thought planning"""
    query_lower = query.lower()
    
    # Complex tasks that benefit from ToT
    tot_triggers = [
        "full scan", "complete scan", "comprehensive",
        "security assessment", "pentest",
        "find all", "discover all",
        "thorough", "deep scan",
        "attack", "exploit",
    ]
    
    return any(trigger in query_lower for trigger in tot_triggers)


def extract_target_from_query(query: str) -> str:
    """Extract target from query string"""
    import re
    
    # Look for URLs
    url_match = re.search(r'https?://[^\s]+', query)
    if url_match:
        return url_match.group(0)
    
    # Look for domains with subdomains (e.g., testphp.vulnweb.com)
    # Pattern: word.word.tld or word.tld
    domain_match = re.search(r'(?:on|for|scan|target)\s+([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})', query, re.IGNORECASE)
    if domain_match:
        return domain_match.group(1)
    
    # Look for any domain-like pattern
    domain_match = re.search(r'\b([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b', query)
    if domain_match:
        return domain_match.group(1)
    
    return ""
