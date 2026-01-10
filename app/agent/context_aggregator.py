"""
Context Aggregator - Pre-LLM Context Gathering
===============================================

Gathers ALL relevant context BEFORE making LLM calls.
This is the Cursor-style "context aggregation" pattern.

Flow:
1. User query comes in
2. ContextAggregator gathers:
   - Session context (current target, findings)
   - Relevant facts from AttackMemory
   - Past failures for this target/tool
   - CVE data for detected technologies
   - Tool suggestions from semantic search
   - Conversation history
3. All this context is passed to the LLM in one rich prompt
"""
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from app.agent.context_manager import SessionContext
    from app.agent.memory import Fact, FailedAction


@dataclass
class AggregatedContext:
    """
    Everything the LLM needs to make a decision.
    
    This is passed to planner_node, analyzer_node, etc.
    Ensures comprehensive context for every LLM call.
    """
    # Current session data
    session: "SessionContext" = None
    
    # Target information (extracted for convenience)
    target: Optional[str] = None
    target_type: str = "unknown"  # domain, ip, url
    
    # Past findings from AttackMemory
    relevant_facts: List["Fact"] = field(default_factory=list)
    past_failures: List["FailedAction"] = field(default_factory=list)
    
    # RAG results
    relevant_cves: List[Dict[str, Any]] = field(default_factory=list)
    tool_suggestions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Conversation history
    recent_messages: List[Dict[str, str]] = field(default_factory=list)
    conversation_summary: str = ""
    
    # Learning hints
    learning_hints: List[str] = field(default_factory=list)
    
    def to_prompt_context(self) -> str:
        """
        Convert to string for inclusion in LLM prompts.
        
        Returns formatted context string.
        """
        lines = []
        
        # Target info
        if self.target:
            lines.append(f"TARGET: {self.target} ({self.target_type})")
        
        # Session summary
        if self.session:
            if self.session.subdomains:
                lines.append(f"SUBDOMAINS: {len(self.session.subdomains)} found")
            if self.session.open_ports:
                lines.append(f"OPEN PORTS: {len(self.session.open_ports)} services")
            if self.session.detected_tech:
                lines.append(f"TECHNOLOGIES: {', '.join(self.session.detected_tech[:5])}")
            if self.session.vulns_found:
                lines.append(f"VULNERABILITIES: {len(self.session.vulns_found)} identified")
            if self.session.tools_run:
                lines.append(f"TOOLS USED: {', '.join(self.session.tools_run[-5:])}")
            lines.append(f"PHASE: {self.session.current_phase}")
        
        # Relevant past findings
        if self.relevant_facts:
            lines.append(f"\nRELEVANT FINDINGS ({len(self.relevant_facts)}):")
            for fact in self.relevant_facts[:5]:
                lines.append(f"  [{fact.fact_type}] {fact.target}: {str(fact.data)[:100]}")
        
        # CVE context
        if self.relevant_cves:
            lines.append(f"\nRELEVANT CVEs ({len(self.relevant_cves)}):")
            for cve in self.relevant_cves[:3]:
                lines.append(f"  {cve.get('cve_id', 'Unknown')}: {cve.get('description', '')[:80]}...")
        
        # Tool suggestions
        if self.tool_suggestions:
            tool_names = [t.get("tool", t.get("name", "")) for t in self.tool_suggestions[:5]]
            lines.append(f"\nSUGGESTED TOOLS: {', '.join(tool_names)}")
        
        # Learning hints (from past failures)
        if self.learning_hints:
            lines.append(f"\n⚡ LEARNED FROM PAST:")
            for hint in self.learning_hints[:3]:
                lines.append(f"  • {hint}")
        
        # Conversation context
        if self.conversation_summary:
            lines.append(f"\nCONVERSATION: {self.conversation_summary[:200]}")
        
        return "\n".join(lines) if lines else "No prior context."
    
    def has_target(self) -> bool:
        """Check if we have a valid target."""
        return bool(self.target)
    
    def has_past_data(self) -> bool:
        """Check if we have any past findings for this target."""
        return bool(self.relevant_facts or 
                   (self.session and (self.session.subdomains or self.session.open_ports)))


class ContextAggregator:
    """
    Gather all context BEFORE LLM call.
    
    This is the key to making intelligent decisions:
    - Don't re-scan what we already know
    - Don't repeat failed approaches
    - Use past findings to inform tool selection
    
    Usage:
        aggregator = ContextAggregator()
        context = aggregator.aggregate_for_planning("scan example.com")
        # Now pass context.to_prompt_context() to LLM
    """
    
    def __init__(self):
        self._context_manager = None
        self._attack_memory = None
        self._intelligence = None
        self._tool_index = None
    
    @property
    def context_manager(self):
        """Lazy-load context manager."""
        if self._context_manager is None:
            from app.agent.context_manager import get_context_manager
            self._context_manager = get_context_manager()
        return self._context_manager
    
    @property
    def attack_memory(self):
        """Lazy-load attack memory."""
        if self._attack_memory is None:
            try:
                from app.agent.memory import get_attack_memory
                self._attack_memory = get_attack_memory()
            except:
                pass
        return self._attack_memory
    
    @property
    def intelligence(self):
        """Lazy-load intelligence layer."""
        if self._intelligence is None:
            try:
                from app.agent.intelligence import get_intelligence
                self._intelligence = get_intelligence()
            except:
                pass
        return self._intelligence
    
    @property
    def tool_index(self):
        """Lazy-load tool index."""
        if self._tool_index is None:
            try:
                from app.rag.tool_index import ToolIndex
                self._tool_index = ToolIndex()
            except:
                pass
        return self._tool_index
    
    def aggregate_for_planning(self, query: str, state: Dict[str, Any] = None) -> AggregatedContext:
        """
        Gather context for planner node.
        
        Called before asking LLM to suggest tools/plan.
        
        Args:
            query: User's query
            state: Current agent state (optional)
            
        Returns:
            AggregatedContext with all relevant data
        """
        agg = AggregatedContext()
        
        # 1. Get session context
        agg.session = self.context_manager.get_context()
        agg.target = agg.session.get_target()
        agg.target_type = self._classify_target(agg.target)
        
        # 2. Extract target from query if not in context
        if not agg.target:
            agg.target = self._extract_target_from_query(query)
            if agg.target:
                self.context_manager.set_target(agg.target, source="query")
                agg.session = self.context_manager.get_context()
                agg.target_type = self._classify_target(agg.target)
        
        # 3. Query AttackMemory for relevant facts
        if self.attack_memory and agg.target:
            try:
                agg.relevant_facts = self.attack_memory.get_facts_for_target(agg.target)
            except Exception as e:
                print(f"  ⚠️ Fact query failed: {e}")
        
        # 4. Get past failures for learning
        if self.attack_memory and agg.target:
            try:
                # Get all failures and filter by target
                all_failures = self.attack_memory.failed_actions if hasattr(self.attack_memory, 'failed_actions') else []
                agg.past_failures = [
                    f for f in all_failures 
                    if agg.target in f.target_pattern or agg.target in str(f.input_params)
                ]
                
                # Generate learning hints
                for failure in agg.past_failures[:3]:
                    hint = failure.suggest_fix() if hasattr(failure, 'suggest_fix') else str(failure.error)[:50]
                    agg.learning_hints.append(f"{failure.action}: {hint}")
            except Exception as e:
                print(f"  ⚠️ Failure query failed: {e}")
        
        # 5. Query CVE RAG if we have detected technologies
        if agg.session and agg.session.detected_tech:
            try:
                agg.relevant_cves = self._get_cves_for_tech(agg.session.detected_tech)
            except Exception as e:
                print(f"  ⚠️ CVE query failed: {e}")
        
        # 6. Get tool suggestions from semantic search
        try:
            agg.tool_suggestions = self._get_tool_suggestions(query)
        except Exception as e:
            print(f"  ⚠️ Tool suggestion failed: {e}")
        
        # 7. Get conversation history from state
        if state and state.get("messages"):
            agg.recent_messages = state.get("messages", [])[-6:]  # Last 3 exchanges
            agg.conversation_summary = self._summarize_conversation(agg.recent_messages)
        
        return agg
    
    def aggregate_for_execution(self, tools: List[str], params: Dict[str, Any]) -> AggregatedContext:
        """
        Gather context for executor node.
        
        Called before executing tools.
        
        Args:
            tools: List of tools to execute
            params: Execution parameters
            
        Returns:
            AggregatedContext focused on execution
        """
        agg = AggregatedContext()
        
        # Get session context
        agg.session = self.context_manager.get_context()
        agg.target = params.get("domain") or params.get("target") or agg.session.get_target()
        
        # Check for past failures on these specific tools
        if self.attack_memory:
            for tool in tools:
                try:
                    hint = self.attack_memory.get_learning_hint(tool, params)
                    if hint:
                        should_retry = hint.get("should_retry", True)
                        suggestion = hint.get("suggestion", "")
                        if not should_retry:
                            agg.learning_hints.append(f"❌ {tool}: Max retries reached - {suggestion}")
                        else:
                            agg.learning_hints.append(f"⚠️ {tool}: Previous failure - {suggestion}")
                except:
                    pass
        
        return agg
    
    def aggregate_for_analysis(self, results: Dict[str, Any], state: Dict[str, Any]) -> AggregatedContext:
        """
        Gather context for analyzer node.
        
        Called after execution to analyze results.
        
        Args:
            results: Execution results
            state: Current agent state
            
        Returns:
            AggregatedContext with execution results and history
        """
        agg = AggregatedContext()
        
        # Get session context
        agg.session = self.context_manager.get_context()
        agg.target = agg.session.get_target()
        
        # Get all relevant facts for comprehensive analysis
        if self.attack_memory and agg.target:
            try:
                agg.relevant_facts = self.attack_memory.get_facts_for_target(agg.target)
            except:
                pass
        
        # Get CVEs for any newly detected tech
        if agg.session and agg.session.detected_tech:
            try:
                agg.relevant_cves = self._get_cves_for_tech(agg.session.detected_tech)
            except:
                pass
        
        return agg
    
    def aggregate_for_memory_query(self, query: str) -> AggregatedContext:
        """
        Gather context for memory query node.
        
        Searches both session and persistent memory.
        
        Args:
            query: User's memory query (e.g., "show me subdomains")
            
        Returns:
            AggregatedContext with memory data
        """
        agg = AggregatedContext()
        
        # Get session context (includes SharedMemory data)
        agg.session = self.context_manager.get_context()
        agg.target = agg.session.get_target()
        
        # Get all facts from AttackMemory
        if self.attack_memory:
            try:
                if agg.target:
                    agg.relevant_facts = self.attack_memory.get_facts_for_target(agg.target)
                else:
                    # Get all facts if no specific target
                    agg.relevant_facts = self.attack_memory.facts[:50] if hasattr(self.attack_memory, 'facts') else []
            except:
                pass
        
        return agg
    
    def _extract_target_from_query(self, query: str) -> Optional[str]:
        """Extract domain or IP from query."""
        import re
        
        # Check for domain
        domain_match = re.search(
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
            query
        )
        if domain_match:
            return domain_match.group()
        
        # Check for IP
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
        if ip_match:
            return ip_match.group()
        
        return None
    
    def _classify_target(self, target: Optional[str]) -> str:
        """Classify target type."""
        if not target:
            return "unknown"
        if target.startswith("http"):
            return "url"
        if all(c.isdigit() or c == '.' for c in target):
            return "ip"
        return "domain"
    
    def _get_cves_for_tech(self, technologies: List[str]) -> List[Dict[str, Any]]:
        """Get CVEs for detected technologies."""
        cves = []
        
        if self.intelligence:
            try:
                cves = self.intelligence.get_relevant_cves(technologies)
            except:
                pass
        
        # Fallback to direct CVE RAG query
        if not cves:
            try:
                from app.rag.cve_rag import get_cve_rag
                cve_rag = get_cve_rag()
                for tech in technologies[:3]:  # Limit queries
                    results = cve_rag.search(tech, n_results=2)
                    cves.extend(results)
            except Exception as e:
                print(f"  ⚠️ CVE RAG query failed: {e}")
        
        return cves[:10]  # Limit total CVEs
    
    def _get_tool_suggestions(self, query: str) -> List[Dict[str, Any]]:
        """Get tool suggestions from semantic search."""
        suggestions = []
        
        if self.tool_index:
            try:
                results = self.tool_index.search(query, n_results=5)
                suggestions = results
            except:
                pass
        
        # Fallback to intelligence layer
        if not suggestions and self.intelligence:
            try:
                understanding = self.intelligence.understand_query(query, {})
                if understanding.get("relevant_tools"):
                    suggestions = [{"tool": t} for t in understanding["relevant_tools"]]
            except:
                pass
        
        return suggestions
    
    def _summarize_conversation(self, messages: List[Dict[str, str]]) -> str:
        """Create brief summary of recent conversation."""
        if not messages:
            return ""
        
        summaries = []
        for msg in messages[-4:]:  # Last 2 exchanges
            role = msg.get("role", "user")
            content = msg.get("content", "")[:50]
            summaries.append(f"{role}: {content}...")
        
        return " | ".join(summaries)


# Singleton
_aggregator: Optional[ContextAggregator] = None


def get_context_aggregator() -> ContextAggregator:
    """Get or create the context aggregator singleton."""
    global _aggregator
    if _aggregator is None:
        _aggregator = ContextAggregator()
    return _aggregator
