"""
Attack Memory - Structured Fact Memory for Pentest Agent
=========================================================

⚠️ DEPRECATED: This module has been moved to app.memory.session
Please use:
    from app.memory import get_session_memory, Fact, Hypothesis

This file is kept for backward compatibility only.
"""
import warnings
warnings.warn(
    "app.agent.memory is deprecated. Use app.memory instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export from new location for backward compat
from app.memory.session import (
    SessionMemory as AttackMemory,
    Fact,
    Hypothesis,
    get_session_memory as get_attack_memory,
)

# Keep the old exports working
__all__ = ["AttackMemory", "Fact", "Hypothesis", "get_attack_memory"]

# =========================================================
# DEPRECATED CODE BELOW - KEPT FOR REFERENCE ONLY
# =========================================================

"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from uuid import uuid4
import json

from app.core.config import get_config

# LangChain memory imports (v1.x API)
try:
    from langchain_community.chat_message_histories import ChatMessageHistory
    from langchain_ollama import ChatOllama
    from langchain_core.messages import HumanMessage, AIMessage
    LANGCHAIN_MEMORY_AVAILABLE = True
except ImportError as e:
    LANGCHAIN_MEMORY_AVAILABLE = False
    print(f"⚠️ LangChain memory not available: {e}")


@dataclass
class Fact:
    """
    A single normalized observation from a tool.
    
    Facts are the atomic units of knowledge in the attack graph.
    They replace raw tool output with structured, queryable data.
    """
    id: str
    fact_type: str  # "open_port", "subdomain", "vulnerability", "service", "technology"
    target: str     # IP/domain this fact relates to
    data: Dict[str, Any]  # Structured data (port, service, cve_id, etc.)
    source_tool: str      # Which tool produced this
    timestamp: str        # ISO format
    confidence: float     # 0.0-1.0
    
    @classmethod
    def create(
        cls,
        fact_type: str,
        target: str,
        data: Dict[str, Any],
        source_tool: str,
        confidence: float = 0.8
    ) -> "Fact":
        """Factory method to create a fact with auto-generated ID and timestamp."""
        return cls(
            id=str(uuid4())[:8],
            fact_type=fact_type,
            target=target,
            data=data,
            source_tool=source_tool,
            timestamp=datetime.now().isoformat(),
            confidence=confidence
        )
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: Dict) -> "Fact":
        return cls(**d)
    
    def __str__(self) -> str:
        return f"[{self.fact_type}] {self.target}: {self.data}"


@dataclass
class Hypothesis:
    """
    An attack hypothesis derived from facts.
    
    Hypotheses represent potential attack vectors that the agent
    can test. They link back to supporting facts.
    """
    id: str
    target: str
    hypothesis: str           # "Apache 2.4.49 may be vulnerable to CVE-2021-41773"
    supporting_facts: List[str]  # Fact IDs
    confidence: float         # 0.0-1.0
    risk_level: str           # "low", "medium", "high", "critical"
    tested: bool = False
    test_result: Optional[str] = None  # "confirmed", "rejected", None
    
    @classmethod
    def create(
        cls,
        target: str,
        hypothesis: str,
        supporting_facts: List[str],
        confidence: float = 0.5,
        risk_level: str = "medium"
    ) -> "Hypothesis":
        return cls(
            id=str(uuid4())[:8],
            target=target,
            hypothesis=hypothesis,
            supporting_facts=supporting_facts,
            confidence=confidence,
            risk_level=risk_level
        )
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: Dict) -> "Hypothesis":
        return cls(**d)


@dataclass
class FailedAction:
    """Record of a failed action for auto-learning with lessons learned."""
    action: str
    input_params: Dict[str, Any]
    error: str
    timestamp: str
    target_pattern: str  # Generalized target for matching
    retry_count: int = 0
    max_retries: int = 2
    lesson_learned: str = ""  # What to do differently
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: Dict) -> "FailedAction":
        # Handle backwards compatibility
        if "retry_count" not in d:
            d["retry_count"] = 0
        if "max_retries" not in d:
            d["max_retries"] = 2
        if "lesson_learned" not in d:
            d["lesson_learned"] = ""
        return cls(**d)
    
    def can_retry(self) -> bool:
        """Check if action can be retried with different approach."""
        return self.retry_count < self.max_retries
    
    def suggest_fix(self) -> str:
        """Suggest how to fix based on error type."""
        error_lower = self.error.lower()
        
        if "timeout" in error_lower:
            return "Use shorter timeout or scan fewer targets"
        elif "not found" in error_lower or "not installed" in error_lower:
            return f"Tool not available - use alternative tool"
        elif "permission" in error_lower or "denied" in error_lower:
            return "Target may be protected - try different approach or stealth mode"
        elif "connection refused" in error_lower:
            return "Host not reachable - verify target is online"
        elif "rate limit" in error_lower or "too many" in error_lower:
            return "Rate limited - use stealth mode with delays"
        elif "no such" in error_lower or "not exist" in error_lower:
            return "Resource doesn't exist - try different path/port"
        else:
            return "Try with different parameters or alternative tool"


class AttackMemory:
    """
    Long-term memory for attack graph and learning.
    
    Features:
    - Structured fact storage (replaces raw observations)
    - Hypothesis tracking for attack graph thinking
    - Auto-learning from failures (persisted to disk)
    - Query interface for context building
    - LangChain conversation memory with summarization
    """
    
    def __init__(self, persist: bool = True, model: str = "mistral"):
        self.facts: List[Fact] = []
        self.hypotheses: List[Hypothesis] = []
        self.failed_actions: List[FailedAction] = []
        self.persist = persist
        
        # Setup persistence directory
        config = get_config()
        self.memory_dir = config.discoveries_dir / "memory"
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.facts_file = self.memory_dir / "facts.json"
        self.hypotheses_file = self.memory_dir / "hypotheses.json"
        self.failures_file = self.memory_dir / "failed_actions.json"
        
        # Initialize LangChain conversation memory (v1.x API)
        self.chat_history = None
        self.llm = None
        if LANGCHAIN_MEMORY_AVAILABLE:
            try:
                self.llm = ChatOllama(
                    model=model,
                    base_url="http://localhost:11434",
                    temperature=0.3
                )
                self.chat_history = ChatMessageHistory()
                print("📚 LangChain memory initialized (ChatMessageHistory)")
            except Exception as e:
                print(f"⚠️ LangChain memory init failed: {e}")
        
        # Load existing data
        if persist:
            self.load()
    
    # ========== Fact Management ==========
    
    def add_fact(self, fact: Fact) -> None:
        """Add a normalized fact to memory."""
        # Avoid duplicates based on content
        for existing in self.facts:
            if (existing.fact_type == fact.fact_type and 
                existing.target == fact.target and
                existing.data == fact.data):
                return  # Already exists
        
        self.facts.append(fact)
        if self.persist:
            self._save_facts()
    
    def add_facts(self, facts: List[Fact]) -> None:
        """Add multiple facts."""
        for fact in facts:
            self.add_fact(fact)
    
    def get_facts_for_target(self, target: str) -> List[Fact]:
        """Get all facts related to a target."""
        return [f for f in self.facts if f.target == target or target in f.target]
    
    def get_facts_by_type(self, fact_type: str) -> List[Fact]:
        """Get all facts of a specific type."""
        return [f for f in self.facts if f.fact_type == fact_type]
    
    def get_open_ports(self) -> Dict[str, List[int]]:
        """Get all discovered open ports grouped by host."""
        ports_by_host: Dict[str, List[int]] = {}
        for fact in self.get_facts_by_type("open_port"):
            host = fact.target
            port = fact.data.get("port")
            if host and port:
                if host not in ports_by_host:
                    ports_by_host[host] = []
                if port not in ports_by_host[host]:
                    ports_by_host[host].append(port)
        return ports_by_host
    
    def get_subdomains(self) -> List[str]:
        """Get all discovered subdomains."""
        return [f.target for f in self.get_facts_by_type("subdomain")]
    
    def get_vulnerabilities(self) -> List[Fact]:
        """Get all discovered vulnerabilities."""
        return self.get_facts_by_type("vulnerability")
    
    # ========== Hypothesis Management ==========
    
    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        """Add an attack hypothesis."""
        self.hypotheses.append(hypothesis)
        if self.persist:
            self._save_hypotheses()
    
    def get_untested_hypotheses(self) -> List[Hypothesis]:
        """Get hypotheses that haven't been tested yet."""
        return [h for h in self.hypotheses if not h.tested]
    
    def mark_hypothesis_tested(
        self, 
        hypothesis_id: str, 
        result: str  # "confirmed" or "rejected"
    ) -> None:
        """Mark a hypothesis as tested with result."""
        for h in self.hypotheses:
            if h.id == hypothesis_id:
                h.tested = True
                h.test_result = result
                break
        if self.persist:
            self._save_hypotheses()
    
    # ========== Failure Learning ==========
    
    def record_failure(
        self, 
        action: str, 
        input_params: Dict[str, Any], 
        error: str
    ) -> None:
        """
        Record a failed action for future avoidance.
        
        This enables auto-learning: if an action fails with certain
        parameters, the agent won't retry the same thing.
        """
        # Extract target pattern for matching
        target = (
            input_params.get("target") or 
            input_params.get("domain") or 
            input_params.get("url") or
            "unknown"
        )
        
        failure = FailedAction(
            action=action,
            input_params=input_params,
            error=str(error)[:500],  # Truncate long errors
            timestamp=datetime.now().isoformat(),
            target_pattern=target
        )
        
        self.failed_actions.append(failure)
        
        if self.persist:
            self._save_failures()
        
        print(f"  📝 Recorded failure: {action} on {target}")
    
    def get_learning_hint(
        self, 
        action: str, 
        params: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Check if this action has failed before and get learning hint.
        
        Returns:
            Dict with 'should_retry', 'suggestion', 'original_error' if failed before
            None if no previous failure
        """
        target = (
            params.get("target") or 
            params.get("domain") or 
            params.get("url") or
            ""
        )
        
        for failure in self.failed_actions:
            if failure.action == action:
                # Same target?
                if failure.target_pattern == target or self._params_similar(failure.input_params, params):
                    return {
                        "should_retry": failure.can_retry(),
                        "suggestion": failure.suggest_fix(),
                        "original_error": failure.error[:100],
                        "retry_count": failure.retry_count,
                        "max_retries": failure.max_retries
                    }
        
        return None
    
    def increment_retry(self, action: str, target: str) -> None:
        """Increment retry count for a failed action."""
        for failure in self.failed_actions:
            if failure.action == action and failure.target_pattern == target:
                failure.retry_count += 1
                if self.persist:
                    self._save_failures()
                return
    
    def _params_similar(self, p1: Dict, p2: Dict) -> bool:
        """Check if two parameter sets are similar enough."""
        # Same target/domain/url?
        for key in ["target", "domain", "url"]:
            if p1.get(key) and p1.get(key) == p2.get(key):
                return True
        return False
    
    def clear_failures(self) -> None:
        """Clear all recorded failures (reset learning)."""
        self.failed_actions.clear()
        if self.persist:
            self._save_failures()
    
    # ========== Context Building ==========
    
    def build_context_summary(self, max_facts: int = 50) -> str:
        """
        Build a summary of known facts for LLM context.
        
        This replaces raw observations with structured knowledge.
        """
        lines = []
        
        # Subdomains
        subs = self.get_subdomains()
        if subs:
            lines.append(f"KNOWN SUBDOMAINS ({len(subs)}): {', '.join(subs[:10])}")
            if len(subs) > 10:
                lines.append(f"  ... and {len(subs) - 10} more")
        
        # Open ports
        ports = self.get_open_ports()
        if ports:
            lines.append(f"OPEN PORTS ({len(ports)} hosts):")
            for host, port_list in list(ports.items())[:10]:
                lines.append(f"  {host}: {', '.join(map(str, sorted(port_list)))}")
        
        # Vulnerabilities
        vulns = self.get_vulnerabilities()
        if vulns:
            lines.append(f"VULNERABILITIES ({len(vulns)}):")
            for v in vulns[:5]:
                severity = v.data.get("severity", "unknown")
                name = v.data.get("name", v.data.get("cve_id", "unknown"))
                lines.append(f"  [{severity.upper()}] {v.target}: {name}")
        
        # Untested hypotheses
        hypos = self.get_untested_hypotheses()
        if hypos:
            lines.append(f"ATTACK HYPOTHESES ({len(hypos)} untested):")
            for h in hypos[:3]:
                lines.append(f"  [{h.risk_level.upper()}] {h.target}: {h.hypothesis}")
        
        # LESSONS LEARNED from failures (for smarter decisions)
        if self.failed_actions:
            lines.append(f"\n⚡ LESSONS FROM PAST FAILURES ({len(self.failed_actions)}):")
            for f in self.failed_actions[-5:]:
                suggestion = f.suggest_fix()
                can_retry = "✅ Can retry" if f.can_retry() else "❌ Max retries"
                lines.append(f"  • {f.action} on {f.target_pattern}: {suggestion} [{can_retry}]")
        
        return "\n".join(lines) if lines else "No facts discovered yet."
    
    # ========== Persistence ==========
    
    def save(self) -> None:
        """Save all memory to disk (fails silently on permission errors)."""
        self._save_facts()
        self._save_hypotheses()
        self._save_failures()
    
    def load(self) -> None:
        """Load memory from disk."""
        self._load_facts()
        self._load_hypotheses()
        self._load_failures()
    
    def _save_facts(self) -> None:
        try:
            with open(self.facts_file, 'w') as f:
                json.dump([fact.to_dict() for fact in self.facts], f, indent=2)
        except PermissionError:
            # Fail silently - don't crash the agent
            pass
        except Exception:
            pass
    
    def _load_facts(self) -> None:
        if self.facts_file.exists():
            try:
                with open(self.facts_file, 'r') as f:
                    data = json.load(f)
                    self.facts = [Fact.from_dict(d) for d in data]
            except (json.JSONDecodeError, KeyError, PermissionError):
                self.facts = []
    
    def _save_hypotheses(self) -> None:
        try:
            with open(self.hypotheses_file, 'w') as f:
                json.dump([h.to_dict() for h in self.hypotheses], f, indent=2)
        except PermissionError:
            pass
        except Exception:
            pass
    
    def _load_hypotheses(self) -> None:
        if self.hypotheses_file.exists():
            try:
                with open(self.hypotheses_file, 'r') as f:
                    data = json.load(f)
                    self.hypotheses = [Hypothesis.from_dict(d) for d in data]
            except (json.JSONDecodeError, KeyError, PermissionError):
                self.hypotheses = []
    
    def _save_failures(self) -> None:
        try:
            with open(self.failures_file, 'w') as f:
                json.dump([fa.to_dict() for fa in self.failed_actions], f, indent=2)
        except PermissionError:
            pass
        except Exception:
            pass
    
    def _load_failures(self) -> None:
        if self.failures_file.exists():
            try:
                with open(self.failures_file, 'r') as f:
                    data = json.load(f)
                    self.failed_actions = [FailedAction.from_dict(d) for d in data]
            except (json.JSONDecodeError, KeyError, PermissionError):
                self.failed_actions = []
    
    # ========== Conversation Memory (LangChain) ==========
    
    def save_conversation_turn(self, user_input: str, ai_output: str) -> None:
        """Save a conversation turn to LangChain memory."""
        if self.chat_history:
            try:
                self.chat_history.add_user_message(user_input)
                self.chat_history.add_ai_message(ai_output)
            except Exception as e:
                print(f"⚠️ Failed to save conversation: {e}")
    
    def get_conversation_history(self) -> str:
        """Get conversation history."""
        if not self.chat_history:
            return ""
        
        try:
            messages = self.chat_history.messages
            lines = []
            for msg in messages[-10:]:  # Last 10 messages
                if hasattr(msg, 'content'):
                    role = "User" if isinstance(msg, HumanMessage) else "SNODE"
                    lines.append(f"{role}: {msg.content[:200]}")
            return "\n".join(lines)
        except Exception as e:
            print(f"⚠️ Memory error: {e}")
            return ""
    
    def get_conversation_summary(self) -> str:
        """Get summary of conversation (uses LLM to summarize if long)."""
        if not self.chat_history or not self.llm:
            return ""
        
        try:
            messages = self.chat_history.messages
            if len(messages) <= 6:
                return ""  # Not enough to summarize
            
            # Summarize older messages (all but last 6)
            older_msgs = messages[:-6]
            if not older_msgs:
                return ""
            
            text_to_summarize = "\n".join([
                f"{'User' if isinstance(m, HumanMessage) else 'SNODE'}: {m.content[:100]}"
                for m in older_msgs
            ])
            
            # Use LLM to summarize
            summary_prompt = f"Summarize this security assessment conversation in 2-3 sentences:\n\n{text_to_summarize}"
            response = self.llm.invoke(summary_prompt)
            return response.content if hasattr(response, 'content') else str(response)
        except:
            return ""
    
    def get_full_context(self) -> str:
        """Get full context combining conversation history and pentest facts."""
        lines = []
        
        # Add conversation summary
        summary = self.get_conversation_summary()
        if summary:
            lines.append(f"CONVERSATION SUMMARY:\n{summary}")
        
        # Add recent history
        history = self.get_conversation_history()
        if history:
            lines.append(f"\nRECENT MESSAGES:\n{history}")
        
        # Add pentest context
        if self.facts:
            lines.append(f"\nFACTS DISCOVERED: {len(self.facts)}")
            # Group by type
            for fact_type in set(f.fact_type for f in self.facts):
                count = len([f for f in self.facts if f.fact_type == fact_type])
                lines.append(f"  • {fact_type}: {count}")
        
        if self.hypotheses:
            untested = [h for h in self.hypotheses if not h.tested]
            lines.append(f"\nHYPOTHESES: {len(self.hypotheses)} ({len(untested)} untested)")
        
        return "\n".join(lines) if lines else "No context yet"
    
    def clear_all(self) -> None:
        """Clear all memory (facts, hypotheses, failures, conversation)."""
        self.facts.clear()
        self.hypotheses.clear()
        self.failed_actions.clear()
        if self.chat_history:
            self.chat_history.clear()
        if self.persist:
            self.save()
    
    def __len__(self) -> int:
        return len(self.facts)
    
    def __repr__(self) -> str:
        return f"AttackMemory(facts={len(self.facts)}, hypotheses={len(self.hypotheses)}, failures={len(self.failed_actions)})"


# =============================================================================
# LETTA-STYLE MEMORY ARCHITECTURE
# =============================================================================

@dataclass
class CoreMemory:
    """
    RAM-like memory: Active context within LLM context window.
    
    This is the "working memory" - what the agent is actively thinking about.
    Contents are included in every LLM prompt.
    """
    current_query: str = ""
    active_targets: List[str] = field(default_factory=list)
    recent_observations: List[str] = field(default_factory=list)  # Last 5 tool results
    goals: List[str] = field(default_factory=list)
    max_observations: int = 5
    
    def add_observation(self, obs: str) -> None:
        """Add observation, maintaining sliding window."""
        self.recent_observations.append(obs[:500])  # Truncate for context size
        if len(self.recent_observations) > self.max_observations:
            self.recent_observations.pop(0)
    
    def set_query(self, query: str) -> None:
        """Set current query and extract targets."""
        self.current_query = query
        # Auto-extract targets from query
        import re
        domains = re.findall(r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}', query)
        if domains:
            self.active_targets = domains[:3]  # Max 3 active targets
    
    def add_goal(self, goal: str) -> None:
        """Add a goal to pursue."""
        if goal not in self.goals:
            self.goals.append(goal)
            if len(self.goals) > 5:
                self.goals.pop(0)
    
    def to_context_string(self) -> str:
        """Convert to string for LLM context."""
        lines = ["=== CORE MEMORY (Active) ==="]
        if self.current_query:
            lines.append(f"Query: {self.current_query}")
        if self.active_targets:
            lines.append(f"Targets: {', '.join(self.active_targets)}")
        if self.goals:
            lines.append(f"Goals: {'; '.join(self.goals)}")
        if self.recent_observations:
            lines.append("Recent Results:")
            for obs in self.recent_observations[-3:]:
                lines.append(f"  • {obs[:100]}...")
        return "\n".join(lines)
    
    def clear(self) -> None:
        """Clear core memory for new session."""
        self.current_query = ""
        self.active_targets.clear()
        self.recent_observations.clear()
        self.goals.clear()


class ArchivalMemory:
    """
    Disk-like memory: Persistent storage with semantic search.
    
    Facts are stored here and retrieved via TF-IDF similarity search.
    This is the "long-term memory" - what persists across sessions.
    """
    
    def __init__(self, facts: List[Fact]):
        self.facts = facts
        self._tfidf_vectorizer = None
        self._tfidf_matrix = None
        self._index_dirty = True
    
    def _build_index(self) -> None:
        """Build TF-IDF index for semantic search."""
        if not self.facts:
            return
        
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            
            # Convert facts to searchable documents
            documents = []
            for fact in self.facts:
                doc = f"{fact.fact_type} {fact.target} {json.dumps(fact.data)} {fact.source_tool}"
                documents.append(doc)
            
            self._tfidf_vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
            self._tfidf_matrix = self._tfidf_vectorizer.fit_transform(documents)
            self._index_dirty = False
        except ImportError:
            # Fallback to simple keyword matching
            self._tfidf_vectorizer = None
    
    def search(self, query: str, top_k: int = 5) -> List[Fact]:
        """Semantic search for relevant facts."""
        if not self.facts:
            return []
        
        if self._index_dirty:
            self._build_index()
        
        if self._tfidf_vectorizer is None:
            # Fallback: simple keyword matching
            return self._keyword_search(query, top_k)
        
        try:
            from sklearn.metrics.pairwise import cosine_similarity
            
            query_vec = self._tfidf_vectorizer.transform([query])
            similarities = cosine_similarity(query_vec, self._tfidf_matrix).flatten()
            
            # Get top-k indices
            top_indices = similarities.argsort()[-top_k:][::-1]
            
            results = []
            for idx in top_indices:
                if similarities[idx] > 0.1:  # Minimum similarity threshold
                    results.append(self.facts[idx])
            return results
        except Exception:
            return self._keyword_search(query, top_k)
    
    def _keyword_search(self, query: str, top_k: int) -> List[Fact]:
        """Simple keyword-based search fallback."""
        query_lower = query.lower()
        scored_facts = []
        
        for fact in self.facts:
            score = 0
            fact_text = f"{fact.fact_type} {fact.target} {json.dumps(fact.data)}".lower()
            
            for word in query_lower.split():
                if word in fact_text:
                    score += 1
            
            if score > 0:
                scored_facts.append((score, fact))
        
        scored_facts.sort(key=lambda x: x[0], reverse=True)
        return [f for _, f in scored_facts[:top_k]]
    
    def add_fact(self, fact: Fact) -> None:
        """Add fact and mark index as dirty."""
        self.facts.append(fact)
        self._index_dirty = True
    
    def remove_fact(self, fact_id: str) -> bool:
        """Remove fact by ID."""
        for i, fact in enumerate(self.facts):
            if fact.id == fact_id:
                self.facts.pop(i)
                self._index_dirty = True
                return True
        return False


class MemoryManager:
    """
    Letta-style Memory Manager: Coordinates Core ↔ Archival operations.
    
    Provides LLM-callable tools for memory management:
    - read_memory: Search archival memory
    - write_memory: Store new facts
    - forget_memory: Remove outdated facts
    - summarize_target: Get comprehensive target profile
    """
    
    def __init__(self, attack_memory: 'AttackMemory'):
        self.attack_memory = attack_memory
        self.core = CoreMemory()
        self.archival = ArchivalMemory(attack_memory.facts)
    
    def read_memory(self, query: str) -> str:
        """
        Search archival memory for relevant past findings.
        
        LLM Tool: read_memory
        Returns formatted string of relevant facts.
        """
        results = self.archival.search(query, top_k=5)
        
        if not results:
            return f"No memories found for: {query}"
        
        output = f"=== MEMORY RECALL: {query} ===\n"
        output += f"Found {len(results)} relevant memories:\n\n"
        
        for fact in results:
            output += f"[{fact.fact_type.upper()}] {fact.target}\n"
            output += f"  Data: {json.dumps(fact.data)}\n"
            output += f"  Source: {fact.source_tool} @ {fact.timestamp[:10]}\n\n"
        
        return output
    
    def write_memory(self, fact_type: str, target: str, data: Dict[str, Any], source: str = "agent") -> str:
        """
        Store important findings to archival memory.
        
        LLM Tool: write_memory
        """
        fact = Fact.create(
            fact_type=fact_type,
            target=target,
            data=data,
            source_tool=source,
            confidence=0.9
        )
        
        self.attack_memory.add_fact(fact)
        self.archival.add_fact(fact)
        
        return f"✅ Stored memory: [{fact_type}] {target} - {json.dumps(data)[:100]}"
    
    def forget_memory(self, fact_id: str) -> str:
        """
        Remove outdated or incorrect fact from memory.
        
        LLM Tool: forget_memory
        """
        # Remove from archival
        if self.archival.remove_fact(fact_id):
            # Remove from attack_memory too
            self.attack_memory.facts = [f for f in self.attack_memory.facts if f.id != fact_id]
            if self.attack_memory.persist:
                self.attack_memory._save_facts()
            return f"✅ Forgot memory: {fact_id}"
        
        return f"❌ Memory not found: {fact_id}"
    
    def summarize_target(self, domain: str) -> str:
        """
        Get comprehensive profile of a target from all memories.
        
        LLM Tool: summarize_target
        """
        # Search for all facts related to target
        relevant_facts = [f for f in self.attack_memory.facts if domain in f.target]
        
        if not relevant_facts:
            return f"No memories for target: {domain}"
        
        output = f"=== TARGET PROFILE: {domain} ===\n\n"
        
        # Group by fact type
        by_type: Dict[str, List[Fact]] = {}
        for fact in relevant_facts:
            if fact.fact_type not in by_type:
                by_type[fact.fact_type] = []
            by_type[fact.fact_type].append(fact)
        
        for fact_type, facts in by_type.items():
            output += f"📌 {fact_type.upper()} ({len(facts)}):\n"
            for fact in facts[:5]:
                output += f"  • {json.dumps(fact.data)[:80]}\n"
            if len(facts) > 5:
                output += f"  ... and {len(facts) - 5} more\n"
            output += "\n"
        
        # Add hypotheses
        target_hypos = [h for h in self.attack_memory.hypotheses if domain in h.target]
        if target_hypos:
            output += f"🎯 ATTACK HYPOTHESES ({len(target_hypos)}):\n"
            for h in target_hypos[:3]:
                status = "✅ Tested" if h.tested else "⏳ Pending"
                output += f"  [{h.risk_level.upper()}] {h.hypothesis} - {status}\n"
        
        return output
    
    def get_full_context(self) -> str:
        """Get combined Core + Archival context for LLM."""
        context = self.core.to_context_string()
        context += "\n\n"
        context += self.attack_memory.build_context_summary(max_facts=30)
        return context


# ============================================================
# SINGLETON: AttackMemory instance
# ============================================================

_attack_memory: Optional[AttackMemory] = None


def get_attack_memory() -> AttackMemory:
    """Get or create the attack memory singleton."""
    global _attack_memory
    if _attack_memory is None:
        _attack_memory = AttackMemory()
    return _attack_memory


def reset_attack_memory() -> None:
    """Reset attack memory (for new engagement)."""
    global _attack_memory
    if _attack_memory:
        _attack_memory.clear_all()
    _attack_memory = None
