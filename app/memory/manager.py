"""
Memory Manager for SNODE.

Combines PostgreSQL (exact) and Vector DB (semantic) memory.
"""
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from .postgres import PostgresMemory, get_postgres
from .vector import VectorMemory, get_vector


class MemoryManager:
    """
    Combined memory manager.
    
    - PostgreSQL: Exact conversation history, sessions, findings
    - Vector DB: Semantic search for relevant context
    """
    
    def __init__(self, auto_cleanup_days: int = 30):
        self.postgres = get_postgres()
        self.vector = get_vector()
        self.session_id: Optional[str] = None
        self.target_domain: Optional[str] = None
        self.auto_cleanup_days = auto_cleanup_days
        
        # Run cleanup on init (async-friendly)
        self._cleanup_old_data()
    
    def _cleanup_old_data(self):
        """Clean up old data based on retention policy."""
        try:
            pg_deleted = self.postgres.cleanup_old_data(self.auto_cleanup_days)
            vec_deleted = self.vector.clear_old(self.auto_cleanup_days)
            if pg_deleted or vec_deleted:
                print(f"🧹 Memory cleanup: {pg_deleted} sessions, {vec_deleted} vectors deleted")
        except Exception as e:
            print(f"⚠️ Cleanup error: {e}")
    
    # ==================== Session Management ====================
    
    def start_session(self, target_domain: str = None) -> str:
        """
        Start a new session.
        
        Call this when terminal starts.
        """
        self.target_domain = target_domain
        self.session_id = self.postgres.create_session(target_domain)
        print(f"📋 New session: {self.session_id}")
        return self.session_id
    
    def resume_session(self, session_id: str = None) -> Optional[Dict]:
        """
        Resume a previous session.
        
        Returns session data with context if found.
        """
        if session_id:
            # Resume specific session (supports partial UUID)
            full_session_id, context = self.postgres.get_session_context(session_id)
            if full_session_id and context:
                self.session_id = full_session_id
                # Get domain from context (primary)
                self.target_domain = context.get("last_domain")
                print(f"📋 Resumed session: {full_session_id}")
                return {"session_id": full_session_id, "context": context}
        else:
            # Resume last session
            last = self.postgres.get_last_session()
            if last:
                self.session_id = str(last["session_id"])
                context = last.get("context", {})
                # Get domain from context (primary) or column (fallback)
                self.target_domain = context.get("last_domain") or last.get("target_domain")
                domain_display = self.target_domain or "no domain"
                print(f"📋 Resumed last session: {self.session_id} ({domain_display})")
                return {
                    "session_id": self.session_id,
                    "context": context,
                    "summary": last.get("summary"),
                    "started_at": last.get("started_at")
                }
        
        return None
    
    def get_or_create_session(self, target_domain: str = None) -> str:
        """Get current session or create new one."""
        if self.session_id:
            return self.session_id
        return self.start_session(target_domain)
    
    # ==================== Message Handling ====================
    
    def save_turn(
        self,
        user_message: str,
        assistant_message: str,
        tools_used: List[str] = None,
        context: Dict = None
    ):
        """
        Save a conversation turn (user + assistant).
        
        Saves to both PostgreSQL and Vector DB.
        """
        session = self.get_or_create_session()
        domain = context.get("last_domain") if context else self.target_domain
        
        # Save to PostgreSQL (exact)
        self.postgres.save_message(
            session_id=session,
            role="user",
            content=user_message,
            tools_used=None,
            context=context
        )
        self.postgres.save_message(
            session_id=session,
            role="assistant",
            content=assistant_message,
            tools_used=tools_used,
            context=context
        )
        
        # Save to Vector DB (semantic)
        self.vector.add_message(
            session_id=session,
            role="user",
            content=user_message,
            domain=domain
        )
        self.vector.add_message(
            session_id=session,
            role="assistant",
            content=assistant_message,
            domain=domain,
            tools=tools_used
        )
        
        # Update session activity
        self.postgres.update_session_activity(session, context)
    
    def save_finding(
        self,
        finding_type: str,
        data: Dict,
        domain: str = None
    ):
        """Save a structured finding."""
        session = self.get_or_create_session()
        domain = domain or self.target_domain
        
        self.postgres.save_finding(
            session_id=session,
            domain=domain,
            finding_type=finding_type,
            data=data
        )
    
    # ==================== Context Retrieval ====================
    
    def get_context_for_query(
        self,
        query: str,
        domain: str = None,
        include_history: bool = True,
        include_semantic: bool = True
    ) -> Dict:
        """
        Get combined context for LLM.
        
        Returns:
            Dict with:
            - history: Recent messages from current session
            - semantic: Relevant past conversations
            - findings: Structured findings for domain
        """
        context = {}
        domain = domain or self.target_domain
        
        # 1. Recent history from current session
        if include_history and self.session_id:
            history = self.postgres.get_messages(self.session_id, limit=10)
            context["history"] = [
                {"role": m["role"], "content": m["content"]}
                for m in history
            ]
        
        # 2. Semantic search for relevant past conversations
        if include_semantic:
            semantic = self.vector.search(query, n_results=5, domain=domain)
            context["semantic"] = [
                {"content": s["content"], "role": s["metadata"].get("role")}
                for s in semantic
            ]
        
        # 3. Findings for domain
        if domain:
            findings = self.postgres.get_findings(domain=domain)
            context["findings"] = [
                {"type": f["finding_type"], "data": f["data"]}
                for f in findings[:20]
            ]
        
        return context
    
    def format_context_for_llm(
        self,
        query: str,
        domain: str = None
    ) -> str:
        """Format context as string for LLM prompt."""
        ctx = self.get_context_for_query(query, domain)
        parts = []
        
        # Recent history
        if ctx.get("history"):
            parts.append("RECENT CONVERSATION:")
            for msg in ctx["history"][-5:]:
                role = "User" if msg["role"] == "user" else "Assistant"
                content = msg["content"][:200]
                parts.append(f"  {role}: {content}")
        
        # Semantic memory
        if ctx.get("semantic"):
            parts.append("\nRELEVANT PAST KNOWLEDGE:")
            for mem in ctx["semantic"][:3]:
                content = mem["content"][:150]
                parts.append(f"  - {content}")
        
        # Findings
        if ctx.get("findings"):
            parts.append("\nKNOWN FINDINGS:")
            types = {}
            for f in ctx["findings"]:
                t = f["type"]
                types[t] = types.get(t, 0) + 1
            for t, count in types.items():
                parts.append(f"  - {t}: {count} items")
        
        return "\n".join(parts)
    
    # ==================== Session Summary ====================
    
    def generate_session_summary(self, llm=None) -> str:
        """Generate and save session summary."""
        if not self.session_id:
            return ""
        
        # Get all messages from session
        messages = self.postgres.get_messages(self.session_id, limit=50)
        
        if not messages:
            return ""
        
        # Build summary prompt
        msg_text = "\n".join([
            f"{m['role']}: {m['content'][:100]}"
            for m in messages
        ])
        
        if llm:
            summary = llm.generate(f"""
Summarize this security assessment session in 2-3 sentences:

{msg_text}

Summary:""", timeout=30)
        else:
            # Simple summary without LLM
            tools = set()
            for m in messages:
                if m.get("tools_used"):
                    tools.update(m["tools_used"])
            
            summary = f"Session with {len(messages)} messages. Tools: {', '.join(tools) or 'none'}"
        
        self.postgres.set_session_summary(self.session_id, summary)
        return summary
    
    def end_session(self, llm=None):
        """End current session with summary."""
        if self.session_id:
            self.generate_session_summary(llm)
            print(f"📋 Session ended: {self.session_id[:8]}...")
        self.session_id = None
        self.target_domain = None


# Singleton
_manager_instance = None

def get_memory_manager() -> MemoryManager:
    """Get or create memory manager instance."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = MemoryManager(auto_cleanup_days=30)
    return _manager_instance
