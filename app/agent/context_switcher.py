"""
Multi-Context Support for SNODE (Phase 3)

Allows managing multiple conversation contexts simultaneously.
Each context has its own:
- Target domain
- History (topic-based)
- Agent state
- Context data

Inspired by agent-zero's AgentContext pattern.
"""
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

from app.memory.topics import History
from app.agent.graph import AgentState


@dataclass
class ConversationContext:
    """A single conversation context."""
    id: str
    target_domain: str
    history: History
    state: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def update(self):
        """Update timestamp."""
        self.updated_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "target_domain": self.target_domain,
            "history": self.history.to_dict() if self.history else None,
            "state": self.state,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any], agent: Optional[Any] = None) -> "ConversationContext":
        """Deserialize from dictionary."""
        ctx = ConversationContext(
            id=data["id"],
            target_domain=data["target_domain"],
            state=data.get("state", {}),
            metadata=data.get("metadata", {})
        )
        ctx.created_at = datetime.fromisoformat(data["created_at"])
        ctx.updated_at = datetime.fromisoformat(data.get("updated_at", data["created_at"]))
        
        # Load history
        if data.get("history"):
            ctx.history = History.from_dict(data["history"], agent=agent)
        else:
            ctx.history = History(agent=agent)
        
        return ctx


class ContextManager:
    """
    Manages multiple conversation contexts.
    
    Allows switching between different targets/conversations.
    """
    
    def __init__(self, persistence_dir: Optional[Path] = None):
        self._contexts: Dict[str, ConversationContext] = {}
        self._current_id: Optional[str] = None
        self._agent = None  # Agent instance for history compression
        
        # Persistence
        if persistence_dir:
            self.persistence_dir = Path(persistence_dir)
            self.persistence_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.persistence_dir = None
    
    def set_agent(self, agent):
        """Set agent instance for history compression."""
        self._agent = agent
        for ctx in self._contexts.values():
            if ctx.history:
                ctx.history.agent = agent
    
    def create_context(self, target_domain: str, metadata: Dict[str, Any] = None) -> str:
        """
        Create a new conversation context.
        
        Returns:
            Context ID
        """
        ctx_id = str(uuid.uuid4())[:8]
        ctx = ConversationContext(
            id=ctx_id,
            target_domain=target_domain,
            history=History(agent=self._agent),
            metadata=metadata or {}
        )
        self._contexts[ctx_id] = ctx
        
        # Set as current if no current context
        if not self._current_id:
            self._current_id = ctx_id
        
        # Persist
        self._save_context(ctx)
        
        return ctx_id
    
    def get_context(self, ctx_id: Optional[str] = None) -> Optional[ConversationContext]:
        """Get context by ID, or current context if None."""
        if ctx_id:
            return self._contexts.get(ctx_id)
        return self._contexts.get(self._current_id) if self._current_id else None
    
    def get_current(self) -> Optional[ConversationContext]:
        """Get current context."""
        return self.get_context()
    
    def switch_to(self, ctx_id: str) -> bool:
        """
        Switch to a different context.
        
        Returns:
            True if switch successful, False if context not found
        """
        if ctx_id not in self._contexts:
            return False
        
        self._current_id = ctx_id
        return True
    
    def list_contexts(self) -> List[Dict[str, Any]]:
        """List all contexts with summary info."""
        contexts = []
        for ctx_id, ctx in self._contexts.items():
            contexts.append({
                "id": ctx_id,
                "target_domain": ctx.target_domain,
                "is_current": ctx_id == self._current_id,
                "created_at": ctx.created_at.isoformat(),
                "updated_at": ctx.updated_at.isoformat(),
                "message_count": len(ctx.history.current.messages) if ctx.history and ctx.history.current else 0,
                "topic_count": len(ctx.history.topics) if ctx.history else 0,
            })
        
        # Sort by updated_at (most recent first)
        contexts.sort(key=lambda x: x["updated_at"], reverse=True)
        return contexts
    
    def delete_context(self, ctx_id: str) -> bool:
        """Delete a context."""
        if ctx_id not in self._contexts:
            return False
        
        # Don't delete if it's the current context
        if ctx_id == self._current_id:
            # Switch to another context first
            other_ids = [cid for cid in self._contexts.keys() if cid != ctx_id]
            if other_ids:
                self._current_id = other_ids[0]
            else:
                self._current_id = None
        
        del self._contexts[ctx_id]
        
        # Delete persistence file
        if self.persistence_dir:
            ctx_file = self.persistence_dir / f"{ctx_id}.json"
            if ctx_file.exists():
                ctx_file.unlink()
        
        return True
    
    def _save_context(self, ctx: ConversationContext):
        """Save context to disk."""
        if not self.persistence_dir:
            return
        
        ctx_file = self.persistence_dir / f"{ctx.id}.json"
        try:
            with open(ctx_file, 'w', encoding='utf-8') as f:
                json.dump(ctx.to_dict(), f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"  ⚠️ Failed to save context {ctx.id}: {e}")
    
    def _load_context(self, ctx_id: str) -> Optional[ConversationContext]:
        """Load context from disk."""
        if not self.persistence_dir:
            return None
        
        ctx_file = self.persistence_dir / f"{ctx_id}.json"
        if not ctx_file.exists():
            return None
        
        try:
            with open(ctx_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return ConversationContext.from_dict(data, agent=self._agent)
        except Exception as e:
            print(f"  ⚠️ Failed to load context {ctx_id}: {e}")
            return None
    
    def load_all_contexts(self):
        """Load all contexts from disk."""
        if not self.persistence_dir:
            return
        
        for ctx_file in self.persistence_dir.glob("*.json"):
            try:
                ctx_id = ctx_file.stem
                ctx = self._load_context(ctx_id)
                if ctx:
                    self._contexts[ctx_id] = ctx
            except Exception as e:
                print(f"  ⚠️ Failed to load context from {ctx_file}: {e}")
    
    def save_all_contexts(self):
        """Save all contexts to disk."""
        for ctx in self._contexts.values():
            self._save_context(ctx)


# Singleton
_context_manager_instance = None


def get_context_manager(persistence_dir: Optional[Path] = None) -> ContextManager:
    """Get or create context manager instance."""
    global _context_manager_instance
    if _context_manager_instance is None:
        _context_manager_instance = ContextManager(persistence_dir=persistence_dir)
    return _context_manager_instance
