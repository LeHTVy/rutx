"""
Message History Manager for SNODE AI
Manages conversation history across multiple agents with automatic persistence
Based on CAI's message_history system
"""

from typing import List, Dict, Optional, Any
from datetime import datetime
import json


class Message:
    """Represents a single message in the conversation"""
    
    def __init__(
        self,
        role: str,
        content: str,
        agent_name: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.role = role  # "user", "assistant", "system", "tool"
        self.content = content
        self.agent_name = agent_name
        self.timestamp = timestamp or datetime.now()
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for LLM API"""
        return {
            "role": self.role,
            "content": self.content
        }
    
    def to_full_dict(self) -> Dict:
        """Convert to full dictionary with metadata"""
        return {
            "role": self.role,
            "content": self.content,
            "agent_name": self.agent_name,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


class MessageHistoryManager:
    """
    Manages conversation history across agents
    
    Features:
    - Automatic message tracking
    - Agent-specific context
    - History transfer on handoffs
    - Database persistence
    - Configurable max history
    """
    
    def __init__(self, max_messages: int = 50, session_id: Optional[str] = None):
        """
        Initialize message history manager
        
        Args:
            max_messages: Maximum number of messages to keep in memory
            session_id: Optional session ID for database persistence
        """
        self.max_messages = max_messages
        self.session_id = session_id
        self.messages: List[Message] = []
        self.agent_contexts: Dict[str, Dict] = {}  # Agent-specific metadata
    
    def add_message(
        self,
        role: str,
        content: str,
        agent_name: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> Message:
        """
        Add a message to history
        
        Args:
            role: Message role (user/assistant/system/tool)
            content: Message content
            agent_name: Name of the agent (if assistant)
            metadata: Additional metadata
        
        Returns:
            Created Message object
        """
        message = Message(
            role=role,
            content=content,
            agent_name=agent_name,
            metadata=metadata
        )
        
        self.messages.append(message)
        
        # Prune if exceeds max
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]
        
        return message
    
    def get_messages(
        self,
        role: Optional[str] = None,
        agent_name: Optional[str] = None,
        last_n: Optional[int] = None
    ) -> List[Message]:
        """
        Get messages with optional filtering
        
        Args:
            role: Filter by role
            agent_name: Filter by agent name
            last_n: Return only last N messages
        
        Returns:
            Filtered list of messages
        """
        messages = self.messages
        
        if role:
            messages = [m for m in messages if m.role == role]
        
        if agent_name:
            messages = [m for m in messages if m.agent_name == agent_name]
        
        if last_n:
            messages = messages[-last_n:]
        
        return messages
    
    def get_history_for_llm(self, last_n: Optional[int] = None) -> List[Dict]:
        """
        Get message history formatted for LLM API
        
        Args:
            last_n: Return only last N messages
        
        Returns:
            List of message dictionaries suitable for LLM
        """
        messages = self.messages[-last_n:] if last_n else self.messages
        return [msg.to_dict() for msg in messages]
    
    def get_history_for_agent(self, agent_name: str) -> List[Dict]:
        """
        Get relevant history for a specific agent
        
        Args:
            agent_name: Name of the agent
        
        Returns:
            Message history relevant to this agent
        """
        # Get all messages + messages from this agent
        relevant = []
        for msg in self.messages:
            if msg.role == "user" or msg.role == "system":
                relevant.append(msg.to_dict())
            elif msg.agent_name == agent_name:
                relevant.append(msg.to_dict())
        
        return relevant
    
    def transfer_to_agent(self, from_agent: str, to_agent: str) -> None:
        """
        Transfer history context during agent handoff
        
        Args:
            from_agent: Source agent name
            to_agent: Destination agent name
        """
        # Mark the handoff in metadata
        handoff_msg = Message(
            role="system",
            content=f"Handoff from {from_agent} to {to_agent}",
            metadata={
                "type": "handoff",
                "from_agent": from_agent,
                "to_agent": to_agent
            }
        )
        self.messages.append(handoff_msg)
        
        # Transfer agent context
        if from_agent in self.agent_contexts:
            self.agent_contexts[to_agent] = self.agent_contexts[from_agent].copy()
    
    def set_agent_context(self, agent_name: str, context: Dict) -> None:
        """
        Set context metadata for an agent
        
        Args:
            agent_name: Agent name
            context: Context dictionary
        """
        self.agent_contexts[agent_name] = context
    
    def get_agent_context(self, agent_name: str) -> Dict:
        """
        Get context metadata for an agent
        
        Args:
            agent_name: Agent name
        
        Returns:
            Context dictionary or empty dict
        """
        return self.agent_contexts.get(agent_name, {})
    
    def save_to_database(self, session_id: Optional[str] = None) -> bool:
        """
        Persist message history to database
        
        Args:
            session_id: Session ID (uses self.session_id if not provided)
        
        Returns:
            True if successful
        """
        session_id = session_id or self.session_id
        if not session_id:
            return False
        
        try:
            from database.agent_persistence import AgentPersistence
            
            persistence = AgentPersistence()
            persistence.save_conversation_history(
                session_id=session_id,
                messages=[msg.to_full_dict() for msg in self.messages],
                agent_contexts=self.agent_contexts
            )
            return True
        except ImportError:
            # Database module not yet implemented, skip
            return False
        except Exception as e:
            print(f"⚠️  Failed to save history to database: {e}")
            return False
    
    def load_from_database(self, session_id: str) -> bool:
        """
        Load message history from database
        
        Args:
            session_id: Session ID to load
        
        Returns:
            True if successful
        """
        try:
            from database.agent_persistence import AgentPersistence
            
            persistence = AgentPersistence()
            data = persistence.load_conversation_history(session_id)
            
            if data:
                # Recreate messages
                self.messages = []
                for msg_dict in data.get("messages", []):
                    msg = Message(
                        role=msg_dict["role"],
                        content=msg_dict["content"],
                        agent_name=msg_dict.get("agent_name"),
                        timestamp=datetime.fromisoformat(msg_dict["timestamp"]),
                        metadata=msg_dict.get("metadata", {})
                    )
                    self.messages.append(msg)
                
                # Restore agent contexts
                self.agent_contexts = data.get("agent_contexts", {})
                self.session_id = session_id
                return True
            
            return False
        except ImportError:
            return False
        except Exception as e:
            print(f"⚠️  Failed to load history from database: {e}")
            return False
    
    def clear(self) -> None:
        """Clear all message history"""
        self.messages.clear()
        self.agent_contexts.clear()
    
    def get_summary(self) -> str:
        """Get a summary of the conversation history"""
        total = len(self.messages)
        by_role = {}
        by_agent = {}
        
        for msg in self.messages:
            by_role[msg.role] = by_role.get(msg.role, 0) + 1
            if msg.agent_name:
                by_agent[msg.agent_name] = by_agent.get(msg.agent_name, 0) + 1
        
        summary = f"Total messages: {total}\n"
        summary += f"By role: {by_role}\n"
        if by_agent:
            summary += f"By agent: {by_agent}\n"
        
        return summary
    
    def __len__(self) -> int:
        """Return number of messages"""
        return len(self.messages)
    
    def __repr__(self) -> str:
        return f"<MessageHistoryManager: {len(self.messages)} messages>"


if __name__ == "__main__":
    # Test the message history manager
    print("🧪 Testing MessageHistoryManager\n")
    
    # Create manager
    history = MessageHistoryManager(max_messages=10, session_id="test-session")
    
    # Add some messages
    history.add_message("user", "Find subdomains of snode.com")
    history.add_message("assistant", "I'll use amass and bbot", agent_name="ReconAgent")
    history.add_message("assistant", "Found 15 subdomains", agent_name="ReconAgent")
    
    # Handoff
    history.transfer_to_agent("ReconAgent", "ExploitAgent")
    history.add_message("assistant", "Scanning for vulnerabilities", agent_name="ExploitAgent")
    
    # Get history
    print("📋 Full history for LLM:")
    for msg in history.get_history_for_llm():
        print(f"  {msg['role']}: {msg['content'][:50]}...")
    
    print(f"\n📊 Summary:")
    print(history.get_summary())
    
    print(f"\n✅ MessageHistoryManager test complete!")
