"""
Topic-Based History Management for SNODE

Inspired by agent-zero's hierarchical history structure:
- Topics: Group of related messages (a conversation topic)
- Bulks: Summarized old topics
- Current: Active topic with full messages

This enables smart compression and better context management.
"""
import json
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union
from enum import Enum

# MessageContent can be str or dict
MessageContent = Union[str, Dict[str, Any]]
from app.agent.utils.tokens import approximate_tokens, get_context_limit


# Configuration constants (from agent-zero)
BULK_MERGE_COUNT = 3
TOPICS_KEEP_COUNT = 3
CURRENT_TOPIC_RATIO = 0.5  # 50% of context for current topic
HISTORY_TOPIC_RATIO = 0.3  # 30% for old topics
HISTORY_BULK_RATIO = 0.2   # 20% for bulks
TOPIC_COMPRESS_RATIO = 0.65
LARGE_MESSAGE_TO_TOPIC_RATIO = 0.25


class Record(ABC):
    """Base class for history records (Topic, Bulk, Message)."""
    
    @abstractmethod
    def get_tokens(self) -> int:
        """Get token count for this record."""
        pass
    
    @abstractmethod
    async def compress(self) -> bool:
        """Compress this record. Returns True if compression occurred."""
        pass
    
    @abstractmethod
    def output(self) -> List[Dict[str, Any]]:
        """Output messages in format for LLM."""
        pass
    
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        pass


@dataclass
class Message(Record):
    """Single message in history."""
    ai: bool
    content: MessageContent
    tokens: int = 0
    summary: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def get_tokens(self) -> int:
        if not self.tokens:
            self.tokens = self._calculate_tokens()
        return self.tokens
    
    def _calculate_tokens(self) -> int:
        """Calculate tokens from content."""
        text = self._content_to_text()
        return approximate_tokens(text)
    
    def _content_to_text(self) -> str:
        """Convert content to text for token counting."""
        if isinstance(self.content, str):
            return self.content
        if isinstance(self.content, dict):
            return json.dumps(self.content, ensure_ascii=False)
        return str(self.content)
    
    async def compress(self) -> bool:
        """Messages don't compress individually."""
        return False
    
    def output(self) -> List[Dict[str, Any]]:
        """Output message for LLM."""
        if self.summary:
            return [{"ai": self.ai, "content": self.summary}]
        return [{"ai": self.ai, "content": self.content}]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "_cls": "Message",
            "ai": self.ai,
            "content": self.content,
            "summary": self.summary,
            "tokens": self.tokens,
            "created_at": self.created_at.isoformat(),
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Message":
        msg = Message(
            ai=data["ai"],
            content=data.get("content", ""),
            tokens=data.get("tokens", 0),
            summary=data.get("summary", "")
        )
        if data.get("created_at"):
            msg.created_at = datetime.fromisoformat(data["created_at"])
        return msg
    
    def set_summary(self, summary: str):
        """Set summary and recalculate tokens."""
        self.summary = summary
        self.tokens = self._calculate_tokens()


@dataclass
class Topic(Record):
    """A topic groups related messages together."""
    id: str
    title: str = ""
    messages: List[Message] = field(default_factory=list)
    summary: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    history: Optional["History"] = None
    
    def get_tokens(self) -> int:
        if self.summary:
            return approximate_tokens(self.summary)
        return sum(msg.get_tokens() for msg in self.messages)
    
    def add_message(self, ai: bool, content: MessageContent, tokens: int = 0) -> Message:
        """Add a message to this topic."""
        msg = Message(ai=ai, content=content, tokens=tokens)
        self.messages.append(msg)
        return msg
    
    def output(self) -> List[Dict[str, Any]]:
        """Output all messages in this topic."""
        if self.summary:
            return [{"ai": False, "content": self.summary}]
        result = []
        for msg in self.messages:
            result.extend(msg.output())
        return result
    
    async def compress(self) -> bool:
        """Compress this topic by summarizing messages."""
        # First try to compress large messages
        compressed = await self._compress_large_messages()
        if not compressed:
            compressed = await self._compress_attention()
        return compressed
    
    async def _compress_large_messages(self) -> bool:
        """Compress individual large messages."""
        if not self.history:
            return False
        
        # Calculate max message size
        ctx_limit = self._get_ctx_limit()
        msg_max_size = int(ctx_limit * CURRENT_TOPIC_RATIO * LARGE_MESSAGE_TO_TOPIC_RATIO)
        
        for msg in self.messages:
            if msg.summary:
                continue
            
            msg_tokens = msg.get_tokens()
            if msg_tokens > msg_max_size:
                # Truncate or summarize large message
                text = msg._content_to_text()
                if len(text) > 5000:
                    # Truncate to reasonable size
                    msg.set_summary(text[:2000] + "... (truncated)")
                    return True
        return False
    
    async def _compress_attention(self) -> bool:
        """Compress by summarizing middle messages, keeping first and last."""
        if len(self.messages) <= 2:
            return False
        
        if not self.history or not self.history.agent:
            return False
        
        # Calculate how many messages to summarize
        cnt_to_sum = math.ceil((len(self.messages) - 2) * TOPIC_COMPRESS_RATIO)
        if cnt_to_sum < 1:
            return False
        
        msg_to_sum = self.messages[1:cnt_to_sum + 1]
        
        # Summarize these messages
        try:
            summary = await self._summarize_messages(msg_to_sum)
            if summary:
                sum_msg = Message(False, summary)
                self.messages[1:cnt_to_sum + 1] = [sum_msg]
                return True
        except Exception as e:
            print(f"  ⚠️ Topic compression error: {e}")
        
        return False
    
    async def _summarize_messages(self, messages: List[Message]) -> str:
        """Use LLM to summarize messages."""
        if not self.history or not self.history.agent:
            return ""
        
        # Build text from messages
        msg_texts = [msg._content_to_text() for msg in messages]
        combined = "\n".join(msg_texts)
        
        # Use utility model to summarize
        try:
            from app.agent.agents.base_agent import BaseAgent
            agent = self.history.agent
            
            if hasattr(agent, 'call_utility_model'):
                summary = await agent.call_utility_model(
                    system="Summarize the following conversation messages concisely.",
                    message=combined[:4000]  # Limit input size
                )
                return summary
        except Exception:
            pass
        
        # Fallback: simple truncation
        return combined[:500] + "..."
    
    async def summarize(self) -> str:
        """Summarize entire topic."""
        if not self.messages:
            return ""
        
        summary = await self._summarize_messages(self.messages)
        if summary:
            self.summary = summary
        return summary
    
    def _get_ctx_limit(self) -> int:
        """Get context window limit."""
        try:
            from app.agent.utils import settings
            s = settings.get_settings() if hasattr(settings, 'get_settings') else {}
            ctx_length = s.get("chat_model_ctx_length", 8192)
            ctx_history = s.get("chat_model_ctx_history", 0.8)
            return int(ctx_length * ctx_history)
        except Exception:
            return 8192  # Default
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "_cls": "Topic",
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "messages": [m.to_dict() for m in self.messages],
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any], history: Optional["History"] = None) -> "Topic":
        topic = Topic(
            id=data.get("id", ""),
            title=data.get("title", ""),
            summary=data.get("summary", ""),
            metadata=data.get("metadata", {}),
            history=history
        )
        if data.get("created_at"):
            topic.created_at = datetime.fromisoformat(data["created_at"])
        topic.messages = [Message.from_dict(m) for m in data.get("messages", [])]
        return topic


@dataclass
class Bulk(Record):
    """Bulk contains summarized old topics."""
    id: str
    summary: str = ""
    records: List[Record] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    history: Optional["History"] = None
    
    def get_tokens(self) -> int:
        if self.summary:
            return approximate_tokens(self.summary)
        return sum(r.get_tokens() for r in self.records)
    
    def output(self) -> List[Dict[str, Any]]:
        """Output bulk summary."""
        if self.summary:
            return [{"ai": False, "content": self.summary}]
        result = []
        for record in self.records:
            result.extend(record.output())
        return result
    
    async def compress(self) -> bool:
        """Bulks don't compress further."""
        return False
    
    async def summarize(self) -> str:
        """Summarize all records in bulk."""
        if not self.history or not self.history.agent:
            return ""
        
        # Get text from all records
        texts = []
        for record in self.records:
            output = record.output()
            for msg in output:
                if isinstance(msg.get("content"), str):
                    texts.append(msg["content"])
        
        combined = "\n".join(texts)
        
        # Use LLM to summarize
        try:
            from app.llm.client import OllamaClient
            llm = OllamaClient()
            
            prompt = f"""Summarize the following old conversation history concisely, focusing on key findings and actions:

{combined[:4000]}

Summary:"""
            
            summary = llm.generate(prompt, timeout=30, stream=False)
            self.summary = summary.strip()
            return self.summary
        except Exception as e:
            print(f"  ⚠️ Bulk summarization error: {e}")
        
        # Fallback
        self.summary = combined[:500] + "..."
        return self.summary
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "_cls": "Bulk",
            "id": self.id,
            "summary": self.summary,
            "records": [r.to_dict() for r in self.records],
            "created_at": self.created_at.isoformat(),
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any], history: Optional["History"] = None) -> "Bulk":
        bulk = Bulk(
            id=data.get("id", ""),
            summary=data.get("summary", ""),
            history=history
        )
        if data.get("created_at"):
            bulk.created_at = datetime.fromisoformat(data["created_at"])
        
        # Reconstruct records
        for r_data in data.get("records", []):
            cls_name = r_data.get("_cls")
            if cls_name == "Topic":
                bulk.records.append(Topic.from_dict(r_data, history))
            elif cls_name == "Bulk":
                bulk.records.append(Bulk.from_dict(r_data, history))
        
        return bulk


@dataclass
class History:
    """Hierarchical history management with topics and bulks."""
    bulks: List[Bulk] = field(default_factory=list)
    topics: List[Topic] = field(default_factory=list)
    current: Optional[Topic] = None
    agent: Optional[Any] = None  # Agent instance for LLM calls
    counter: int = 0
    
    def __post_init__(self):
        if self.current is None:
            self.current = Topic(id=self._generate_id(), history=self)
    
    def _generate_id(self) -> str:
        """Generate unique ID."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def get_tokens(self) -> int:
        """Get total token count."""
        return (
            self.get_bulks_tokens() +
            self.get_topics_tokens() +
            self.get_current_topic_tokens()
        )
    
    def get_bulks_tokens(self) -> int:
        return sum(b.get_tokens() for b in self.bulks)
    
    def get_topics_tokens(self) -> int:
        return sum(t.get_tokens() for t in self.topics)
    
    def get_current_topic_tokens(self) -> int:
        return self.current.get_tokens() if self.current else 0
    
    def is_over_limit(self) -> bool:
        """Check if history exceeds context limit."""
        limit = self._get_ctx_limit()
        return self.get_tokens() > limit
    
    def _get_ctx_limit(self) -> int:
        """Get context window limit."""
        try:
            from app.agent.utils import settings
            s = settings.get_settings() if hasattr(settings, 'get_settings') else {}
            ctx_length = s.get("chat_model_ctx_length", 8192)
            ctx_history = s.get("chat_model_ctx_history", 0.8)
            return int(ctx_length * ctx_history)
        except Exception:
            return 8192  # Default
    
    def add_message(self, ai: bool, content: MessageContent, tokens: int = 0) -> Message:
        """Add a message to current topic."""
        self.counter += 1
        if not self.current:
            self.current = Topic(id=self._generate_id(), history=self)
        return self.current.add_message(ai, content, tokens)
    
    def new_topic(self, title: str = ""):
        """Start a new topic (user message starts new topic)."""
        if self.current and self.current.messages:
            # Auto-generate title if not provided
            if not title:
                title = self._auto_detect_topic_title(self.current)
            self.current.title = title
            self.topics.append(self.current)
        
        # Create new current topic
        self.current = Topic(id=self._generate_id(), history=self, title=title)
    
    def _auto_detect_topic_title(self, topic: Topic) -> str:
        """Auto-detect topic title from messages."""
        if not topic.messages:
            return "General"
        
        # Get first user message
        first_user_msg = None
        for msg in topic.messages:
            if not msg.ai:
                first_user_msg = msg
                break
        
        if not first_user_msg:
            return "General"
        
        # Extract keywords from first message
        content = first_user_msg._content_to_text().lower()
        
        # Common topic patterns
        if any(kw in content for kw in ["subdomain", "subfinder", "amass"]):
            return "Subdomain Enumeration"
        elif any(kw in content for kw in ["port", "nmap", "scan"]):
            return "Port Scanning"
        elif any(kw in content for kw in ["vulnerability", "nuclei", "exploit"]):
            return "Vulnerability Assessment"
        elif any(kw in content for kw in ["directory", "gobuster", "dirsearch"]):
            return "Directory Enumeration"
        elif any(kw in content for kw in ["brute", "hydra", "password"]):
            return "Credential Brute Force"
        else:
            # Use first few words
            words = content.split()[:5]
            return " ".join(words).title()[:50]
    
    def output(self) -> List[Dict[str, Any]]:
        """Output all messages in order (bulks → topics → current)."""
        result = []
        result.extend([m for b in self.bulks for m in b.output()])
        result.extend([m for t in self.topics for m in t.output()])
        if self.current:
            result.extend(self.current.output())
        return result
    
    async def compress(self) -> bool:
        """Compress history to fit context window."""
        compressed = False
        
        while self.is_over_limit():
            curr_tokens = self.get_current_topic_tokens()
            hist_tokens = self.get_topics_tokens()
            bulk_tokens = self.get_bulks_tokens()
            total_limit = self._get_ctx_limit()
            
            # Calculate ratios
            ratios = [
                (curr_tokens, CURRENT_TOPIC_RATIO, "current_topic"),
                (hist_tokens, HISTORY_TOPIC_RATIO, "history_topic"),
                (bulk_tokens, HISTORY_BULK_RATIO, "history_bulk"),
            ]
            
            # Sort by how much over ratio they are
            ratios = sorted(ratios, key=lambda x: (x[0] / total_limit) / x[1] if x[1] > 0 else 0, reverse=True)
            
            compressed_part = False
            for tokens_count, ratio, part_name in ratios:
                if tokens_count > ratio * total_limit:
                    if part_name == "current_topic" and self.current:
                        compressed_part = await self.current.compress()
                    elif part_name == "history_topic":
                        compressed_part = await self.compress_topics()
                    elif part_name == "history_bulk":
                        compressed_part = await self.compress_bulks()
                    
                    if compressed_part:
                        break
            
            if compressed_part:
                compressed = True
                continue
            else:
                # If nothing can compress, remove oldest bulk
                if self.bulks:
                    self.bulks.pop(0)
                    compressed = True
                else:
                    break
        
        return compressed
    
    async def compress_topics(self) -> bool:
        """Compress old topics by summarizing."""
        # First, summarize topics that don't have summaries
        for topic in self.topics:
            if not topic.summary:
                await topic.summarize()
                return True
        
        # If all topics summarized, move oldest to bulk
        if self.topics:
            oldest_topic = self.topics[0]
            bulk = Bulk(id=self._generate_id(), history=self)
            bulk.records.append(oldest_topic)
            
            if oldest_topic.summary:
                bulk.summary = oldest_topic.summary
            else:
                await bulk.summarize()
            
            self.bulks.append(bulk)
            self.topics.remove(oldest_topic)
            return True
        
        return False
    
    async def compress_bulks(self) -> bool:
        """Compress bulks by merging."""
        # Merge bulks in groups
        if len(self.bulks) < BULK_MERGE_COUNT:
            return False
        
        # Merge first BULK_MERGE_COUNT bulks
        bulks_to_merge = self.bulks[:BULK_MERGE_COUNT]
        merged_bulk = Bulk(id=self._generate_id(), history=self)
        merged_bulk.records = bulks_to_merge
        
        await merged_bulk.summarize()
        
        # Replace merged bulks with new bulk
        self.bulks = [merged_bulk] + self.bulks[BULK_MERGE_COUNT:]
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "_cls": "History",
            "counter": self.counter,
            "bulks": [b.to_dict() for b in self.bulks],
            "topics": [t.to_dict() for t in self.topics],
            "current": self.current.to_dict() if self.current else None,
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any], agent: Optional[Any] = None) -> "History":
        history = History(agent=agent)
        history.counter = data.get("counter", 0)
        history.bulks = [Bulk.from_dict(b, history) for b in data.get("bulks", [])]
        history.topics = [Topic.from_dict(t, history) for t in data.get("topics", [])]
        if data.get("current"):
            history.current = Topic.from_dict(data["current"], history)
        return history
    
    def serialize(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)
    
    @staticmethod
    def deserialize(json_str: str, agent: Optional[Any] = None) -> "History":
        """Deserialize from JSON string."""
        if not json_str:
            return History(agent=agent)
        data = json.loads(json_str)
        return History.from_dict(data, agent)
