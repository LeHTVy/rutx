"""
Redis buffer for short-term memory (conversation buffer and active state).

This implements the short-term memory layer for production architecture:
- Sliding window of recent messages
- Active agent state
- Chain-of-thought reasoning
- Automatic TTL for cleanup
"""

import os
import json
from typing import List, Dict, Any, Optional
from datetime import timedelta

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class RedisBuffer:
    """Redis-based short-term memory buffer.
    
    Stores:
    - Recent conversation messages (sliding window)
    - Active agent state
    - Chain-of-thought reasoning
    - Temporary context
    """
    
    def __init__(self, 
                 default_ttl: int = 3600,
                 max_messages: int = 50):
        """Initialize Redis buffer.
        
        Args:
            default_ttl: Default TTL in seconds for buffer entries (default: 1 hour)
            max_messages: Maximum number of messages to keep in buffer (default: 50)
        """
        if not REDIS_AVAILABLE:
            raise ImportError("redis package required: pip install redis")
        
        self.default_ttl = default_ttl
        self.max_messages = max_messages
        self.key_prefix = "snode"
        
        # Redis connection from environment
        self.redis_config = {
            "host": os.getenv("REDIS_HOST", "localhost"),
            "port": int(os.getenv("REDIS_PORT", 6379)),
            "password": os.getenv("REDIS_PASSWORD", None) or None,
            "db": int(os.getenv("REDIS_DB", 0)),
            "decode_responses": True,
        }
        
        self._client: Optional[redis.Redis] = None
    
    @property
    def client(self) -> redis.Redis:
        """Get Redis client (lazy initialization)."""
        if self._client is None:
            self._client = redis.Redis(**self.redis_config)
        return self._client
    
    def _key(self, conversation_id: str, key_type: str) -> str:
        """Generate Redis key.
        
        Args:
            conversation_id: Conversation UUID
            key_type: Type of key (messages, state, etc.)
            
        Returns:
            Redis key string
        """
        return f"{self.key_prefix}:{conversation_id}:{key_type}"
    
    def health_check(self) -> bool:
        """Check if Redis connection is healthy.
        
        Returns:
            True if Redis is accessible, False otherwise
        """
        try:
            return self.client.ping()
        except Exception:
            return False
    
    def add_message(self, 
                   conversation_id: str,
                   role: str,
                   content: str,
                   metadata: Optional[Dict[str, Any]] = None) -> int:
        """Add message to conversation buffer.
        
        Args:
            conversation_id: Conversation UUID
            role: Message role (user, assistant, system)
            content: Message content
            metadata: Optional metadata
            
        Returns:
            Current message count in buffer
        """
        key = self._key(conversation_id, "messages")
        
        message = {
            "role": role,
            "content": content,
            "metadata": metadata or {},
            "timestamp": json.dumps({"$date": True})  # Placeholder for timestamp
        }
        
        # Add to list (right push)
        self.client.rpush(key, json.dumps(message))
        
        # Trim to max messages (keep most recent)
        self.client.ltrim(key, -self.max_messages, -1)
        
        # Set TTL
        self.client.expire(key, self.default_ttl)
        
        return self.client.llen(key)
    
    def get_recent_messages(self, 
                           conversation_id: str,
                           n: int = 10) -> List[Dict[str, Any]]:
        """Get recent messages from buffer.
        
        Args:
            conversation_id: Conversation UUID
            n: Number of messages to retrieve (default: 10)
            
        Returns:
            List of message dicts
        """
        key = self._key(conversation_id, "messages")
        
        # Get last n messages
        messages = self.client.lrange(key, -n, -1)
        
        return [json.loads(msg) for msg in messages]
    
    def get_all_messages(self, conversation_id: str) -> List[Dict[str, Any]]:
        """Get all messages from buffer.
        
        Args:
            conversation_id: Conversation UUID
            
        Returns:
            List of all message dicts
        """
        key = self._key(conversation_id, "messages")
        messages = self.client.lrange(key, 0, -1)
        return [json.loads(msg) for msg in messages]
    
    def clear_messages(self, conversation_id: str) -> bool:
        """Clear all messages for a conversation.
        
        Args:
            conversation_id: Conversation UUID
            
        Returns:
            True if cleared successfully
        """
        key = self._key(conversation_id, "messages")
        self.client.delete(key)
        return True
    
    def set_state(self, 
                 conversation_id: str,
                 state_type: str,
                 data: Dict[str, Any],
                 ttl: Optional[int] = None) -> bool:
        """Set agent state.
        
        Args:
            conversation_id: Conversation UUID
            state_type: Type of state (e.g., 'agent_context', 'chain_of_thought')
            data: State data dict
            ttl: Optional TTL in seconds (uses default if None)
            
        Returns:
            True if set successfully
        """
        key = self._key(conversation_id, f"state:{state_type}")
        
        self.client.set(key, json.dumps(data))
        self.client.expire(key, ttl or self.default_ttl)
        
        return True
    
    def get_state(self, 
                 conversation_id: str,
                 state_type: str) -> Optional[Dict[str, Any]]:
        """Get agent state.
        
        Args:
            conversation_id: Conversation UUID
            state_type: Type of state
            
        Returns:
            State data dict or None if not found
        """
        key = self._key(conversation_id, f"state:{state_type}")
        
        data = self.client.get(key)
        if data:
            return json.loads(data)
        return None
    
    def delete_state(self, conversation_id: str, state_type: str) -> bool:
        """Delete agent state.
        
        Args:
            conversation_id: Conversation UUID
            state_type: Type of state
            
        Returns:
            True if deleted
        """
        key = self._key(conversation_id, f"state:{state_type}")
        self.client.delete(key)
        return True
    
    def clear_conversation(self, conversation_id: str) -> int:
        """Clear all buffer data for a conversation.
        
        Args:
            conversation_id: Conversation UUID
            
        Returns:
            Number of keys deleted
        """
        pattern = self._key(conversation_id, "*")
        keys = list(self.client.scan_iter(pattern))
        
        if keys:
            return self.client.delete(*keys)
        return 0
    
    def set_verified_target(self, 
                           conversation_id: str,
                           domain: str,
                           info: Optional[Dict[str, Any]] = None) -> bool:
        """Set verified target for conversation.
        
        Args:
            conversation_id: Conversation UUID
            domain: Verified domain
            info: Additional target info
            
        Returns:
            True if set successfully
        """
        return self.set_state(
            conversation_id,
            "verified_target",
            {"domain": domain, "info": info or {}},
            ttl=86400  # 24 hours for target
        )
    
    def get_verified_target(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        """Get verified target for conversation.
        
        Args:
            conversation_id: Conversation UUID
            
        Returns:
            Target info dict or None
        """
        return self.get_state(conversation_id, "verified_target")


# Singleton instance
_redis_buffer: Optional[RedisBuffer] = None


def get_redis_buffer() -> RedisBuffer:
    """Get or create Redis buffer instance.
    
    Returns:
        RedisBuffer instance
    """
    global _redis_buffer
    if _redis_buffer is None:
        _redis_buffer = RedisBuffer()
    return _redis_buffer
