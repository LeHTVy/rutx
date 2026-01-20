"""
Conversation store for persistent message storage.

Uses PostgreSQL for reliable conversation persistence, with support for:
- Message sequence tracking
- Summary compression for long conversations
- Verified target storage
"""

import os
import uuid
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False


class ConversationStore:
    """PostgreSQL-backed conversation persistence.
    
    Provides reliable storage for:
    - Conversation metadata
    - Full message history with sequence tracking
    - Agent state persistence
    - Tool execution results
    """
    
    def __init__(self):
        """Initialize conversation store."""
        if not PSYCOPG2_AVAILABLE:
            raise ImportError("psycopg2-binary required: pip install psycopg2-binary")
        
        self.db_config = {
            "host": os.getenv("POSTGRES_HOST", "localhost"),
            "port": int(os.getenv("POSTGRES_PORT", 5432)),
            "database": os.getenv("POSTGRES_DATABASE", "snode_db"),
            "user": os.getenv("POSTGRES_USER", "snode"),
            "password": os.getenv("POSTGRES_PASSWORD", ""),
        }
    
    def _get_connection(self):
        """Get PostgreSQL connection."""
        return psycopg2.connect(**self.db_config)
    
    def health_check(self) -> bool:
        """Check if PostgreSQL is accessible."""
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    return True
        except Exception:
            return False
    
    # =========================================================================
    # Conversation Management
    # =========================================================================
    
    def create_conversation(self, 
                           title: Optional[str] = None,
                           target_domain: Optional[str] = None,
                           session_id: Optional[str] = None) -> str:
        """Create a new conversation.
        
        Args:
            title: Optional conversation title
            target_domain: Optional target domain
            session_id: Optional legacy session ID
            
        Returns:
            Conversation UUID
        """
        conversation_id = str(uuid.uuid4())
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO conversations 
                    (id, title, verified_target, session_id)
                    VALUES (%s, %s, %s, %s)
                """, (conversation_id, title, target_domain, session_id))
                conn.commit()
        
        return conversation_id
    
    def get_conversation(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        """Get conversation by ID.
        
        Args:
            conversation_id: Conversation UUID
            
        Returns:
            Conversation dict or None
        """
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM conversations WHERE id = %s
                """, (conversation_id,))
                row = cur.fetchone()
                
                if row:
                    return dict(row)
                return None
    
    def get_conversation_by_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get conversation by legacy session ID.
        
        Args:
            session_id: Legacy session ID
            
        Returns:
            Conversation dict or None
        """
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM conversations WHERE session_id = %s
                """, (session_id,))
                row = cur.fetchone()
                
                if row:
                    return dict(row)
                return None
    
    def update_conversation(self, 
                           conversation_id: str,
                           title: Optional[str] = None,
                           verified_target: Optional[str] = None,
                           summary: Optional[str] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update conversation metadata.
        
        Args:
            conversation_id: Conversation UUID
            title: New title
            verified_target: New verified target
            summary: Conversation summary
            metadata: Additional metadata
            
        Returns:
            True if updated
        """
        updates = []
        params = []
        
        if title is not None:
            updates.append("title = %s")
            params.append(title)
        
        if verified_target is not None:
            updates.append("verified_target = %s")
            params.append(verified_target)
        
        if summary is not None:
            updates.append("summary = %s")
            params.append(summary)
        
        if metadata is not None:
            updates.append("metadata = %s")
            params.append(json.dumps(metadata))
        
        if not updates:
            return False
        
        params.append(conversation_id)
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    UPDATE conversations 
                    SET {', '.join(updates)}
                    WHERE id = %s
                """, params)
                conn.commit()
        
        return True
    
    def list_conversations(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent conversations.
        
        Args:
            limit: Maximum number to return
            
        Returns:
            List of conversation dicts
        """
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, title, verified_target, created_at, updated_at
                    FROM conversations
                    ORDER BY updated_at DESC
                    LIMIT %s
                """, (limit,))
                return [dict(row) for row in cur.fetchall()]
    
    # =========================================================================
    # Message Management
    # =========================================================================
    
    def add_message(self,
                   conversation_id: str,
                   role: str,
                   content: str,
                   metadata: Optional[Dict[str, Any]] = None) -> str:
        """Add message to conversation.
        
        Args:
            conversation_id: Conversation UUID
            role: Message role (user, assistant, system)
            content: Message content
            metadata: Optional metadata
            
        Returns:
            Message UUID
        """
        message_id = str(uuid.uuid4())
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                # Get next sequence number
                cur.execute("""
                    SELECT COALESCE(MAX(sequence_number), 0) + 1
                    FROM conversation_messages
                    WHERE conversation_id = %s
                """, (conversation_id,))
                seq_num = cur.fetchone()[0]
                
                # Insert message
                cur.execute("""
                    INSERT INTO conversation_messages
                    (id, conversation_id, role, content, sequence_number, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    message_id,
                    conversation_id,
                    role,
                    content,
                    seq_num,
                    json.dumps(metadata or {})
                ))
                conn.commit()
        
        return message_id
    
    def get_messages(self,
                    conversation_id: str,
                    limit: Optional[int] = None,
                    offset: int = 0) -> List[Dict[str, Any]]:
        """Get messages for conversation.
        
        Args:
            conversation_id: Conversation UUID
            limit: Maximum number of messages
            offset: Number of messages to skip
            
        Returns:
            List of message dicts
        """
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if limit:
                    cur.execute("""
                        SELECT id, role, content, sequence_number, created_at, metadata
                        FROM conversation_messages
                        WHERE conversation_id = %s
                        ORDER BY sequence_number ASC
                        LIMIT %s OFFSET %s
                    """, (conversation_id, limit, offset))
                else:
                    cur.execute("""
                        SELECT id, role, content, sequence_number, created_at, metadata
                        FROM conversation_messages
                        WHERE conversation_id = %s
                        ORDER BY sequence_number ASC
                    """, (conversation_id,))
                
                return [dict(row) for row in cur.fetchall()]
    
    def get_recent_messages(self,
                           conversation_id: str,
                           n: int = 10) -> List[Dict[str, Any]]:
        """Get most recent messages.
        
        Args:
            conversation_id: Conversation UUID
            n: Number of messages
            
        Returns:
            List of message dicts (oldest first)
        """
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, role, content, sequence_number, created_at, metadata
                    FROM conversation_messages
                    WHERE conversation_id = %s
                    ORDER BY sequence_number DESC
                    LIMIT %s
                """, (conversation_id, n))
                
                messages = [dict(row) for row in cur.fetchall()]
                messages.reverse()  # Return oldest first
                return messages
    
    def count_messages(self, conversation_id: str) -> int:
        """Count messages in conversation.
        
        Args:
            conversation_id: Conversation UUID
            
        Returns:
            Message count
        """
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM conversation_messages
                    WHERE conversation_id = %s
                """, (conversation_id,))
                return cur.fetchone()[0]
    
    # =========================================================================
    # Agent State Management
    # =========================================================================
    
    def set_state(self,
                 conversation_id: str,
                 state_type: str,
                 data: Dict[str, Any]) -> bool:
        """Set agent state.
        
        Args:
            conversation_id: Conversation UUID
            state_type: Type of state
            data: State data
            
        Returns:
            True if set successfully
        """
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO agent_states (conversation_id, state_type, state_data)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (conversation_id, state_type) 
                    DO UPDATE SET state_data = EXCLUDED.state_data
                """, (conversation_id, state_type, json.dumps(data)))
                conn.commit()
        
        return True
    
    def get_state(self,
                 conversation_id: str,
                 state_type: str) -> Optional[Dict[str, Any]]:
        """Get agent state.
        
        Args:
            conversation_id: Conversation UUID
            state_type: Type of state
            
        Returns:
            State data or None
        """
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT state_data FROM agent_states
                    WHERE conversation_id = %s AND state_type = %s
                """, (conversation_id, state_type))
                row = cur.fetchone()
                
                if row:
                    data = row["state_data"]
                    return data if isinstance(data, dict) else json.loads(data)
                return None
    
    # =========================================================================
    # Tool Results
    # =========================================================================
    
    def save_tool_result(self,
                        conversation_id: str,
                        tool_name: str,
                        command_name: Optional[str],
                        target: str,
                        output: str,
                        parsed_data: Optional[Dict[str, Any]] = None,
                        success: bool = True,
                        execution_time: Optional[float] = None) -> str:
        """Save tool execution result.
        
        Args:
            conversation_id: Conversation UUID
            tool_name: Tool name
            command_name: Command name
            target: Target domain/IP
            output: Raw output
            parsed_data: Parsed data dict
            success: Whether execution succeeded
            execution_time: Execution time in seconds
            
        Returns:
            Result UUID
        """
        result_id = str(uuid.uuid4())
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO tool_results
                    (id, conversation_id, tool_name, command_name, target, output, 
                     parsed_data, success, execution_time)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    result_id,
                    conversation_id,
                    tool_name,
                    command_name,
                    target,
                    output,
                    json.dumps(parsed_data or {}),
                    success,
                    execution_time
                ))
                conn.commit()
        
        return result_id
    
    def get_tool_results(self,
                        conversation_id: str,
                        tool_name: Optional[str] = None,
                        target: Optional[str] = None,
                        limit: int = 10) -> List[Dict[str, Any]]:
        """Get tool results for conversation.
        
        Args:
            conversation_id: Conversation UUID
            tool_name: Optional filter by tool
            target: Optional filter by target
            limit: Maximum results
            
        Returns:
            List of result dicts
        """
        where_clauses = ["conversation_id = %s"]
        params = [conversation_id]
        
        if tool_name:
            where_clauses.append("tool_name = %s")
            params.append(tool_name)
        
        if target:
            where_clauses.append("target = %s")
            params.append(target)
        
        params.append(limit)
        
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(f"""
                    SELECT * FROM tool_results
                    WHERE {' AND '.join(where_clauses)}
                    ORDER BY created_at DESC
                    LIMIT %s
                """, params)
                return [dict(row) for row in cur.fetchall()]


# Singleton instance
_conversation_store: Optional[ConversationStore] = None


def get_conversation_store() -> ConversationStore:
    """Get or create conversation store instance.
    
    Returns:
        ConversationStore instance
    """
    global _conversation_store
    if _conversation_store is None:
        _conversation_store = ConversationStore()
    return _conversation_store
