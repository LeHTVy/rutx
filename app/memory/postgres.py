"""
PostgreSQL Memory Storage for SNODE.

Stores exact conversation history and session data.
"""
import psycopg2
from psycopg2.extras import RealDictCursor, Json
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any


class PostgresMemory:
    """PostgreSQL-based conversation memory."""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "snode_memory",
        user: str = "snode",
        password: str = "snode123"
    ):
        self.conn_params = {
            "host": host,
            "port": port,
            "database": database,
            "user": user,
            "password": password
        }
        self.conn = None
        self._connect()
        self._init_schema()
    
    def _connect(self):
        """Connect to PostgreSQL."""
        try:
            self.conn = psycopg2.connect(**self.conn_params)
            self.conn.autocommit = True
        except Exception as e:
            print(f"⚠️ PostgreSQL connection failed: {e}")
            self.conn = None
    
    def _init_schema(self):
        """Initialize database schema."""
        if not self.conn:
            return
        
        with self.conn.cursor() as cur:
            # Sessions table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id SERIAL PRIMARY KEY,
                    session_id UUID UNIQUE NOT NULL,
                    user_id VARCHAR(255) DEFAULT 'default',
                    started_at TIMESTAMP DEFAULT NOW(),
                    last_active TIMESTAMP DEFAULT NOW(),
                    target_domain VARCHAR(255),
                    summary TEXT,
                    context JSONB DEFAULT '{}'
                )
            """)
            
            # Messages table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    session_id UUID REFERENCES sessions(session_id) ON DELETE CASCADE,
                    role VARCHAR(20) NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT NOW(),
                    tools_used TEXT[],
                    context JSONB DEFAULT '{}'
                )
            """)
            
            # Findings table (structured results from tools)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id SERIAL PRIMARY KEY,
                    session_id UUID REFERENCES sessions(session_id) ON DELETE CASCADE,
                    domain VARCHAR(255),
                    finding_type VARCHAR(50),
                    data JSONB,
                    discovered_at TIMESTAMP DEFAULT NOW()
                )
            """)
            
            # Create indexes
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_session 
                ON messages(session_id)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_domain 
                ON findings(domain)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_domain 
                ON sessions(target_domain)
            """)
    
    # ==================== Session Management ====================
    
    def create_session(
        self, 
        target_domain: str = None,
        user_id: str = "default"
    ) -> str:
        """Create a new session, return session_id."""
        if not self.conn:
            return str(uuid.uuid4())
        
        session_id = str(uuid.uuid4())
        
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO sessions (session_id, user_id, target_domain)
                VALUES (%s, %s, %s)
            """, (session_id, user_id, target_domain))
        
        return session_id
    
    def get_last_session(self, target_domain: str = None) -> Optional[Dict]:
        """Get the most recent session, optionally for a specific domain."""
        if not self.conn:
            return None
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            if target_domain:
                cur.execute("""
                    SELECT * FROM sessions 
                    WHERE target_domain = %s
                    ORDER BY last_active DESC
                    LIMIT 1
                """, (target_domain,))
            else:
                cur.execute("""
                    SELECT * FROM sessions 
                    ORDER BY last_active DESC
                    LIMIT 1
                """)
            return cur.fetchone()
    
    def update_session_activity(self, session_id: str, context: Dict = None):
        """Update session's last_active timestamp and context."""
        if not self.conn:
            return
        
        with self.conn.cursor() as cur:
            if context:
                cur.execute("""
                    UPDATE sessions 
                    SET last_active = NOW(), context = %s
                    WHERE session_id = %s
                """, (Json(context), session_id))
            else:
                cur.execute("""
                    UPDATE sessions SET last_active = NOW()
                    WHERE session_id = %s
                """, (session_id,))
    
    def set_session_summary(self, session_id: str, summary: str):
        """Set session summary."""
        if not self.conn:
            return
        
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE sessions SET summary = %s
                WHERE session_id = %s
            """, (summary, session_id))
    
    def get_session_context(self, session_id: str) -> tuple:
        """
        Get session context (for resume). Supports partial UUID prefixes.
        
        Returns:
            tuple: (full_session_id, context) or (None, {}) if not found
        """
        if not self.conn:
            return (None, {})
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Support partial UUID (e.g., "6e436103" matches "6e436103-...")
            if len(session_id) < 36:
                cur.execute("""
                    SELECT session_id, context FROM sessions 
                    WHERE session_id::text LIKE %s
                    ORDER BY last_active DESC
                    LIMIT 1
                """, (session_id + '%',))
            else:
                cur.execute("""
                    SELECT session_id, context FROM sessions WHERE session_id = %s
                """, (session_id,))
            row = cur.fetchone()
            if row:
                return (str(row['session_id']), row['context'] or {})
            return (None, {})
    
    # ==================== Message Storage ====================
    
    def save_message(
        self,
        session_id: str,
        role: str,
        content: str,
        tools_used: List[str] = None,
        context: Dict = None
    ):
        """Save a message to the database."""
        if not self.conn:
            return
        
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO messages (session_id, role, content, tools_used, context)
                VALUES (%s, %s, %s, %s, %s)
            """, (session_id, role, content, tools_used, Json(context or {})))
    
    def get_messages(
        self,
        session_id: str,
        limit: int = 20
    ) -> List[Dict]:
        """Get messages from a session."""
        if not self.conn:
            return []
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT role, content, timestamp, tools_used
                FROM messages
                WHERE session_id = %s
                ORDER BY timestamp DESC
                LIMIT %s
            """, (session_id, limit))
            rows = cur.fetchall()
            return list(reversed(rows))  # Return in chronological order
    
    def get_recent_messages_all_sessions(self, limit: int = 10) -> List[Dict]:
        """Get recent messages across all sessions."""
        if not self.conn:
            return []
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT m.role, m.content, m.timestamp, s.target_domain
                FROM messages m
                JOIN sessions s ON m.session_id = s.session_id
                ORDER BY m.timestamp DESC
                LIMIT %s
            """, (limit,))
            return cur.fetchall()
    
    # ==================== Findings Storage ====================
    
    def save_finding(
        self,
        session_id: str,
        domain: str,
        finding_type: str,
        data: Dict
    ):
        """Save a finding (subdomain, port, vuln, etc.)."""
        if not self.conn:
            return
        
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO findings (session_id, domain, finding_type, data)
                VALUES (%s, %s, %s, %s)
            """, (session_id, domain, finding_type, Json(data)))
    
    def get_findings(
        self,
        domain: str = None,
        finding_type: str = None,
        session_id: str = None
    ) -> List[Dict]:
        """Get findings, optionally filtered."""
        if not self.conn:
            return []
        
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        
        if domain:
            query += " AND domain = %s"
            params.append(domain)
        if finding_type:
            query += " AND finding_type = %s"
            params.append(finding_type)
        if session_id:
            query += " AND session_id = %s"
            params.append(session_id)
        
        query += " ORDER BY discovered_at DESC LIMIT 100"
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            return cur.fetchall()
    
    # ==================== Cleanup ====================
    
    def cleanup_old_data(self, days: int = 30):
        """Delete data older than specified days."""
        if not self.conn:
            return 0
        
        cutoff = datetime.now() - timedelta(days=days)
        
        with self.conn.cursor() as cur:
            # Delete old sessions (cascades to messages and findings)
            cur.execute("""
                DELETE FROM sessions 
                WHERE last_active < %s
                RETURNING id
            """, (cutoff,))
            deleted = cur.rowcount
        
        return deleted
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()


# Singleton
_postgres_instance = None

def get_postgres() -> PostgresMemory:
    """Get or create PostgreSQL memory instance."""
    global _postgres_instance
    if _postgres_instance is None:
        _postgres_instance = PostgresMemory()
    return _postgres_instance
