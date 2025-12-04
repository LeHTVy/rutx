"""
Database Manager - Connection and Session Management
Provides SQLite database connection with SQLAlchemy ORM.
"""

import os
from typing import Optional, Generator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from .models import Base

# Default database path
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "pentest.db"
)


class DatabaseManager:
    """
    Manages database connections and sessions.
    Supports SQLite (local) and can be extended for PostgreSQL.
    """

    _instance: Optional['DatabaseManager'] = None
    _engine = None
    _session_factory = None

    def __new__(cls, db_url: Optional[str] = None):
        """Singleton pattern for database manager."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_url: Optional[str] = None):
        """Initialize database connection."""
        if self._initialized:
            return

        if db_url is None:
            # Ensure data directory exists
            data_dir = os.path.dirname(DEFAULT_DB_PATH)
            os.makedirs(data_dir, exist_ok=True)
            db_url = f"sqlite:///{DEFAULT_DB_PATH}"

        self.db_url = db_url
        self._init_engine()
        self._initialized = True

    def _init_engine(self):
        """Create SQLAlchemy engine with appropriate settings."""
        if "sqlite" in self.db_url:
            # SQLite-specific settings
            self._engine = create_engine(
                self.db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                echo=False  # Set to True for SQL debugging
            )

            # Enable foreign keys for SQLite
            @event.listens_for(self._engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        else:
            # PostgreSQL or other databases
            self._engine = create_engine(
                self.db_url,
                pool_size=10,
                max_overflow=20,
                echo=False
            )

        self._session_factory = sessionmaker(
            bind=self._engine,
            autocommit=False,
            autoflush=False
        )

    def create_tables(self):
        """Create all database tables."""
        Base.metadata.create_all(self._engine)

    def drop_tables(self):
        """Drop all database tables (use with caution!)."""
        Base.metadata.drop_all(self._engine)

    def get_session(self) -> Session:
        """Get a new database session."""
        return self._session_factory()

    @property
    def engine(self):
        """Get the SQLAlchemy engine."""
        return self._engine

    def health_check(self) -> bool:
        """
        Check if database connection is working.
        Uses the global db_session_scope() function.
        """
        try:
            session = self.get_session()
            try:
                session.execute("SELECT 1")
                session.commit()
                return True
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()
        except Exception:
            return False


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def init_database(db_url: Optional[str] = None, create_tables: bool = True) -> DatabaseManager:
    """
    Initialize the database connection.

    Args:
        db_url: Database connection URL (defaults to SQLite)
        create_tables: Whether to create tables on initialization

    Returns:
        DatabaseManager instance
    """
    global _db_manager
    _db_manager = DatabaseManager(db_url)

    if create_tables:
        _db_manager.create_tables()

    return _db_manager


def get_db_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = init_database()
    return _db_manager


def get_db_session() -> Session:
    """Get a new database session from the global manager."""
    return get_db_manager().get_session()


@contextmanager
def db_session_scope() -> Generator[Session, None, None]:
    """
    Context manager for database sessions.

    Usage:
        from database import db_session_scope

        with db_session_scope() as session:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            scan.status = ScanStatus.COMPLETED
            # Auto-commit on exit
    """
    manager = get_db_manager()
    session = manager.get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
