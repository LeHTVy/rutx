"""
Database Module - Data Persistence Layer for Security Scanning Framework
Provides SQLite/SQLAlchemy-based storage for scans, findings, assets, and hosts.

Slimmed down version - keeping core components:
- models.py: SQLAlchemy ORM models
- database.py: Connection management
- parsers.py: Tool output parsers
- repositories.py: CRUD operations

Complex services moved to backup/database/ for future use.
"""

from .models import (
    Base, Scan, Finding, Asset, Host, Port, Subdomain,
    ScanType, ScanStatus, Severity, FindingStatus, PortState
)

from .database import (
    DatabaseManager, get_db_session, init_database,
    get_db_manager, db_session_scope
)

from .repositories import (
    ScanRepository,
    FindingRepository,
    AssetRepository,
    HostRepository
)

from .parsers import (
    NmapParser, AmassParser, BBOTParser, ShodanParser,
    get_parser, parse_scan_output
)

__all__ = [
    # Models & Enums
    'Base',
    'Scan',
    'Finding',
    'Asset',
    'Host',
    'Port',
    'Subdomain',
    'ScanType',
    'ScanStatus',
    'Severity',
    'FindingStatus',
    'PortState',

    # Database Management
    'DatabaseManager',
    'get_db_session',
    'get_db_manager',
    'init_database',
    'db_session_scope',

    # Repositories
    'ScanRepository',
    'FindingRepository',
    'AssetRepository',
    'HostRepository',

    # Parsers
    'NmapParser',
    'AmassParser',
    'BBOTParser',
    'ShodanParser',
    'get_parser',
    'parse_scan_output',
]
