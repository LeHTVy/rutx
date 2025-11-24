"""
Database Module - Data Persistence Layer for Security Scanning Framework
Provides SQLite/SQLAlchemy-based storage for scans, findings, assets, and hosts.

Architecture:
    models.py       - SQLAlchemy ORM models (Scan, Finding, Host, Asset, etc.)
    database.py     - Database connection and session management
    parsers.py      - Tool output parsers (Nmap XML, Amass JSON, BBOT JSON)
    repositories.py - Data access layer with CRUD operations
    service.py      - High-level service layer for tool runners
    reporting.py    - Report generation for LLM consumption
    tool_integration.py - Integration with unified_tool_runner
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
from .service import (
    ScanService, ReportingService,
    save_scan_result, get_context_for_llm
)
from .reporting import (
    PentestReporter,
    get_llm_context, get_findings_context, get_host_context,
    query_database, DATABASE_QUERY_TOOL
)
from .tool_integration import (
    with_database_persistence,
    save_scan_to_database,
    run_nmap_with_db,
    run_amass_with_db,
    run_bbot_with_db,
    run_shodan_with_db
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

    # Services
    'ScanService',
    'ReportingService',
    'save_scan_result',
    'get_context_for_llm',

    # Reporting
    'PentestReporter',
    'get_llm_context',
    'get_findings_context',
    'get_host_context',
    'query_database',
    'DATABASE_QUERY_TOOL',

    # Tool Integration
    'with_database_persistence',
    'save_scan_to_database',
    'run_nmap_with_db',
    'run_amass_with_db',
    'run_bbot_with_db',
    'run_shodan_with_db'
]
