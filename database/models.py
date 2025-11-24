"""
Database Models - SQLAlchemy ORM for Security Scanning Framework
Defines the core data structures for persistent storage of scan results.
"""

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional, List, Dict, Any

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Enum, Table, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON

Base = declarative_base()


# Enums for structured data
class ScanStatus(PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(PyEnum):
    NMAP = "nmap"
    AMASS = "amass"
    BBOT = "bbot"
    SHODAN = "shodan"
    NIKTO = "nikto"
    SQLMAP = "sqlmap"
    ZAP = "zap"
    CUSTOM = "custom"


class Severity(PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(PyEnum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"


class PortState(PyEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


# Association table for many-to-many: Scans <-> Assets
scan_asset_association = Table(
    'scan_asset_association',
    Base.metadata,
    Column('scan_id', String(36), ForeignKey('scans.id'), primary_key=True),
    Column('asset_id', String(36), ForeignKey('assets.id'), primary_key=True)
)


def generate_uuid() -> str:
    """Generate a UUID string for primary keys."""
    return str(uuid.uuid4())


class Scan(Base):
    """
    Represents a single security scan execution.
    Links to findings, hosts, and assets discovered during the scan.
    """
    __tablename__ = 'scans'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    session_id = Column(String(36), index=True, nullable=True)  # Group related scans

    # Scan metadata
    tool = Column(Enum(ScanType), nullable=False, index=True)
    scan_profile = Column(String(100), nullable=True)  # e.g., "quick", "comprehensive", "vuln"
    target = Column(String(500), nullable=False, index=True)
    command = Column(Text, nullable=True)

    # Execution details
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    start_time = Column(DateTime, default=datetime.utcnow, index=True)
    end_time = Column(DateTime, nullable=True)
    elapsed_seconds = Column(Float, nullable=True)

    # Output files
    raw_output_file = Column(String(500), nullable=True)  # XML, JSON file path
    json_output_file = Column(String(500), nullable=True)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    return_code = Column(Integer, nullable=True)

    # Summary statistics
    hosts_discovered = Column(Integer, default=0)
    ports_discovered = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    subdomains_count = Column(Integer, default=0)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = Column(Text, nullable=True)

    # Relationships
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    assets = relationship("Asset", secondary=scan_asset_association, back_populates="scans")

    # Indexes
    __table_args__ = (
        Index('idx_scan_tool_target', 'tool', 'target'),
        Index('idx_scan_session_status', 'session_id', 'status'),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "tool": self.tool.value if self.tool else None,
            "scan_profile": self.scan_profile,
            "target": self.target,
            "command": self.command,
            "status": self.status.value if self.status else None,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "elapsed_seconds": self.elapsed_seconds,
            "raw_output_file": self.raw_output_file,
            "json_output_file": self.json_output_file,
            "hosts_discovered": self.hosts_discovered,
            "ports_discovered": self.ports_discovered,
            "findings_count": self.findings_count,
            "subdomains_count": self.subdomains_count,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class Host(Base):
    """
    Represents a discovered host from network scanning.
    Contains aggregated port and service information.
    """
    __tablename__ = 'hosts'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey('assets.id'), nullable=True, index=True)

    # Host identification
    ip_address = Column(String(45), nullable=False, index=True)  # IPv4 or IPv6
    hostname = Column(String(255), nullable=True)
    mac_address = Column(String(17), nullable=True)

    # Host status
    status = Column(String(20), default="up")  # up, down, unknown
    reason = Column(String(100), nullable=True)  # e.g., "syn-ack"

    # OS detection
    os_name = Column(String(255), nullable=True)
    os_accuracy = Column(Integer, nullable=True)
    os_family = Column(String(100), nullable=True)
    os_vendor = Column(String(100), nullable=True)

    # Port summary
    open_ports = Column(Integer, default=0)
    filtered_ports = Column(Integer, default=0)
    closed_ports = Column(Integer, default=0)

    # Raw data
    raw_data = Column(JSON, nullable=True)  # Store full nmap host data

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="hosts")
    asset = relationship("Asset", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="host")

    __table_args__ = (
        Index('idx_host_ip_scan', 'ip_address', 'scan_id'),
        UniqueConstraint('scan_id', 'ip_address', name='uq_host_scan_ip'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "status": self.status,
            "os_name": self.os_name,
            "os_accuracy": self.os_accuracy,
            "open_ports": self.open_ports,
            "filtered_ports": self.filtered_ports,
            "closed_ports": self.closed_ports,
            "ports": [p.to_dict() for p in self.ports] if self.ports else []
        }


class Port(Base):
    """
    Represents a discovered port on a host.
    """
    __tablename__ = 'ports'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    host_id = Column(String(36), ForeignKey('hosts.id'), nullable=False, index=True)

    # Port details
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")  # tcp, udp
    state = Column(Enum(PortState), default=PortState.OPEN)
    reason = Column(String(100), nullable=True)

    # Service detection
    service_name = Column(String(100), nullable=True)
    product = Column(String(255), nullable=True)
    version = Column(String(100), nullable=True)
    extra_info = Column(String(500), nullable=True)
    cpe = Column(String(255), nullable=True)  # Common Platform Enumeration

    # Script output
    scripts = Column(JSON, nullable=True)  # NSE script results

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    host = relationship("Host", back_populates="ports")
    findings = relationship("Finding", back_populates="port")

    __table_args__ = (
        Index('idx_port_host_number', 'host_id', 'port_number'),
        UniqueConstraint('host_id', 'port_number', 'protocol', name='uq_port_host_number_proto'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "port_number": self.port_number,
            "protocol": self.protocol,
            "state": self.state.value if self.state else None,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
            "scripts": self.scripts
        }


class Finding(Base):
    """
    Represents a security finding/vulnerability discovered during scanning.
    Can be linked to hosts, ports, and assets.
    """
    __tablename__ = 'findings'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False, index=True)
    host_id = Column(String(36), ForeignKey('hosts.id'), nullable=True, index=True)
    port_id = Column(String(36), ForeignKey('ports.id'), nullable=True, index=True)
    asset_id = Column(String(36), ForeignKey('assets.id'), nullable=True, index=True)

    # Finding identification
    finding_type = Column(String(100), nullable=False, index=True)  # e.g., "open_port", "vuln", "misconfig"
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    # Severity and scoring
    severity = Column(Enum(Severity), default=Severity.INFO, index=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)

    # CVE/CWE references
    cve_id = Column(String(20), nullable=True, index=True)  # e.g., "CVE-2021-44228"
    cwe_id = Column(String(20), nullable=True)  # e.g., "CWE-79"
    references = Column(JSON, nullable=True)  # List of URLs

    # Status tracking
    status = Column(Enum(FindingStatus), default=FindingStatus.NEW, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    remediated_at = Column(DateTime, nullable=True)

    # Evidence
    evidence = Column(Text, nullable=True)  # Raw output proving the finding
    affected_component = Column(String(255), nullable=True)  # e.g., "nginx/1.18.0"
    remediation = Column(Text, nullable=True)  # Suggested fix

    # Metadata
    source_tool = Column(String(50), nullable=True)  # Which tool found this
    confidence = Column(Float, default=1.0)  # 0.0-1.0
    false_positive_likelihood = Column(Float, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = Column(Text, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    host = relationship("Host", back_populates="findings")
    port = relationship("Port", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")

    __table_args__ = (
        Index('idx_finding_severity_status', 'severity', 'status'),
        Index('idx_finding_cve', 'cve_id'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "host_id": self.host_id,
            "finding_type": self.finding_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value if self.severity else None,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "status": self.status.value if self.status else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "evidence": self.evidence,
            "affected_component": self.affected_component,
            "remediation": self.remediation,
            "source_tool": self.source_tool,
            "confidence": self.confidence
        }


class Asset(Base):
    """
    Represents a tracked asset in the inventory (CMDB).
    An asset may be associated with multiple scans and findings.
    """
    __tablename__ = 'assets'

    id = Column(String(36), primary_key=True, default=generate_uuid)

    # Asset identification
    name = Column(String(255), nullable=False, index=True)
    asset_type = Column(String(50), nullable=True)  # server, router, workstation, webapp
    ip_address = Column(String(45), nullable=True, index=True)
    hostname = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True, index=True)
    url = Column(String(500), nullable=True)

    # Business context
    environment = Column(String(50), nullable=True)  # production, staging, dev
    criticality = Column(String(20), default="medium")  # critical, high, medium, low
    owner = Column(String(255), nullable=True)
    department = Column(String(100), nullable=True)
    business_function = Column(String(255), nullable=True)

    # Technical details
    operating_system = Column(String(100), nullable=True)
    os_version = Column(String(50), nullable=True)
    services = Column(JSON, nullable=True)  # List of known services
    tags = Column(JSON, nullable=True)  # Custom tags for filtering

    # Risk tracking
    risk_score = Column(Float, nullable=True)  # Calculated risk score
    last_scan_date = Column(DateTime, nullable=True)
    open_findings_count = Column(Integer, default=0)
    critical_findings_count = Column(Integer, default=0)

    # Metadata
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = Column(Text, nullable=True)

    # Relationships
    scans = relationship("Scan", secondary=scan_asset_association, back_populates="assets")
    hosts = relationship("Host", back_populates="asset")
    findings = relationship("Finding", back_populates="asset")
    subdomains = relationship("Subdomain", back_populates="asset")

    __table_args__ = (
        Index('idx_asset_ip_domain', 'ip_address', 'domain'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "asset_type": self.asset_type,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "domain": self.domain,
            "url": self.url,
            "environment": self.environment,
            "criticality": self.criticality,
            "owner": self.owner,
            "risk_score": self.risk_score,
            "last_scan_date": self.last_scan_date.isoformat() if self.last_scan_date else None,
            "open_findings_count": self.open_findings_count,
            "critical_findings_count": self.critical_findings_count,
            "is_active": self.is_active
        }


class Subdomain(Base):
    """
    Represents a discovered subdomain from Amass/BBOT scans.
    """
    __tablename__ = 'subdomains'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey('assets.id'), nullable=True, index=True)

    # Subdomain details
    subdomain = Column(String(255), nullable=False, index=True)
    parent_domain = Column(String(255), nullable=False, index=True)
    ip_addresses = Column(JSON, nullable=True)  # Resolved IPs
    cname = Column(String(255), nullable=True)
    source = Column(String(100), nullable=True)  # amass, bbot, cert transparency

    # Discovery metadata
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_alive = Column(Boolean, nullable=True)  # HTTP check result

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="subdomains")
    asset = relationship("Asset", back_populates="subdomains")

    __table_args__ = (
        Index('idx_subdomain_parent', 'parent_domain'),
        UniqueConstraint('subdomain', 'scan_id', name='uq_subdomain_scan'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "subdomain": self.subdomain,
            "parent_domain": self.parent_domain,
            "ip_addresses": self.ip_addresses,
            "cname": self.cname,
            "source": self.source,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "is_alive": self.is_alive
        }
