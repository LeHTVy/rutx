"""
Enhanced Database Models for Tool-Specific Data & LLM Intelligence

This module extends the base models to provide:
1. Tool-specific tables (NmapResult, ShodanResult, BBOTResult, AmassResult)
2. Enrichment tables (CVE, ThreatIntel, ServiceIntel)
3. LLM context cache for efficient queries
4. Generated reports storage
5. Scan sessions for grouping related scans

Architecture:
    User Query -> Phase 1 (Tool Selection)
              -> Phase 2 (Execution & Persistence to these models)
              -> Phase 3 (Intelligence Analysis using enriched context)
              -> Phase 4 (Report Generation & Storage)
"""

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional, List, Dict, Any

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Enum, Table, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship

from .models import Base, generate_uuid, ScanType, Severity


# ============================================================================
# SCAN SESSION - Groups related scans together
# ============================================================================

class ScanSession(Base):
    """
    Groups related scans into a single session for LLM analysis.
    A session represents one user request that may spawn multiple tool runs.
    """
    __tablename__ = 'scan_sessions'

    id = Column(String(36), primary_key=True, default=generate_uuid)

    # Session metadata
    user_prompt = Column(Text, nullable=False)  # Original user request
    target = Column(String(500), nullable=False, index=True)
    session_type = Column(String(50), nullable=True)  # subdomain_enum, port_scan, vuln_scan

    # Phase tracking
    current_phase = Column(Integer, default=1)  # 1-4
    phase1_completed = Column(DateTime, nullable=True)
    phase2_completed = Column(DateTime, nullable=True)
    phase3_completed = Column(DateTime, nullable=True)
    phase4_completed = Column(DateTime, nullable=True)

    # Tool selection (Phase 1 result)
    selected_tools = Column(JSON, nullable=True)  # [{tool, args}, ...]
    tool_selection_reasoning = Column(Text, nullable=True)

    # Execution status
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    elapsed_seconds = Column(Float, nullable=True)

    # Analysis results (Phase 3)
    analysis_json = Column(JSON, nullable=True)  # Structured analysis
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)  # CRITICAL, HIGH, MEDIUM, LOW

    # Relationships
    nmap_results = relationship("NmapResult", back_populates="session", cascade="all, delete-orphan")
    shodan_results = relationship("ShodanResult", back_populates="session", cascade="all, delete-orphan")
    bbot_results = relationship("BBOTResult", back_populates="session", cascade="all, delete-orphan")
    amass_results = relationship("AmassResult", back_populates="session", cascade="all, delete-orphan")
    generated_reports = relationship("GeneratedReport", back_populates="session", cascade="all, delete-orphan")

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_prompt": self.user_prompt,
            "target": self.target,
            "session_type": self.session_type,
            "current_phase": self.current_phase,
            "status": self.status,
            "selected_tools": self.selected_tools,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "elapsed_seconds": self.elapsed_seconds
        }


# ============================================================================
# TOOL-SPECIFIC RESULT MODELS
# ============================================================================

class NmapResult(Base):
    """
    Stores parsed Nmap scan results for easy LLM querying.
    Human-friendly and queryable by IP, port, service.
    """
    __tablename__ = 'nmap_results'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    session_id = Column(String(36), ForeignKey('scan_sessions.id'), nullable=True, index=True)
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=True, index=True)

    # Target info
    target = Column(String(500), nullable=False, index=True)
    scan_type = Column(String(50), nullable=True)  # quick_scan, vuln_scan, aggressive, etc.

    # Execution
    command = Column(Text, nullable=True)
    xml_output_path = Column(String(500), nullable=True)
    elapsed_seconds = Column(Float, nullable=True)
    executed_at = Column(DateTime, default=datetime.utcnow)

    # Host summary (denormalized for fast queries)
    hosts_up = Column(Integer, default=0)
    hosts_down = Column(Integer, default=0)
    total_open_ports = Column(Integer, default=0)
    total_filtered_ports = Column(Integer, default=0)

    # Parsed data (structured for LLM)
    hosts_data = Column(JSON, nullable=True)  # [{ip, hostname, os, ports: [...]}]
    services_detected = Column(JSON, nullable=True)  # [{port, service, product, version}]
    vulnerabilities = Column(JSON, nullable=True)  # From --script vuln
    os_detections = Column(JSON, nullable=True)  # [{ip, os, accuracy}]

    # Scripts output (NSE)
    script_results = Column(JSON, nullable=True)  # Parsed NSE output

    # Raw output (for fallback)
    raw_stdout = Column(Text, nullable=True)

    # Relationships
    session = relationship("ScanSession", back_populates="nmap_results")

    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_nmap_target_type', 'target', 'scan_type'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "scan_type": self.scan_type,
            "hosts_up": self.hosts_up,
            "total_open_ports": self.total_open_ports,
            "hosts_data": self.hosts_data,
            "services_detected": self.services_detected,
            "vulnerabilities": self.vulnerabilities,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None
        }

    def get_open_ports_summary(self) -> List[str]:
        """Get human-readable list of open ports."""
        if not self.services_detected:
            return []
        return [
            f"{s.get('port')}/{s.get('protocol', 'tcp')} - {s.get('service', 'unknown')} ({s.get('product', '')} {s.get('version', '')})"
            for s in self.services_detected
        ]


class ShodanResult(Base):
    """
    Stores Shodan API results for OSINT enrichment.
    """
    __tablename__ = 'shodan_results'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    session_id = Column(String(36), ForeignKey('scan_sessions.id'), nullable=True, index=True)

    # Query info
    ip_address = Column(String(45), nullable=False, index=True)
    query_type = Column(String(50), nullable=True)  # host_lookup, search, etc.
    executed_at = Column(DateTime, default=datetime.utcnow)

    # Organization info
    organization = Column(String(255), nullable=True)
    isp = Column(String(255), nullable=True)
    asn = Column(String(20), nullable=True)

    # Location
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)

    # Technical details
    hostnames = Column(JSON, nullable=True)  # List of hostnames
    domains = Column(JSON, nullable=True)  # Associated domains
    open_ports = Column(JSON, nullable=True)  # [22, 80, 443, ...]

    # Services (detailed)
    services = Column(JSON, nullable=True)  # [{port, product, version, banner}]

    # Security/Threat data
    vulns = Column(JSON, nullable=True)  # List of CVE IDs
    tags = Column(JSON, nullable=True)  # Shodan tags (honeypot, malware, etc.)
    threat_level = Column(String(20), nullable=True)  # HIGH, MEDIUM, LOW, UNKNOWN
    threat_indicators = Column(JSON, nullable=True)  # Detailed threat info

    # Raw response
    raw_data = Column(JSON, nullable=True)

    # Relationships
    session = relationship("ScanSession", back_populates="shodan_results")

    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_shodan_ip', 'ip_address'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "organization": self.organization,
            "isp": self.isp,
            "country": self.country,
            "city": self.city,
            "open_ports": self.open_ports,
            "vulns": self.vulns,
            "threat_level": self.threat_level,
            "threat_indicators": self.threat_indicators,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None
        }


class BBOTResult(Base):
    """
    Stores BBOT scan results.
    """
    __tablename__ = 'bbot_results'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    session_id = Column(String(36), ForeignKey('scan_sessions.id'), nullable=True, index=True)

    # Scan info
    target = Column(String(500), nullable=False, index=True)
    preset = Column(String(50), nullable=True)  # subdomain-enum, web-basic, etc.
    modules_used = Column(JSON, nullable=True)

    # Execution
    command = Column(Text, nullable=True)
    output_directory = Column(String(500), nullable=True)
    json_output_path = Column(String(500), nullable=True)
    elapsed_seconds = Column(Float, nullable=True)
    executed_at = Column(DateTime, default=datetime.utcnow)

    # Summary counts
    total_events = Column(Integer, default=0)
    subdomains_found = Column(Integer, default=0)
    urls_found = Column(Integer, default=0)
    technologies_found = Column(Integer, default=0)

    # Parsed data
    subdomains = Column(JSON, nullable=True)  # List of discovered subdomains
    urls = Column(JSON, nullable=True)  # Discovered URLs
    technologies = Column(JSON, nullable=True)  # Web technologies
    event_types = Column(JSON, nullable=True)  # {DNS_NAME: 50, URL: 20, ...}

    # High-value targets (for LLM)
    high_value_targets = Column(JSON, nullable=True)  # Admin, API, dev subdomains

    # Relationships
    session = relationship("ScanSession", back_populates="bbot_results")

    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_bbot_target_preset', 'target', 'preset'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "preset": self.preset,
            "total_events": self.total_events,
            "subdomains_found": self.subdomains_found,
            "subdomains": self.subdomains[:100] if self.subdomains else [],
            "high_value_targets": self.high_value_targets,
            "technologies": self.technologies,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None
        }


class AmassResult(Base):
    """
    Stores Amass enumeration results.
    """
    __tablename__ = 'amass_results'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    session_id = Column(String(36), ForeignKey('scan_sessions.id'), nullable=True, index=True)

    # Scan info
    domain = Column(String(255), nullable=False, index=True)
    mode = Column(String(20), nullable=True)  # passive, active, brute

    # Execution
    command = Column(Text, nullable=True)
    json_output_path = Column(String(500), nullable=True)
    elapsed_seconds = Column(Float, nullable=True)
    executed_at = Column(DateTime, default=datetime.utcnow)

    # Results
    subdomains_found = Column(Integer, default=0)
    subdomains = Column(JSON, nullable=True)  # Full list

    # Categorized (for LLM)
    subdomains_by_category = Column(JSON, nullable=True)  # {api: [], admin: [], www: []}
    high_value_targets = Column(JSON, nullable=True)

    # IP resolution
    resolved_ips = Column(JSON, nullable=True)  # {subdomain: [ips]}

    # Relationships
    session = relationship("ScanSession", back_populates="amass_results")

    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_amass_domain_mode', 'domain', 'mode'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "domain": self.domain,
            "mode": self.mode,
            "subdomains_found": self.subdomains_found,
            "subdomains": self.subdomains[:100] if self.subdomains else [],
            "subdomains_by_category": self.subdomains_by_category,
            "high_value_targets": self.high_value_targets,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None
        }


# ============================================================================
# ENRICHMENT TABLES
# ============================================================================

class CVEEnrichment(Base):
    """
    Cached CVE data for vulnerability enrichment.
    """
    __tablename__ = 'cve_enrichment'

    cve_id = Column(String(20), primary_key=True)  # CVE-2021-44228

    # Basic info
    description = Column(Text, nullable=True)
    published_date = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)

    # Scoring
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v3_vector = Column(String(100), nullable=True)
    cvss_v2_score = Column(Float, nullable=True)

    # Attack details
    attack_vector = Column(String(50), nullable=True)  # NETWORK, LOCAL, etc.
    attack_complexity = Column(String(20), nullable=True)  # LOW, HIGH
    privileges_required = Column(String(20), nullable=True)
    user_interaction = Column(String(20), nullable=True)

    # Impact
    confidentiality_impact = Column(String(20), nullable=True)
    integrity_impact = Column(String(20), nullable=True)
    availability_impact = Column(String(20), nullable=True)

    # References
    references = Column(JSON, nullable=True)  # URLs
    cwe_ids = Column(JSON, nullable=True)  # Associated CWEs

    # Exploit info
    exploit_available = Column(Boolean, default=False)
    exploit_maturity = Column(String(50), nullable=True)

    # Affected products (CPE)
    affected_products = Column(JSON, nullable=True)

    # LLM-friendly summary
    remediation_summary = Column(Text, nullable=True)

    # Cache metadata
    fetched_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_v3_score": self.cvss_v3_score,
            "attack_vector": self.attack_vector,
            "exploit_available": self.exploit_available,
            "remediation_summary": self.remediation_summary
        }


class ThreatIntelligence(Base):
    """
    Threat intelligence for IPs and domains.
    """
    __tablename__ = 'threat_intelligence'

    id = Column(String(36), primary_key=True, default=generate_uuid)

    # Indicator
    indicator = Column(String(255), nullable=False, index=True)  # IP or domain
    indicator_type = Column(String(20), nullable=False)  # ip, domain, hash

    # Threat assessment
    reputation_score = Column(Integer, nullable=True)  # 0-100
    threat_level = Column(String(20), nullable=True)  # benign, suspicious, malicious
    threat_types = Column(JSON, nullable=True)  # [botnet, c2, malware, phishing]

    # Context
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    times_reported = Column(Integer, default=0)

    # Sources
    sources = Column(JSON, nullable=True)  # [abuseipdb, virustotal, greynoise]
    raw_data = Column(JSON, nullable=True)

    # Geolocation (for IPs)
    country_code = Column(String(2), nullable=True)
    city = Column(String(100), nullable=True)
    asn = Column(Integer, nullable=True)
    asn_org = Column(String(255), nullable=True)

    # Cache metadata
    enriched_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index('idx_threat_indicator', 'indicator'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "reputation_score": self.reputation_score,
            "threat_level": self.threat_level,
            "threat_types": self.threat_types,
            "country_code": self.country_code
        }


# ============================================================================
# LLM CONTEXT & REPORTS
# ============================================================================

class LLMContextCache(Base):
    """
    Cached context for LLM to avoid expensive queries.
    """
    __tablename__ = 'llm_context_cache'

    id = Column(String(36), primary_key=True, default=generate_uuid)

    # Context identification
    context_type = Column(String(50), nullable=False, index=True)
    # Types: scan_summary, finding_analysis, host_inventory, subdomain_report
    session_id = Column(String(36), ForeignKey('scan_sessions.id'), nullable=True, index=True)
    target = Column(String(255), nullable=True)

    # Cached data
    context_json = Column(JSON, nullable=False)  # Structured context
    context_text = Column(Text, nullable=True)  # Pre-formatted narrative

    # Token estimation (for context window management)
    estimated_tokens = Column(Integer, nullable=True)

    # Cache metadata
    generated_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    is_valid = Column(Boolean, default=True)

    __table_args__ = (
        Index('idx_context_type_session', 'context_type', 'session_id'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "context_type": self.context_type,
            "target": self.target,
            "context_json": self.context_json,
            "estimated_tokens": self.estimated_tokens,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None
        }


class GeneratedReport(Base):
    """
    Stores LLM-generated reports (Phase 4 output).
    """
    __tablename__ = 'generated_reports'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    session_id = Column(String(36), ForeignKey('scan_sessions.id'), nullable=True, index=True)

    # Report metadata
    report_type = Column(String(50), nullable=False)  # executive, technical, compliance
    title = Column(String(255), nullable=True)
    target = Column(String(255), nullable=True, index=True)

    # Content
    content = Column(Text, nullable=False)  # Full report (Markdown)
    executive_summary = Column(Text, nullable=True)
    format = Column(String(20), default="markdown")  # markdown, html, json

    # Analysis metadata
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)

    # LLM metadata
    model_used = Column(String(100), nullable=True)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)

    # Relationships
    session = relationship("ScanSession", back_populates="generated_reports")

    generated_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_report_type_target', 'report_type', 'target'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "report_type": self.report_type,
            "title": self.title,
            "target": self.target,
            "risk_level": self.risk_level,
            "findings_count": self.findings_count,
            "executive_summary": self.executive_summary,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None
        }


# ============================================================================
# UTILITY FUNCTIONS FOR LLM QUERIES
# ============================================================================

def get_nmap_summary_for_target(session, target: str) -> Dict[str, Any]:
    """Get summarized Nmap data for a target - optimized for LLM."""
    results = session.query(NmapResult).filter(
        NmapResult.target == target
    ).order_by(NmapResult.executed_at.desc()).limit(5).all()

    return {
        "target": target,
        "scan_count": len(results),
        "latest_scan": results[0].to_dict() if results else None,
        "all_open_ports": list(set(
            port for r in results
            for port in (r.open_ports or [])
        )),
        "all_services": list(set(
            f"{s.get('port')}/{s.get('service')}"
            for r in results
            for s in (r.services_detected or [])
        ))
    }


def get_subdomain_summary_for_domain(session, domain: str) -> Dict[str, Any]:
    """Get combined Amass + BBOT subdomain data for LLM."""
    amass = session.query(AmassResult).filter(
        AmassResult.domain == domain
    ).order_by(AmassResult.executed_at.desc()).first()

    bbot = session.query(BBOTResult).filter(
        BBOTResult.target.contains(domain)
    ).order_by(BBOTResult.executed_at.desc()).first()

    all_subdomains = set()
    if amass and amass.subdomains:
        all_subdomains.update(amass.subdomains)
    if bbot and bbot.subdomains:
        all_subdomains.update(bbot.subdomains)

    return {
        "domain": domain,
        "total_unique_subdomains": len(all_subdomains),
        "amass_count": amass.subdomains_found if amass else 0,
        "bbot_count": bbot.subdomains_found if bbot else 0,
        "high_value_targets": (amass.high_value_targets if amass else []) +
                              (bbot.high_value_targets if bbot else []),
        "subdomains_sample": sorted(list(all_subdomains))[:50]
    }


def get_threat_context_for_ip(session, ip: str) -> Dict[str, Any]:
    """Get threat intelligence context for an IP."""
    shodan = session.query(ShodanResult).filter(
        ShodanResult.ip_address == ip
    ).order_by(ShodanResult.executed_at.desc()).first()

    threat = session.query(ThreatIntelligence).filter(
        ThreatIntelligence.indicator == ip
    ).first()

    return {
        "ip_address": ip,
        "shodan_data": shodan.to_dict() if shodan else None,
        "threat_intel": threat.to_dict() if threat else None,
        "is_malicious": threat.threat_level == "malicious" if threat else None
    }
