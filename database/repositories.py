"""
Repository Pattern - Data Access Layer
Provides clean interfaces for CRUD operations on database entities.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func, and_, or_

from .models import (
    Scan, Host, Port, Finding, Asset, Subdomain,
    ScanType, ScanStatus, Severity, FindingStatus, PortState
)
from .parsers import parse_scan_output


class BaseRepository:
    """Base repository with common CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def commit(self):
        """Commit current transaction."""
        self.session.commit()

    def rollback(self):
        """Rollback current transaction."""
        self.session.rollback()

    def flush(self):
        """Flush pending changes."""
        self.session.flush()


class ScanRepository(BaseRepository):
    """
    Repository for Scan entity operations.
    Handles scan creation, updates, and queries.
    """

    def create(
        self,
        tool: ScanType,
        target: str,
        scan_profile: Optional[str] = None,
        command: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> Scan:
        """Create a new scan record."""
        scan = Scan(
            tool=tool,
            target=target,
            scan_profile=scan_profile,
            command=command,
            session_id=session_id,
            status=ScanStatus.PENDING,
            start_time=datetime.utcnow()
        )
        self.session.add(scan)
        self.session.flush()  # Get ID without committing
        return scan

    def get_by_id(self, scan_id: str) -> Optional[Scan]:
        """Get scan by ID with related entities."""
        return (
            self.session.query(Scan)
            .options(
                joinedload(Scan.hosts).joinedload(Host.ports),
                joinedload(Scan.findings),
                joinedload(Scan.subdomains)
            )
            .filter(Scan.id == scan_id)
            .first()
        )

    def get_recent(self, limit: int = 10) -> List[Scan]:
        """Get most recent scans."""
        return (
            self.session.query(Scan)
            .order_by(desc(Scan.created_at))
            .limit(limit)
            .all()
        )

    def get_by_target(self, target: str, limit: int = 10) -> List[Scan]:
        """Get scans for a specific target."""
        return (
            self.session.query(Scan)
            .filter(Scan.target.ilike(f"%{target}%"))
            .order_by(desc(Scan.created_at))
            .limit(limit)
            .all()
        )

    def get_by_tool(self, tool: ScanType, limit: int = 10) -> List[Scan]:
        """Get scans by tool type."""
        return (
            self.session.query(Scan)
            .filter(Scan.tool == tool)
            .order_by(desc(Scan.created_at))
            .limit(limit)
            .all()
        )

    def get_by_session(self, session_id: str) -> List[Scan]:
        """Get all scans for a session."""
        return (
            self.session.query(Scan)
            .filter(Scan.session_id == session_id)
            .order_by(Scan.created_at)
            .all()
        )

    def update_status(
        self,
        scan_id: str,
        status: ScanStatus,
        end_time: Optional[datetime] = None,
        elapsed_seconds: Optional[float] = None
    ) -> Optional[Scan]:
        """Update scan status."""
        scan = self.session.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = status
            if end_time:
                scan.end_time = end_time
            if elapsed_seconds:
                scan.elapsed_seconds = elapsed_seconds
            self.session.flush()
        return scan

    def update_results(
        self,
        scan_id: str,
        raw_output_file: Optional[str] = None,
        json_output_file: Optional[str] = None,
        hosts_discovered: int = 0,
        ports_discovered: int = 0,
        findings_count: int = 0,
        subdomains_count: int = 0
    ) -> Optional[Scan]:
        """Update scan results metadata."""
        scan = self.session.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            if raw_output_file:
                scan.raw_output_file = raw_output_file
            if json_output_file:
                scan.json_output_file = json_output_file
            scan.hosts_discovered = hosts_discovered
            scan.ports_discovered = ports_discovered
            scan.findings_count = findings_count
            scan.subdomains_count = subdomains_count
            self.session.flush()
        return scan

    def complete_scan_with_results(
        self,
        scan_id: str,
        output_file: str,
        elapsed_seconds: float = 0,
        stdout: Optional[str] = None,
        return_code: int = 0
    ) -> Tuple[Scan, List[Host], List[Finding], List[Subdomain]]:
        """
        Complete a scan and parse its results into the database.

        This is the main entry point for saving scan results:
        1. Updates scan status to COMPLETED
        2. Parses the output file
        3. Creates Host, Port, Finding, Subdomain entities
        4. Links everything together

        Returns:
            Tuple of (scan, hosts, findings, subdomains)
        """
        scan = self.get_by_id(scan_id)
        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")

        # Update scan status
        scan.status = ScanStatus.COMPLETED
        scan.end_time = datetime.utcnow()
        scan.elapsed_seconds = elapsed_seconds
        scan.stdout = stdout
        scan.return_code = return_code

        # Determine output file type
        if output_file.endswith('.xml'):
            scan.raw_output_file = output_file
        else:
            scan.json_output_file = output_file

        # Parse output and create entities
        hosts, findings, subdomains = parse_scan_output(scan, output_file)

        # Add entities to session
        for host in hosts:
            host.scan_id = scan.id
            self.session.add(host)

        for finding in findings:
            finding.scan_id = scan.id
            self.session.add(finding)

        for subdomain in subdomains:
            subdomain.scan_id = scan.id
            self.session.add(subdomain)

        # Update summary counts
        scan.hosts_discovered = len(hosts)
        scan.ports_discovered = sum(len(h.ports) for h in hosts)
        scan.findings_count = len(findings)
        scan.subdomains_count = len(subdomains)

        self.session.flush()

        return scan, hosts, findings, subdomains

    def get_stats(self, days: int = 30) -> Dict[str, Any]:
        """Get scan statistics for the last N days."""
        cutoff = datetime.utcnow() - timedelta(days=days)

        total = self.session.query(func.count(Scan.id)).filter(
            Scan.created_at >= cutoff
        ).scalar()

        by_tool = (
            self.session.query(Scan.tool, func.count(Scan.id))
            .filter(Scan.created_at >= cutoff)
            .group_by(Scan.tool)
            .all()
        )

        by_status = (
            self.session.query(Scan.status, func.count(Scan.id))
            .filter(Scan.created_at >= cutoff)
            .group_by(Scan.status)
            .all()
        )

        return {
            "total_scans": total,
            "by_tool": {str(t.value): c for t, c in by_tool},
            "by_status": {str(s.value): c for s, c in by_status},
            "period_days": days
        }


class FindingRepository(BaseRepository):
    """
    Repository for Finding entity operations.
    Handles vulnerability tracking and analysis.
    """

    def create(
        self,
        scan_id: str,
        finding_type: str,
        title: str,
        severity: Severity = Severity.INFO,
        **kwargs
    ) -> Finding:
        """Create a new finding."""
        finding = Finding(
            scan_id=scan_id,
            finding_type=finding_type,
            title=title,
            severity=severity,
            **kwargs
        )
        self.session.add(finding)
        self.session.flush()
        return finding

    def get_by_id(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID."""
        return self.session.query(Finding).filter(Finding.id == finding_id).first()

    def get_by_scan(self, scan_id: str) -> List[Finding]:
        """Get all findings for a scan."""
        return (
            self.session.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .order_by(desc(Finding.severity))
            .all()
        )

    def get_by_severity(self, severity: Severity, limit: int = 100) -> List[Finding]:
        """Get findings by severity level."""
        return (
            self.session.query(Finding)
            .filter(Finding.severity == severity)
            .order_by(desc(Finding.created_at))
            .limit(limit)
            .all()
        )

    def get_critical_and_high(self, limit: int = 50) -> List[Finding]:
        """Get critical and high severity findings."""
        return (
            self.session.query(Finding)
            .filter(Finding.severity.in_([Severity.CRITICAL, Severity.HIGH]))
            .filter(Finding.status.in_([FindingStatus.NEW, FindingStatus.CONFIRMED]))
            .order_by(desc(Finding.severity), desc(Finding.created_at))
            .limit(limit)
            .all()
        )

    def get_by_cve(self, cve_id: str) -> List[Finding]:
        """Get findings by CVE ID."""
        return (
            self.session.query(Finding)
            .filter(Finding.cve_id == cve_id)
            .all()
        )

    def search(
        self,
        query: str,
        severity: Optional[Severity] = None,
        status: Optional[FindingStatus] = None,
        limit: int = 50
    ) -> List[Finding]:
        """Search findings by title or description."""
        filters = [
            or_(
                Finding.title.ilike(f"%{query}%"),
                Finding.description.ilike(f"%{query}%")
            )
        ]

        if severity:
            filters.append(Finding.severity == severity)
        if status:
            filters.append(Finding.status == status)

        return (
            self.session.query(Finding)
            .filter(and_(*filters))
            .order_by(desc(Finding.created_at))
            .limit(limit)
            .all()
        )

    def update_status(
        self,
        finding_id: str,
        status: FindingStatus,
        notes: Optional[str] = None
    ) -> Optional[Finding]:
        """Update finding status."""
        finding = self.get_by_id(finding_id)
        if finding:
            finding.status = status
            if notes:
                finding.notes = notes
            if status == FindingStatus.REMEDIATED:
                finding.remediated_at = datetime.utcnow()
            self.session.flush()
        return finding

    def get_stats(self) -> Dict[str, Any]:
        """Get finding statistics."""
        by_severity = (
            self.session.query(Finding.severity, func.count(Finding.id))
            .group_by(Finding.severity)
            .all()
        )

        by_status = (
            self.session.query(Finding.status, func.count(Finding.id))
            .group_by(Finding.status)
            .all()
        )

        by_type = (
            self.session.query(Finding.finding_type, func.count(Finding.id))
            .group_by(Finding.finding_type)
            .order_by(desc(func.count(Finding.id)))
            .limit(10)
            .all()
        )

        total = self.session.query(func.count(Finding.id)).scalar()

        return {
            "total_findings": total,
            "by_severity": {s.value: c for s, c in by_severity},
            "by_status": {s.value: c for s, c in by_status},
            "top_types": {t: c for t, c in by_type}
        }


class AssetRepository(BaseRepository):
    """
    Repository for Asset entity operations.
    Handles asset inventory management.
    """

    def create(
        self,
        name: str,
        ip_address: Optional[str] = None,
        domain: Optional[str] = None,
        **kwargs
    ) -> Asset:
        """Create a new asset."""
        asset = Asset(
            name=name,
            ip_address=ip_address,
            domain=domain,
            **kwargs
        )
        self.session.add(asset)
        self.session.flush()
        return asset

    def get_by_id(self, asset_id: str) -> Optional[Asset]:
        """Get asset by ID with related entities."""
        return (
            self.session.query(Asset)
            .options(
                joinedload(Asset.hosts),
                joinedload(Asset.findings),
                joinedload(Asset.subdomains)
            )
            .filter(Asset.id == asset_id)
            .first()
        )

    def get_by_ip(self, ip_address: str) -> Optional[Asset]:
        """Get asset by IP address."""
        return (
            self.session.query(Asset)
            .filter(Asset.ip_address == ip_address)
            .first()
        )

    def get_by_domain(self, domain: str) -> Optional[Asset]:
        """Get asset by domain."""
        return (
            self.session.query(Asset)
            .filter(Asset.domain == domain)
            .first()
        )

    def get_or_create(
        self,
        name: str,
        ip_address: Optional[str] = None,
        domain: Optional[str] = None,
        **kwargs
    ) -> Tuple[Asset, bool]:
        """
        Get existing asset or create new one.

        Returns:
            Tuple of (asset, created) where created is True if new asset was created
        """
        # Try to find by IP or domain
        asset = None
        if ip_address:
            asset = self.get_by_ip(ip_address)
        if not asset and domain:
            asset = self.get_by_domain(domain)

        if asset:
            return asset, False

        # Create new asset
        asset = self.create(name, ip_address, domain, **kwargs)
        return asset, True

    def get_all(self, active_only: bool = True) -> List[Asset]:
        """Get all assets."""
        query = self.session.query(Asset)
        if active_only:
            query = query.filter(Asset.is_active == True)
        return query.order_by(Asset.name).all()

    def get_by_criticality(self, criticality: str) -> List[Asset]:
        """Get assets by criticality level."""
        return (
            self.session.query(Asset)
            .filter(Asset.criticality == criticality)
            .filter(Asset.is_active == True)
            .all()
        )

    def update_risk_score(self, asset_id: str) -> Optional[Asset]:
        """
        Calculate and update asset risk score based on findings.
        """
        asset = self.get_by_id(asset_id)
        if not asset:
            return None

        # Count findings by severity
        findings = asset.findings
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL and f.status != FindingStatus.REMEDIATED)
        high = sum(1 for f in findings if f.severity == Severity.HIGH and f.status != FindingStatus.REMEDIATED)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM and f.status != FindingStatus.REMEDIATED)
        low = sum(1 for f in findings if f.severity == Severity.LOW and f.status != FindingStatus.REMEDIATED)

        # Simple weighted risk score (0-100)
        score = min(100, (critical * 25) + (high * 10) + (medium * 3) + (low * 1))

        asset.risk_score = score
        asset.open_findings_count = critical + high + medium + low
        asset.critical_findings_count = critical

        self.session.flush()
        return asset

    def link_to_scan(self, asset_id: str, scan_id: str):
        """Link an asset to a scan."""
        asset = self.session.query(Asset).filter(Asset.id == asset_id).first()
        scan = self.session.query(Scan).filter(Scan.id == scan_id).first()
        if asset and scan:
            if scan not in asset.scans:
                asset.scans.append(scan)
                asset.last_scan_date = scan.start_time
            self.session.flush()


class HostRepository(BaseRepository):
    """
    Repository for Host entity operations.
    Handles host discovery and port aggregation.
    """

    def create(
        self,
        scan_id: str,
        ip_address: str,
        hostname: Optional[str] = None,
        **kwargs
    ) -> Host:
        """Create a new host."""
        host = Host(
            scan_id=scan_id,
            ip_address=ip_address,
            hostname=hostname,
            **kwargs
        )
        self.session.add(host)
        self.session.flush()
        return host

    def get_by_id(self, host_id: str) -> Optional[Host]:
        """Get host by ID with ports."""
        return (
            self.session.query(Host)
            .options(joinedload(Host.ports))
            .filter(Host.id == host_id)
            .first()
        )

    def get_by_ip(self, ip_address: str) -> List[Host]:
        """Get all host records for an IP (across scans)."""
        return (
            self.session.query(Host)
            .filter(Host.ip_address == ip_address)
            .order_by(desc(Host.created_at))
            .all()
        )

    def get_by_scan(self, scan_id: str) -> List[Host]:
        """Get all hosts discovered in a scan."""
        return (
            self.session.query(Host)
            .options(joinedload(Host.ports))
            .filter(Host.scan_id == scan_id)
            .all()
        )

    def get_with_open_ports(self, min_ports: int = 1) -> List[Host]:
        """Get hosts with at least N open ports."""
        return (
            self.session.query(Host)
            .filter(Host.open_ports >= min_ports)
            .order_by(desc(Host.open_ports))
            .all()
        )

    def aggregate_ports_for_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Aggregate port data across all scans for an IP.
        Useful for trend analysis.
        """
        hosts = self.get_by_ip(ip_address)

        all_ports = {}
        scan_history = []

        for host in hosts:
            scan_info = {
                "scan_id": host.scan_id,
                "scan_date": host.created_at.isoformat() if host.created_at else None,
                "open_ports": host.open_ports
            }
            scan_history.append(scan_info)

            for port in host.ports:
                port_key = f"{port.port_number}/{port.protocol}"
                if port_key not in all_ports:
                    all_ports[port_key] = {
                        "port": port.port_number,
                        "protocol": port.protocol,
                        "states": [],
                        "services": set()
                    }
                all_ports[port_key]["states"].append(port.state.value if port.state else "unknown")
                if port.service_name:
                    all_ports[port_key]["services"].add(port.service_name)

        # Convert sets to lists for JSON serialization
        for port_info in all_ports.values():
            port_info["services"] = list(port_info["services"])

        return {
            "ip_address": ip_address,
            "total_scans": len(hosts),
            "ports": all_ports,
            "scan_history": scan_history
        }
