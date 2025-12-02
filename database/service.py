"""
Database Service Layer - High-Level Operations
Provides simplified interface for common database operations.
Used by tool runners and agents to persist scan results.
"""

import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

from .database import get_db_manager, db_session_scope
from .models import (
    Scan, Host, Port, Finding, Asset, Subdomain,
    ScanType, ScanStatus, Severity
)
from .repositories import (
    ScanRepository, FindingRepository, AssetRepository, HostRepository
)
from .parsers import parse_scan_output


class ScanService:
    """
    High-level service for scan operations.
    Provides a clean API for tool runners to save results.
    """

    @staticmethod
    def generate_session_id() -> str:
        """Generate a unique session ID for grouping related scans."""
        return str(uuid.uuid4())

    @staticmethod
    def start_scan(
        tool: str,
        target: str,
        scan_profile: Optional[str] = None,
        command: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> str:
        """
        Start a new scan and return its ID.

        Args:
            tool: Tool name (nmap, amass, bbot, shodan)
            target: Scan target (IP, domain, etc.)
            scan_profile: Scan type/profile
            command: Executed command
            session_id: Optional session ID to group scans

        Returns:
            Scan ID (UUID string)
        """
        tool_map = {
            "nmap": ScanType.NMAP,
            "amass": ScanType.AMASS,
            "bbot": ScanType.BBOT,
            "shodan": ScanType.SHODAN,
            "nikto": ScanType.NIKTO,
            "sqlmap": ScanType.SQLMAP,
            "zap": ScanType.ZAP
        }

        scan_type = tool_map.get(tool.lower(), ScanType.CUSTOM)

        with db_session_scope() as session:
            repo = ScanRepository(session)
            scan = repo.create(
                tool=scan_type,
                target=target,
                scan_profile=scan_profile,
                command=command,
                session_id=session_id
            )
            scan.status = ScanStatus.RUNNING
            scan_id = scan.id

        return scan_id

    @staticmethod
    def complete_scan(
        scan_id: str,
        output_file: str,
        elapsed_seconds: float = 0,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        return_code: int = 0
    ) -> Dict[str, Any]:
        """
        Complete a scan and save parsed results to database.

        This is the main entry point called by tool runners after
        a scan completes. It:
        1. Updates scan status to COMPLETED
        2. Parses the output file (XML/JSON)
        3. Creates Host, Port, Finding, Subdomain entities
        4. Returns summary statistics

        Args:
            scan_id: ID of the scan to complete
            output_file: Path to output file (XML or JSON)
            elapsed_seconds: Scan duration
            stdout: Standard output from command
            stderr: Standard error from command
            return_code: Command return code

        Returns:
            Dictionary with scan summary and statistics
        """
        with db_session_scope() as session:
            repo = ScanRepository(session)

            try:
                scan, hosts, findings, subdomains = repo.complete_scan_with_results(
                    scan_id=scan_id,
                    output_file=output_file,
                    elapsed_seconds=elapsed_seconds,
                    stdout=stdout,
                    return_code=return_code
                )

                # Try to link to existing asset
                asset_repo = AssetRepository(session)
                asset, created = asset_repo.get_or_create(
                    name=scan.target,
                    domain=scan.target if '.' in scan.target else None,
                    ip_address=scan.target if scan.target[0].isdigit() else None
                )

                if asset:
                    asset_repo.link_to_scan(asset.id, scan.id)

                    # Link findings to asset
                    for finding in findings:
                        finding.asset_id = asset.id

                    # Link hosts to asset
                    for host in hosts:
                        host.asset_id = asset.id

                return {
                    "success": True,
                    "scan_id": scan.id,
                    "status": "completed",
                    "hosts_discovered": len(hosts),
                    "ports_discovered": sum(len(h.ports) for h in hosts),
                    "findings_count": len(findings),
                    "subdomains_count": len(subdomains),
                    "asset_id": asset.id if asset else None,
                    "elapsed_seconds": elapsed_seconds
                }

            except Exception as e:
                # Mark scan as failed
                scan = session.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.stderr = str(e)

                return {
                    "success": False,
                    "scan_id": scan_id,
                    "status": "failed",
                    "error": str(e)
                }

    @staticmethod
    def fail_scan(scan_id: str, error: str) -> Dict[str, Any]:
        """Mark a scan as failed."""
        with db_session_scope() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.end_time = datetime.utcnow()
                scan.stderr = error

                return {
                    "success": True,
                    "scan_id": scan_id,
                    "status": "failed"
                }

        return {
            "success": False,
            "error": f"Scan not found: {scan_id}"
        }

    @staticmethod
    def get_scan_summary(scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan summary with all related data."""
        with db_session_scope() as session:
            repo = ScanRepository(session)
            scan = repo.get_by_id(scan_id)

            if not scan:
                return None

            return {
                "scan": scan.to_dict(),
                "hosts": [h.to_dict() for h in scan.hosts],
                "findings": [f.to_dict() for f in scan.findings],
                "subdomains": [s.to_dict() for s in scan.subdomains]
            }

    @staticmethod
    def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans."""
        with db_session_scope() as session:
            repo = ScanRepository(session)
            scans = repo.get_recent(limit)
            return [s.to_dict() for s in scans]

    @staticmethod
    def get_session_scans(session_id: str) -> List[Dict[str, Any]]:
        """Get all scans for a session."""
        with db_session_scope() as session:
            repo = ScanRepository(session)
            scans = repo.get_by_session(session_id)
            return [s.to_dict() for s in scans]


class ReportingService:
    """
    High-level service for generating reports from database.
    Used by the Reporting AI to query structured data.
    """

    @staticmethod
    def get_executive_summary(session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate executive summary of findings.

        Args:
            session_id: Optional session to scope the report

        Returns:
            Executive summary with key metrics
        """
        with db_session_scope() as session:
            scan_repo = ScanRepository(session)
            finding_repo = FindingRepository(session)

            # Get scan stats
            scan_stats = scan_repo.get_stats()
            finding_stats = finding_repo.get_stats()

            # Get critical findings
            critical_findings = finding_repo.get_critical_and_high(limit=10)

            return {
                "generated_at": datetime.utcnow().isoformat(),
                "scan_statistics": scan_stats,
                "finding_statistics": finding_stats,
                "critical_findings": [f.to_dict() for f in critical_findings],
                "risk_assessment": {
                    "overall_risk": "HIGH" if finding_stats.get("by_severity", {}).get("critical", 0) > 0 else "MEDIUM",
                    "critical_count": finding_stats.get("by_severity", {}).get("critical", 0),
                    "high_count": finding_stats.get("by_severity", {}).get("high", 0),
                    "total_findings": finding_stats.get("total_findings", 0)
                }
            }

    @staticmethod
    def get_findings_report(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get detailed findings report.

        Args:
            severity: Filter by severity (critical, high, medium, low, info)
            status: Filter by status (new, confirmed, remediated, etc.)
            limit: Maximum results

        Returns:
            List of findings with full details
        """
        with db_session_scope() as session:
            repo = FindingRepository(session)

            sev = Severity[severity.upper()] if severity else None

            if sev:
                findings = repo.get_by_severity(sev, limit)
            else:
                findings = repo.get_critical_and_high(limit)

            return [f.to_dict() for f in findings]

    @staticmethod
    def get_host_inventory(scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get discovered hosts inventory.

        Args:
            scan_id: Optional scan to scope results

        Returns:
            List of hosts with port details
        """
        with db_session_scope() as session:
            repo = HostRepository(session)

            if scan_id:
                hosts = repo.get_by_scan(scan_id)
            else:
                hosts = repo.get_with_open_ports(min_ports=1)

            return [h.to_dict() for h in hosts]

    @staticmethod
    def get_asset_risk_report() -> List[Dict[str, Any]]:
        """
        Get asset risk report sorted by risk score.

        Returns:
            List of assets with risk information
        """
        with db_session_scope() as session:
            repo = AssetRepository(session)
            assets = repo.get_all(active_only=True)

            # Update risk scores
            for asset in assets:
                repo.update_risk_score(asset.id)

            # Sort by risk score
            assets_sorted = sorted(assets, key=lambda a: a.risk_score or 0, reverse=True)

            return [a.to_dict() for a in assets_sorted]

    @staticmethod
    def search_findings(query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Search findings by keyword.

        Args:
            query: Search term
            limit: Maximum results

        Returns:
            List of matching findings
        """
        with db_session_scope() as session:
            repo = FindingRepository(session)
            findings = repo.search(query, limit=limit)
            return [f.to_dict() for f in findings]

    @staticmethod
    def get_vulnerability_trends(ip_address: str) -> Dict[str, Any]:
        """
        Get vulnerability trends for a specific host.

        Args:
            ip_address: IP address to analyze

        Returns:
            Trend data across scans
        """
        with db_session_scope() as session:
            repo = HostRepository(session)
            return repo.aggregate_ports_for_ip(ip_address)


# Convenience functions for easy import
def save_scan_result(
    tool: str,
    target: str,
    output_file: str,
    scan_profile: Optional[str] = None,
    command: Optional[str] = None,
    elapsed_seconds: float = 0,
    stdout: Optional[str] = None,
    return_code: int = 0,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function to save scan results in one call.

    This is the main function called by tool runners:
    1. Creates scan record
    2. Parses output
    3. Saves all entities

    Returns:
        Dictionary with scan summary
    """
    scan_id = ScanService.start_scan(
        tool=tool,
        target=target,
        scan_profile=scan_profile,
        command=command,
        session_id=session_id
    )

    return ScanService.complete_scan(
        scan_id=scan_id,
        output_file=output_file,
        elapsed_seconds=elapsed_seconds,
        stdout=stdout,
        return_code=return_code
    )


class ProgrammaticReportService:
    """
    Service for managing programmatic reports.

    Programmatic reports are raw tool outputs formatted consistently.
    They are generated BEFORE LLM analysis and stored in the database.
    """

    @staticmethod
    def save_programmatic_report(
        session_id: str,
        report_data: Dict[str, Any],
        target: str
    ) -> str:
        """
        Save a programmatic report to the database.

        Args:
            session_id: Associated session ID
            report_data: Report data from ProgrammaticReportGenerator
            target: Scan target

        Returns:
            Report ID
        """
        from .models_enhanced import GeneratedReport, ReportCategory

        with db_session_scope() as session:
            report = GeneratedReport(
                session_id=session_id,
                report_category=ReportCategory.PROGRAMMATIC,
                report_type=report_data.get("report_type", "unknown"),
                title=report_data.get("title", "Programmatic Report"),
                target=target,
                content=report_data.get("content", ""),
                structured_data=report_data.get("structured_data"),
                format="markdown"
            )

            session.add(report)
            session.commit()

            return report.id

    @staticmethod
    def get_programmatic_report(report_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a programmatic report by ID.

        Args:
            report_id: Report ID

        Returns:
            Report data or None if not found
        """
        from .models_enhanced import GeneratedReport, ReportCategory

        with db_session_scope() as session:
            report = session.query(GeneratedReport).filter(
                GeneratedReport.id == report_id,
                GeneratedReport.report_category == ReportCategory.PROGRAMMATIC
            ).first()

            if report:
                return {
                    "id": report.id,
                    "session_id": report.session_id,
                    "report_type": report.report_type,
                    "title": report.title,
                    "target": report.target,
                    "content": report.content,
                    "structured_data": report.structured_data,
                    "generated_at": report.generated_at.isoformat() if report.generated_at else None
                }

            return None

    @staticmethod
    def get_programmatic_reports_for_session(session_id: str) -> List[Dict[str, Any]]:
        """
        Get all programmatic reports for a session.

        Args:
            session_id: Session ID

        Returns:
            List of programmatic reports
        """
        from .models_enhanced import GeneratedReport, ReportCategory

        with db_session_scope() as session:
            reports = session.query(GeneratedReport).filter(
                GeneratedReport.session_id == session_id,
                GeneratedReport.report_category == ReportCategory.PROGRAMMATIC
            ).all()

            return [
                {
                    "id": r.id,
                    "report_type": r.report_type,
                    "title": r.title,
                    "target": r.target,
                    "content": r.content,
                    "structured_data": r.structured_data,
                    "generated_at": r.generated_at.isoformat() if r.generated_at else None
                }
                for r in reports
            ]


def get_context_for_llm(session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get structured context for LLM report generation.

    Instead of reading raw logs, the Reporting AI calls this
    function to get normalized, queryable data.

    Returns:
        Structured data ready for LLM analysis
    """
    return {
        "executive_summary": ReportingService.get_executive_summary(session_id),
        "critical_findings": ReportingService.get_findings_report(severity="critical", limit=20),
        "high_findings": ReportingService.get_findings_report(severity="high", limit=20),
        "host_inventory": ReportingService.get_host_inventory(),
        "asset_risks": ReportingService.get_asset_risk_report()
    }
