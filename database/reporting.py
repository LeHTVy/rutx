"""
Reporting Module - Generate Reports from Database
Provides structured data retrieval for LLM-based report generation.
The Reporting AI queries this module instead of raw logs.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from .database import db_session_scope, get_db_manager
from .models import (
    Scan, Host, Port, Finding, Asset, Subdomain,
    ScanType, ScanStatus, Severity, FindingStatus
)
from .repositories import (
    ScanRepository, FindingRepository, AssetRepository, HostRepository
)


class PentestReporter:
    """
    Generates penetration testing reports from database.
    Designed for LLM consumption - returns structured data.
    """

    def __init__(self, session_id: Optional[str] = None):
        """
        Initialize reporter.

        Args:
            session_id: Optional session to scope reports
        """
        self.session_id = session_id

    def get_full_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive penetration test report.

        Returns complete structured data for LLM analysis:
        - Executive summary
        - All findings by severity
        - Host inventory
        - Subdomain enumeration results
        - Risk assessment

        Returns:
            Complete report structure
        """
        with db_session_scope() as session:
            scan_repo = ScanRepository(session)
            finding_repo = FindingRepository(session)
            host_repo = HostRepository(session)
            asset_repo = AssetRepository(session)

            # Get scans
            if self.session_id:
                scans = scan_repo.get_by_session(self.session_id)
            else:
                scans = scan_repo.get_recent(limit=50)

            # Aggregate findings
            all_findings = []
            all_hosts = []
            all_subdomains = []

            for scan in scans:
                all_findings.extend(scan.findings)
                all_hosts.extend(scan.hosts)
                all_subdomains.extend(scan.subdomains)

            # Categorize findings
            findings_by_severity = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            }

            for finding in all_findings:
                sev = finding.severity.value if finding.severity else "info"
                findings_by_severity[sev].append(finding.to_dict())

            # Build report
            report = {
                "report_metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "session_id": self.session_id,
                    "scans_analyzed": len(scans),
                    "total_findings": len(all_findings),
                    "total_hosts": len(all_hosts),
                    "total_subdomains": len(all_subdomains)
                },
                "executive_summary": self._generate_executive_summary(
                    scans, all_findings, all_hosts
                ),
                "findings": findings_by_severity,
                "hosts": [h.to_dict() for h in all_hosts],
                "subdomains": [s.to_dict() for s in all_subdomains[:100]],  # Limit for LLM
                "scans": [s.to_dict() for s in scans],
                "risk_assessment": self._calculate_risk_assessment(all_findings),
                "recommendations": self._generate_recommendations(all_findings)
            }

            return report

    def _generate_executive_summary(
        self,
        scans: List[Scan],
        findings: List[Finding],
        hosts: List[Host]
    ) -> Dict[str, Any]:
        """Generate executive summary section."""
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)

        # Determine overall risk level
        if critical_count > 0:
            risk_level = "CRITICAL"
            risk_color = "red"
        elif high_count > 0:
            risk_level = "HIGH"
            risk_color = "orange"
        elif medium_count > 0:
            risk_level = "MEDIUM"
            risk_color = "yellow"
        else:
            risk_level = "LOW"
            risk_color = "green"

        # Get unique targets
        targets = set(s.target for s in scans)

        return {
            "overall_risk_level": risk_level,
            "risk_color": risk_color,
            "targets_scanned": list(targets),
            "scan_types_used": list(set(s.tool.value for s in scans if s.tool)),
            "findings_summary": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": sum(1 for f in findings if f.severity == Severity.LOW),
                "info": sum(1 for f in findings if f.severity == Severity.INFO)
            },
            "hosts_discovered": len(hosts),
            "open_ports_total": sum(h.open_ports for h in hosts),
            "assessment_period": {
                "start": min(s.start_time for s in scans).isoformat() if scans else None,
                "end": max(s.end_time or s.start_time for s in scans).isoformat() if scans else None
            }
        }

    def _calculate_risk_assessment(self, findings: List[Finding]) -> Dict[str, Any]:
        """Calculate risk assessment metrics."""
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.INFO: 0
        }

        total_score = sum(weights.get(f.severity, 0) for f in findings)
        max_possible = len(findings) * 10 if findings else 1

        risk_percentage = (total_score / max_possible) * 100 if max_possible > 0 else 0

        return {
            "risk_score": round(risk_percentage, 1),
            "weighted_total": total_score,
            "max_possible": max_possible,
            "risk_rating": (
                "CRITICAL" if risk_percentage >= 80 else
                "HIGH" if risk_percentage >= 60 else
                "MEDIUM" if risk_percentage >= 40 else
                "LOW" if risk_percentage >= 20 else
                "MINIMAL"
            ),
            "immediate_action_required": any(f.severity == Severity.CRITICAL for f in findings)
        }

    def _generate_recommendations(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations based on findings."""
        recommendations = []

        # Group findings by type
        finding_types = {}
        for f in findings:
            if f.finding_type not in finding_types:
                finding_types[f.finding_type] = []
            finding_types[f.finding_type].append(f)

        # Generate recommendations for each type
        priority = 1
        for finding_type, type_findings in sorted(
            finding_types.items(),
            key=lambda x: max(
                (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO).index(f.severity)
                for f in x[1]
            ) if x[1] else 5
        ):
            max_severity = max(
                (f.severity for f in type_findings),
                key=lambda s: (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO).index(s)
            )

            recommendations.append({
                "priority": priority,
                "finding_type": finding_type,
                "count": len(type_findings),
                "max_severity": max_severity.value if max_severity else "info",
                "recommendation": self._get_recommendation_text(finding_type, type_findings)
            })
            priority += 1

        return recommendations[:10]  # Top 10 recommendations

    def _get_recommendation_text(self, finding_type: str, findings: List[Finding]) -> str:
        """Generate recommendation text for a finding type."""
        templates = {
            "open_port": "Review and close unnecessary open ports. Implement firewall rules to restrict access.",
            "vulnerability": "Apply security patches and updates. Consider compensating controls if immediate patching is not possible.",
            "subdomain_enumeration": "Review exposed subdomains. Ensure proper access controls and remove unused services.",
            "discovery": "Review discovered assets and ensure they are properly documented in the asset inventory.",
            "parse_error": "Review scan configuration and retry failed scans."
        }

        return templates.get(finding_type, f"Review {len(findings)} {finding_type} findings and address as appropriate.")


def get_llm_context(session_id: Optional[str] = None) -> str:
    """
    Get formatted context for LLM report generation.

    This is the main function called by the Reporting AI.
    Instead of reading raw logs, it queries the database
    and returns structured, normalized data.

    Args:
        session_id: Optional session to scope the report

    Returns:
        JSON string ready for LLM consumption
    """
    reporter = PentestReporter(session_id)
    report = reporter.get_full_report()

    # Format for LLM consumption
    context = {
        "context_type": "penetration_test_results",
        "data_source": "structured_database",
        "report": report
    }

    return json.dumps(context, indent=2, default=str)


def get_findings_context(
    severity: Optional[str] = None,
    limit: int = 50
) -> str:
    """
    Get findings context for LLM analysis.

    Args:
        severity: Filter by severity level
        limit: Maximum findings to return

    Returns:
        JSON string with findings data
    """
    with db_session_scope() as session:
        repo = FindingRepository(session)

        if severity:
            try:
                sev = Severity[severity.upper()]
                findings = repo.get_by_severity(sev, limit)
            except KeyError:
                findings = repo.get_critical_and_high(limit)
        else:
            findings = repo.get_critical_and_high(limit)

        return json.dumps({
            "findings_count": len(findings),
            "severity_filter": severity,
            "findings": [f.to_dict() for f in findings]
        }, indent=2, default=str)


def get_host_context(ip_address: Optional[str] = None) -> str:
    """
    Get host context for LLM analysis.

    Args:
        ip_address: Optional IP to filter by

    Returns:
        JSON string with host data
    """
    with db_session_scope() as session:
        repo = HostRepository(session)

        if ip_address:
            hosts = repo.get_by_ip(ip_address)
            trend_data = repo.aggregate_ports_for_ip(ip_address)
        else:
            hosts = repo.get_with_open_ports(min_ports=1)
            trend_data = None

        return json.dumps({
            "hosts_count": len(hosts),
            "ip_filter": ip_address,
            "hosts": [h.to_dict() for h in hosts],
            "trend_data": trend_data
        }, indent=2, default=str)


def query_database(query_type: str, **kwargs) -> Dict[str, Any]:
    """
    Generic database query interface for LLM tools.

    This function can be exposed as an LLM tool for
    the Reporting AI to query the database dynamically.

    Args:
        query_type: Type of query (scans, findings, hosts, assets)
        **kwargs: Query parameters

    Returns:
        Query results
    """
    with db_session_scope() as session:
        if query_type == "scans":
            repo = ScanRepository(session)
            if "target" in kwargs:
                results = repo.get_by_target(kwargs["target"], kwargs.get("limit", 10))
            elif "tool" in kwargs:
                tool = ScanType[kwargs["tool"].upper()]
                results = repo.get_by_tool(tool, kwargs.get("limit", 10))
            else:
                results = repo.get_recent(kwargs.get("limit", 10))
            return {"scans": [s.to_dict() for s in results]}

        elif query_type == "findings":
            repo = FindingRepository(session)
            if "severity" in kwargs:
                sev = Severity[kwargs["severity"].upper()]
                results = repo.get_by_severity(sev, kwargs.get("limit", 50))
            elif "cve" in kwargs:
                results = repo.get_by_cve(kwargs["cve"])
            elif "search" in kwargs:
                results = repo.search(kwargs["search"], limit=kwargs.get("limit", 50))
            else:
                results = repo.get_critical_and_high(kwargs.get("limit", 50))
            return {"findings": [f.to_dict() for f in results]}

        elif query_type == "hosts":
            repo = HostRepository(session)
            if "ip" in kwargs:
                results = repo.get_by_ip(kwargs["ip"])
            elif "scan_id" in kwargs:
                results = repo.get_by_scan(kwargs["scan_id"])
            else:
                results = repo.get_with_open_ports(kwargs.get("min_ports", 1))
            return {"hosts": [h.to_dict() for h in results]}

        elif query_type == "assets":
            repo = AssetRepository(session)
            if "ip" in kwargs:
                asset = repo.get_by_ip(kwargs["ip"])
                return {"asset": asset.to_dict() if asset else None}
            elif "domain" in kwargs:
                asset = repo.get_by_domain(kwargs["domain"])
                return {"asset": asset.to_dict() if asset else None}
            else:
                results = repo.get_all()
                return {"assets": [a.to_dict() for a in results]}

        elif query_type == "stats":
            scan_repo = ScanRepository(session)
            finding_repo = FindingRepository(session)
            return {
                "scan_stats": scan_repo.get_stats(),
                "finding_stats": finding_repo.get_stats()
            }

        else:
            return {"error": f"Unknown query type: {query_type}"}


# LLM Tool Definition for database queries
DATABASE_QUERY_TOOL = {
    "type": "function",
    "function": {
        "name": "query_pentest_database",
        "description": "Query the penetration testing database for structured results. Use this instead of reading raw log files.",
        "parameters": {
            "type": "object",
            "properties": {
                "query_type": {
                    "type": "string",
                    "enum": ["scans", "findings", "hosts", "assets", "stats"],
                    "description": "Type of data to query"
                },
                "target": {
                    "type": "string",
                    "description": "Filter scans by target (for query_type=scans)"
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Filter findings by severity (for query_type=findings)"
                },
                "ip": {
                    "type": "string",
                    "description": "Filter by IP address (for query_type=hosts or assets)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return",
                    "default": 50
                }
            },
            "required": ["query_type"]
        }
    }
}
