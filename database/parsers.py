"""
Parser Middleware - Tool Output Normalization
Parses raw tool outputs (XML/JSON) and normalizes to database models.
"""

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from .models import (
    Scan, Host, Port, Finding, Subdomain, Asset,
    ScanType, ScanStatus, Severity, FindingStatus, PortState
)


class BaseParser:
    """Base class for tool output parsers."""

    def __init__(self, scan: Scan):
        self.scan = scan

    def parse(self, data: Any) -> Tuple[List[Host], List[Finding], List[Subdomain]]:
        """
        Parse tool output and return normalized entities.

        Returns:
            Tuple of (hosts, findings, subdomains)
        """
        raise NotImplementedError


class NmapParser(BaseParser):
    """
    Parses Nmap XML output into normalized database entities.
    """

    # Severity mapping for common vulnerabilities
    VULN_SEVERITY_MAP = {
        "critical": ["remote-code-execution", "rce", "shell", "root"],
        "high": ["sql-injection", "sqli", "xss", "csrf", "command-injection"],
        "medium": ["information-disclosure", "directory-listing", "version"],
        "low": ["deprecated", "weak-cipher", "self-signed"],
    }

    def parse(self, xml_file: str) -> Tuple[List[Host], List[Finding], List[Subdomain]]:
        """Parse Nmap XML file and extract hosts, ports, findings."""
        hosts = []
        findings = []
        subdomains = []

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host_elem in root.findall(".//host"):
                host, host_findings = self._parse_host(host_elem)
                if host:
                    hosts.append(host)
                    findings.extend(host_findings)

        except ET.ParseError as e:
            # Create error finding
            findings.append(Finding(
                scan_id=self.scan.id,
                finding_type="parse_error",
                title=f"Nmap XML Parse Error",
                description=str(e),
                severity=Severity.INFO,
                source_tool="nmap"
            ))

        return hosts, findings, subdomains

    def _parse_host(self, host_elem: ET.Element) -> Tuple[Optional[Host], List[Finding]]:
        """Parse a single host element."""
        findings = []

        # Get host status
        status_elem = host_elem.find("status")
        if status_elem is None or status_elem.get("state") != "up":
            return None, []

        # Get IP address
        ip_address = None
        hostname = None

        for addr_elem in host_elem.findall("address"):
            if addr_elem.get("addrtype") == "ipv4":
                ip_address = addr_elem.get("addr")
            elif addr_elem.get("addrtype") == "mac":
                mac_address = addr_elem.get("addr")

        # Get hostname
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")

        if not ip_address:
            return None, []

        # Create host
        host = Host(
            scan_id=self.scan.id,
            ip_address=ip_address,
            hostname=hostname,
            status="up",
            reason=status_elem.get("reason", "")
        )

        # Parse OS detection
        os_elem = host_elem.find(".//os/osmatch")
        if os_elem is not None:
            host.os_name = os_elem.get("name")
            host.os_accuracy = int(os_elem.get("accuracy", 0))

            osclass = os_elem.find("osclass")
            if osclass is not None:
                host.os_family = osclass.get("osfamily")
                host.os_vendor = osclass.get("vendor")

        # Parse ports
        ports_elem = host_elem.find("ports")
        open_count = 0
        filtered_count = 0
        closed_count = 0

        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port, port_findings = self._parse_port(port_elem, host)
                if port:
                    host.ports.append(port)

                    state = port.state
                    if state == PortState.OPEN:
                        open_count += 1
                        # Create finding for open port
                        findings.append(Finding(
                            scan_id=self.scan.id,
                            host=host,
                            port=port,
                            finding_type="open_port",
                            title=f"Open port {port.port_number}/{port.protocol}",
                            description=f"Service: {port.service_name or 'unknown'}, Product: {port.product or 'unknown'}",
                            severity=self._assess_port_severity(port),
                            source_tool="nmap",
                            affected_component=f"{port.product}/{port.version}" if port.product else None
                        ))
                    elif state == PortState.FILTERED:
                        filtered_count += 1
                    else:
                        closed_count += 1

                    findings.extend(port_findings)

        host.open_ports = open_count
        host.filtered_ports = filtered_count
        host.closed_ports = closed_count

        return host, findings

    def _parse_port(self, port_elem: ET.Element, host: Host) -> Tuple[Optional[Port], List[Finding]]:
        """Parse a single port element."""
        findings = []

        port_number = int(port_elem.get("portid", 0))
        protocol = port_elem.get("protocol", "tcp")

        state_elem = port_elem.find("state")
        state_str = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

        # Map state string to enum
        state_map = {
            "open": PortState.OPEN,
            "closed": PortState.CLOSED,
            "filtered": PortState.FILTERED,
            "open|filtered": PortState.OPEN_FILTERED
        }
        state = state_map.get(state_str, PortState.FILTERED)

        port = Port(
            host_id=host.id,
            port_number=port_number,
            protocol=protocol,
            state=state,
            reason=state_elem.get("reason") if state_elem is not None else None
        )

        # Parse service
        service_elem = port_elem.find("service")
        if service_elem is not None:
            port.service_name = service_elem.get("name")
            port.product = service_elem.get("product")
            port.version = service_elem.get("version")
            port.extra_info = service_elem.get("extrainfo")

            # Get CPE
            cpe_elem = service_elem.find("cpe")
            if cpe_elem is not None:
                port.cpe = cpe_elem.text

        # Parse NSE scripts (vulnerability scanners)
        scripts = {}
        for script_elem in port_elem.findall("script"):
            script_id = script_elem.get("id", "unknown")
            script_output = script_elem.get("output", "")
            scripts[script_id] = script_output

            # Check for vulnerability findings in script output
            vuln_finding = self._parse_script_for_vulns(script_id, script_output, host, port)
            if vuln_finding:
                findings.append(vuln_finding)

        if scripts:
            port.scripts = scripts

        return port, findings

    def _parse_script_for_vulns(
        self, script_id: str, output: str, host: Host, port: Port
    ) -> Optional[Finding]:
        """Check NSE script output for vulnerabilities."""

        # Common vulnerability patterns
        if "VULNERABLE" in output.upper():
            # Extract CVE if present
            cve_match = re.search(r'CVE-\d{4}-\d+', output)
            cve_id = cve_match.group(0) if cve_match else None

            severity = Severity.HIGH
            if cve_id:
                severity = Severity.CRITICAL

            return Finding(
                scan_id=self.scan.id,
                host=host,
                port=port,
                finding_type="vulnerability",
                title=f"Vulnerability found: {script_id}",
                description=output[:1000],  # Truncate long output
                severity=severity,
                cve_id=cve_id,
                source_tool="nmap",
                evidence=output
            )

        return None

    def _assess_port_severity(self, port: Port) -> Severity:
        """Assess severity based on port and service."""
        high_risk_ports = {21, 22, 23, 25, 53, 110, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
        critical_services = {"telnet", "ftp", "rsh", "rlogin", "rexec"}

        if port.service_name in critical_services:
            return Severity.HIGH

        if port.port_number in high_risk_ports:
            return Severity.MEDIUM

        return Severity.LOW


class AmassParser(BaseParser):
    """
    Parses Amass JSON output into normalized database entities.
    """

    def parse(self, json_file: str) -> Tuple[List[Host], List[Finding], List[Subdomain]]:
        """Parse Amass JSON file and extract subdomains."""
        hosts = []
        findings = []
        subdomains = []

        try:
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        subdomain = self._parse_entry(entry)
                        if subdomain:
                            subdomains.append(subdomain)
                    except json.JSONDecodeError:
                        continue

        except FileNotFoundError:
            findings.append(Finding(
                scan_id=self.scan.id,
                finding_type="parse_error",
                title="Amass output file not found",
                description=f"File: {json_file}",
                severity=Severity.INFO,
                source_tool="amass"
            ))

        # Create summary finding
        if subdomains:
            findings.append(Finding(
                scan_id=self.scan.id,
                finding_type="subdomain_enumeration",
                title=f"Discovered {len(subdomains)} subdomains",
                description=f"Subdomain enumeration completed for {self.scan.target}",
                severity=Severity.INFO,
                source_tool="amass"
            ))

        return hosts, findings, subdomains

    def _parse_entry(self, entry: Dict[str, Any]) -> Optional[Subdomain]:
        """Parse a single Amass JSON entry."""
        name = entry.get("name")
        if not name:
            return None

        # Extract parent domain
        parts = name.split('.')
        if len(parts) >= 2:
            parent_domain = '.'.join(parts[-2:])
        else:
            parent_domain = name

        subdomain = Subdomain(
            scan_id=self.scan.id,
            subdomain=name,
            parent_domain=parent_domain,
            source="amass"
        )

        # Extract IP addresses if present
        addresses = entry.get("addresses", [])
        if addresses:
            subdomain.ip_addresses = [addr.get("ip") for addr in addresses if addr.get("ip")]

        return subdomain


class BBOTParser(BaseParser):
    """
    Parses BBOT JSON output into normalized database entities.
    """

    def parse(self, json_file: str) -> Tuple[List[Host], List[Finding], List[Subdomain]]:
        """Parse BBOT JSON file and extract findings."""
        hosts = []
        findings = []
        subdomains = []

        try:
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        self._parse_event(event, hosts, findings, subdomains)
                    except json.JSONDecodeError:
                        continue

        except FileNotFoundError:
            findings.append(Finding(
                scan_id=self.scan.id,
                finding_type="parse_error",
                title="BBOT output file not found",
                description=f"File: {json_file}",
                severity=Severity.INFO,
                source_tool="bbot"
            ))

        return hosts, findings, subdomains

    def _parse_event(
        self,
        event: Dict[str, Any],
        hosts: List[Host],
        findings: List[Finding],
        subdomains: List[Subdomain]
    ):
        """Parse a single BBOT event."""
        event_type = event.get("type", "")
        data = event.get("data", "")

        if event_type == "DNS_NAME":
            subdomain = Subdomain(
                scan_id=self.scan.id,
                subdomain=str(data),
                parent_domain=self.scan.target,
                source="bbot"
            )
            subdomains.append(subdomain)

        elif event_type == "IP_ADDRESS":
            # Could create a host entry
            pass

        elif event_type == "VULNERABILITY":
            finding = Finding(
                scan_id=self.scan.id,
                finding_type="vulnerability",
                title=str(data),
                severity=Severity.HIGH,
                source_tool="bbot"
            )
            findings.append(finding)

        elif event_type == "FINDING":
            finding = Finding(
                scan_id=self.scan.id,
                finding_type="discovery",
                title=str(data),
                severity=Severity.MEDIUM,
                source_tool="bbot"
            )
            findings.append(finding)


class ShodanParser(BaseParser):
    """
    Parses Shodan JSON output into normalized database entities.
    """

    def parse(self, json_file: str) -> Tuple[List[Host], List[Finding], List[Subdomain]]:
        """Parse Shodan JSON file and extract hosts and findings."""
        hosts = []
        findings = []
        subdomains = []

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            if isinstance(data, dict):
                host, host_findings = self._parse_host_data(data)
                if host:
                    hosts.append(host)
                findings.extend(host_findings)

        except (FileNotFoundError, json.JSONDecodeError) as e:
            findings.append(Finding(
                scan_id=self.scan.id,
                finding_type="parse_error",
                title="Shodan output parse error",
                description=str(e),
                severity=Severity.INFO,
                source_tool="shodan"
            ))

        return hosts, findings, subdomains

    def _parse_host_data(self, data: Dict[str, Any]) -> Tuple[Optional[Host], List[Finding]]:
        """Parse Shodan host data."""
        findings = []

        ip_address = data.get("ip_str")
        if not ip_address:
            return None, []

        host = Host(
            scan_id=self.scan.id,
            ip_address=ip_address,
            hostname=",".join(data.get("hostnames", [])),
            os_name=data.get("os"),
            status="up"
        )

        # Parse ports from Shodan data
        for service in data.get("data", []):
            port_number = service.get("port")
            if port_number:
                port = Port(
                    host=host,
                    port_number=port_number,
                    protocol=service.get("transport", "tcp"),
                    state=PortState.OPEN,
                    service_name=service.get("product"),
                    version=service.get("version")
                )
                host.ports.append(port)

        # Check for vulnerabilities
        vulns = data.get("vulns", [])
        for vuln_id in vulns:
            finding = Finding(
                scan_id=self.scan.id,
                host=host,
                finding_type="vulnerability",
                title=f"Known vulnerability: {vuln_id}",
                cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                severity=Severity.HIGH,
                source_tool="shodan"
            )
            findings.append(finding)

        host.open_ports = len(host.ports)

        return host, findings


def get_parser(scan_type: ScanType, scan: Scan) -> BaseParser:
    """
    Factory function to get appropriate parser for scan type.

    Args:
        scan_type: Type of scan (nmap, amass, bbot, shodan)
        scan: Scan entity for relationship linking

    Returns:
        Appropriate parser instance
    """
    parsers = {
        ScanType.NMAP: NmapParser,
        ScanType.AMASS: AmassParser,
        ScanType.BBOT: BBOTParser,
        ScanType.SHODAN: ShodanParser,
    }

    parser_class = parsers.get(scan_type, BaseParser)
    return parser_class(scan)


def parse_scan_output(
    scan: Scan,
    output_file: str
) -> Tuple[List[Host], List[Finding], List[Subdomain]]:
    """
    Parse scan output file and return normalized entities.

    Args:
        scan: Scan entity
        output_file: Path to output file (XML/JSON)

    Returns:
        Tuple of (hosts, findings, subdomains)
    """
    parser = get_parser(scan.tool, scan)
    return parser.parse(output_file)
