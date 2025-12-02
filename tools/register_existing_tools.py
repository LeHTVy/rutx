"""
Register Existing Security Tools with the Tool Registry

This module registers all existing tools (nmap, masscan, shodan, etc.)
with metadata so the LLM can autonomously discover and use them.
"""

from .tool_registry import (
    ToolMetadata, ToolParameter, ToolOutput,
    ToolCategory, InputType,
    register_tool, get_tool_registry
)

# Import existing tool functions
from .nmap_tools import (
    run_nmap_native,
    run_nmap_quick_scan,
    run_nmap_service_detection,
    run_nmap_vuln_scan,
    run_nmap_stealth_batch_scan
)
from .masscan_tools import run_masscan_batch_scan
from .naabu_tools import run_naabu_batch_scan
from .shodan_tools import lookup_shodan
from .amass_tools import run_amass_native
from .bbot_tools import run_bbot_native
from .dns_tools import resolve_dns, reverse_dns_lookup


def register_all_tools():
    """Register all existing security tools with metadata."""

    # ============================================================================
    # NMAP TOOLS
    # ============================================================================

    @register_tool(ToolMetadata(
        name="Nmap Quick Scan",
        function_name="run_nmap_quick_scan",
        description="Fast Nmap scan (-T4 -F) to quickly discover open ports on a target",
        category=ToolCategory.NETWORK,
        parameters=[
            ToolParameter(
                name="target",
                type=InputType.IP_ADDRESS,
                description="IP address or hostname to scan",
                examples=["192.168.1.1", "example.com", "10.0.0.0/24"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "hosts_discovered": "int",
                "open_ports": "list",
                "services": "list"
            },
            description="Discovered hosts, open ports, and services"
        ),
        use_cases=[
            "Quick reconnaissance of unknown target",
            "Initial port discovery before detailed scanning",
            "Fast network mapping"
        ],
        triggers=["port scan", "quick scan", "fast scan", "nmap fast"],
        chains_to=["Nmap Service Detection", "Nmap Vulnerability Scan", "Shodan Lookup"],
        timeout=300,
        is_intrusive=True,
        is_safe=False  # Requires authorization
    ))
    def nmap_quick_wrapper(target: str) -> dict:
        return run_nmap_quick_scan(target)

    @register_tool(ToolMetadata(
        name="Nmap Service Detection",
        function_name="run_nmap_service_detection",
        description="Detailed service/version detection scan (-sV) to identify running services",
        category=ToolCategory.NETWORK,
        parameters=[
            ToolParameter(
                name="target",
                type=InputType.IP_ADDRESS,
                description="IP address or hostname to scan",
                examples=["192.168.1.1", "example.com"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "services_detected": "list",
                "versions": "dict",
                "os_detection": "dict"
            },
            description="Detailed service and version information"
        ),
        use_cases=[
            "Identify service versions for vulnerability assessment",
            "Banner grabbing and service fingerprinting",
            "OS detection"
        ],
        triggers=["service detection", "version scan", "banner grab", "fingerprint"],
        prerequisites=["Nmap Quick Scan"],
        chains_to=["Nmap Vulnerability Scan", "CVE Search"],
        timeout=600,
        is_intrusive=True,
        is_safe=False
    ))
    def nmap_service_wrapper(target: str) -> dict:
        return run_nmap_service_detection(target)

    @register_tool(ToolMetadata(
        name="Nmap Vulnerability Scan",
        function_name="run_nmap_vuln_scan",
        description="Vulnerability scanning using Nmap NSE scripts (--script vuln)",
        category=ToolCategory.VULNERABILITY,
        parameters=[
            ToolParameter(
                name="target",
                type=InputType.IP_ADDRESS,
                description="IP address or hostname to scan",
                examples=["192.168.1.1", "example.com"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "vulnerabilities": "list",
                "cve_ids": "list",
                "severity": "dict"
            },
            description="Discovered vulnerabilities and CVE IDs"
        ),
        use_cases=[
            "Discover known vulnerabilities",
            "Check for common misconfigurations",
            "Validate patch status"
        ],
        triggers=["vulnerability scan", "vuln scan", "exploit check", "cve check"],
        prerequisites=["Nmap Service Detection"],
        chains_to=["CVE Enrichment", "Metasploit Search"],
        timeout=900,
        is_intrusive=True,
        is_safe=False
    ))
    def nmap_vuln_wrapper(target: str) -> dict:
        return run_nmap_vuln_scan(target)

    @register_tool(ToolMetadata(
        name="Nmap Stealth Batch Scan",
        function_name="run_nmap_stealth_batch_scan",
        description="Stealth SYN scan across multiple targets (-sS)",
        category=ToolCategory.NETWORK,
        parameters=[
            ToolParameter(
                name="targets",
                type=InputType.ANY,
                description="List of IP addresses or hostnames",
                examples=["['192.168.1.1', '192.168.1.2']", "10.0.0.0/24"]
            ),
            ToolParameter(
                name="ports",
                type=InputType.TEXT,
                description="Port range to scan",
                required=False,
                default="1-1000",
                examples=["80,443", "1-65535", "top-1000"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "results": "dict",
                "total_open_ports": "int",
                "targets_with_open_ports": "int"
            },
            description="Aggregated scan results across all targets"
        ),
        use_cases=[
            "Bulk network scanning",
            "Enterprise network reconnaissance",
            "Multi-target port discovery"
        ],
        triggers=["batch scan", "bulk scan", "multi-target", "network sweep"],
        chains_to=["Nmap Service Detection", "Shodan Lookup"],
        timeout=1800,
        is_intrusive=True,
        is_safe=False
    ))
    def nmap_batch_wrapper(targets: list, ports: str = "1-1000") -> dict:
        return run_nmap_stealth_batch_scan(targets, ports)

    # ============================================================================
    # MASSCAN TOOLS
    # ============================================================================

    @register_tool(ToolMetadata(
        name="Masscan Batch Scan",
        function_name="run_masscan_batch_scan",
        description="Ultra-fast port scanner across multiple targets (faster than nmap)",
        category=ToolCategory.NETWORK,
        parameters=[
            ToolParameter(
                name="targets",
                type=InputType.ANY,
                description="List of IP addresses, hostnames, or CIDR ranges",
                examples=["['192.168.1.0/24']", "['example.com', 'test.com']"]
            ),
            ToolParameter(
                name="ports",
                type=InputType.TEXT,
                description="Ports to scan",
                required=False,
                default="80,443,22,21,25,3306,3389",
                examples=["80,443", "1-65535", "top-ports"]
            ),
            ToolParameter(
                name="rate",
                type=InputType.TEXT,
                description="Packet rate (packets/sec)",
                required=False,
                default="10000",
                examples=["1000", "10000", "100000"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "results": "dict",
                "total_open_ports": "int",
                "scan_duration": "float"
            },
            description="Fast port scan results"
        ),
        use_cases=[
            "Large-scale network scanning",
            "Quick port discovery across multiple domains",
            "Internet-wide scanning"
        ],
        triggers=["fast scan", "masscan", "quick port scan", "bulk port scan"],
        chains_to=["Nmap Service Detection", "Shodan Lookup"],
        timeout=600,
        is_intrusive=True,
        is_safe=False
    ))
    def masscan_wrapper(targets: list, ports: str = "80,443,22,21,25,3306,3389", rate: int = 10000) -> dict:
        return run_masscan_batch_scan(targets, ports, rate)

    # ============================================================================
    # NAABU TOOLS
    # ============================================================================

    @register_tool(ToolMetadata(
        name="Naabu Port Scan",
        function_name="run_naabu_batch_scan",
        description="Fast port scanner optimized for reliability and speed",
        category=ToolCategory.NETWORK,
        parameters=[
            ToolParameter(
                name="targets",
                type=InputType.ANY,
                description="List of IP addresses or hostnames",
                examples=["['example.com']", "['192.168.1.1', '192.168.1.2']"]
            ),
            ToolParameter(
                name="ports",
                type=InputType.TEXT,
                description="Ports to scan",
                required=False,
                default="top-1000",
                examples=["80,443", "1-65535", "top-1000"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "results": "dict",
                "total_open_ports": "int"
            },
            description="Port scan results"
        ),
        use_cases=[
            "Fast and reliable port scanning",
            "Alternative to nmap/masscan",
            "Batch domain port discovery"
        ],
        triggers=["naabu", "port scan", "fast scan"],
        chains_to=["Nmap Service Detection"],
        timeout=600,
        is_intrusive=True,
        is_safe=False
    ))
    def naabu_wrapper(targets: list, ports: str = "top-1000") -> dict:
        return run_naabu_batch_scan(targets, ports)

    # ============================================================================
    # THREAT INTELLIGENCE TOOLS
    # ============================================================================

    @register_tool(ToolMetadata(
        name="Shodan Lookup",
        function_name="lookup_shodan",
        description="Query Shodan for host information, open ports, vulnerabilities, and threat intelligence",
        category=ToolCategory.THREAT_INTEL,
        parameters=[
            ToolParameter(
                name="ip",
                type=InputType.IP_ADDRESS,
                description="IP address to lookup",
                examples=["8.8.8.8", "1.1.1.1", "192.168.1.1"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "ports": "list",
                "vulns": "list",
                "org": "str",
                "hostnames": "list",
                "country": "str"
            },
            description="Shodan intelligence data"
        ),
        use_cases=[
            "Check for publicly exposed services",
            "Discover known vulnerabilities",
            "Get hosting/ISP information",
            "Historical scan data"
        ],
        triggers=["shodan", "threat intelligence", "exposed services", "public scan"],
        prerequisites=["Port Scan"],
        chains_to=["CVE Enrichment"],
        timeout=30,
        requires_api_key=True,
        api_key_env="SHODAN_API_KEY",
        rate_limited=True
    ))
    def shodan_wrapper(ip: str) -> dict:
        return lookup_shodan(ip)

    # ============================================================================
    # SUBDOMAIN ENUMERATION TOOLS
    # ============================================================================

    @register_tool(ToolMetadata(
        name="Amass Subdomain Enumeration",
        function_name="run_amass_native",
        description="Comprehensive subdomain discovery using OWASP Amass",
        category=ToolCategory.SUBDOMAIN,
        parameters=[
            ToolParameter(
                name="domain",
                type=InputType.DOMAIN,
                description="Target domain for subdomain enumeration",
                examples=["example.com", "test.com", "company.org"]
            ),
            ToolParameter(
                name="passive",
                type=InputType.ANY,
                description="Use only passive sources (no active DNS queries)",
                required=False,
                default=False,
                examples=["true", "false"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "subdomains": "list",
                "sources": "dict",
                "ip_addresses": "dict"
            },
            description="Discovered subdomains with source attribution"
        ),
        use_cases=[
            "Discover hidden subdomains",
            "Map attack surface",
            "Find forgotten/staging environments",
            "Certificate transparency mining"
        ],
        triggers=["subdomain", "amass", "dns enumeration", "subdomain discovery"],
        chains_to=["DNS Resolution", "Port Scan", "Web Crawl"],
        timeout=1800,
        is_intrusive=False  # Passive mode available
    ))
    def amass_wrapper(domain: str, passive: bool = False) -> dict:
        return run_amass_native(domain, passive=passive)

    @register_tool(ToolMetadata(
        name="BBOT Subdomain Enumeration",
        function_name="run_bbot_native",
        description="Advanced subdomain discovery and web reconnaissance using BBOT",
        category=ToolCategory.SUBDOMAIN,
        parameters=[
            ToolParameter(
                name="target",
                type=InputType.DOMAIN,
                description="Target domain or IP address",
                examples=["example.com", "192.168.1.0/24"]
            ),
            ToolParameter(
                name="passive",
                type=InputType.ANY,
                description="Passive mode (no active scanning)",
                required=False,
                default=False
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "subdomains": "list",
                "web_servers": "list",
                "technologies": "list"
            },
            description="Subdomains, web technologies, and asset inventory"
        ),
        use_cases=[
            "Comprehensive subdomain discovery",
            "Technology stack identification",
            "Web asset inventory",
            "OSINT aggregation"
        ],
        triggers=["subdomain", "bbot", "web recon", "asset discovery"],
        chains_to=["Port Scan", "Web Vulnerability Scan"],
        timeout=1800
    ))
    def bbot_wrapper(target: str, passive: bool = False) -> dict:
        return run_bbot_native(target, passive=passive)

    # ============================================================================
    # DNS TOOLS
    # ============================================================================

    @register_tool(ToolMetadata(
        name="DNS Resolution",
        function_name="resolve_dns",
        description="Resolve domain names to IP addresses (A, AAAA, CNAME records)",
        category=ToolCategory.DOMAIN,
        parameters=[
            ToolParameter(
                name="domain",
                type=InputType.DOMAIN,
                description="Domain name to resolve",
                examples=["example.com", "www.test.com"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "A": "list",
                "AAAA": "list",
                "CNAME": "list"
            },
            description="DNS resolution results"
        ),
        use_cases=[
            "Convert domain to IP for scanning",
            "Verify DNS configuration",
            "Discover CDN/proxy usage"
        ],
        triggers=["dns", "resolve", "dns lookup", "a record"],
        chains_to=["Reverse DNS", "Port Scan", "Geolocation"],
        timeout=10
    ))
    def dns_resolve_wrapper(domain: str) -> dict:
        return resolve_dns(domain)

    @register_tool(ToolMetadata(
        name="Reverse DNS Lookup",
        function_name="reverse_dns_lookup",
        description="Reverse DNS lookup (PTR record) to find hostname from IP",
        category=ToolCategory.DOMAIN,
        parameters=[
            ToolParameter(
                name="ip",
                type=InputType.IP_ADDRESS,
                description="IP address for reverse lookup",
                examples=["8.8.8.8", "1.1.1.1"]
            )
        ],
        output=ToolOutput(
            format="json",
            schema={
                "hostname": "str",
                "ptr": "str"
            },
            description="Hostname associated with IP"
        ),
        use_cases=[
            "Identify hosting provider",
            "Verify server ownership",
            "Discover related domains"
        ],
        triggers=["reverse dns", "ptr", "ip to hostname"],
        prerequisites=["Port Scan"],
        chains_to=["WHOIS Lookup"],
        timeout=10
    ))
    def reverse_dns_wrapper(ip: str) -> dict:
        return reverse_dns_lookup(ip)

    print("[OK] Registered all existing security tools with LLM registry")


# Auto-register on import
register_all_tools()
