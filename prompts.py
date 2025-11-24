"""
Prompt Management System
Centralized prompts for SNODE AI 3-Phase Security Scanning
"""

# ============================================================================
# TOOL SELECTION GUIDE (Used in Phase 1)
# ============================================================================

TOOL_SELECTION_GUIDE = """TOOL SELECTION BASED ON TARGET TYPE:

1. DNS/HOSTNAME (example.com):
   - Subdomain enumeration: amass_enum, bbot_subdomain_enum
   - Port scanning: nmap_quick_scan, nmap_service_detection
   - Threat intel: shodan_search

2. IP ADDRESS (192.168.1.100):
   - Port scanning: nmap_aggressive_scan, nmap_vuln_scan
   - Threat intel: shodan_lookup, shodan_host

3. NETWORK RANGE (192.168.1.0/24):
   - Host discovery: nmap_ping_scan
   - No Shodan for ranges

TOOL COMBINATIONS:
- Comprehensive domain scan: amass_enum → nmap_service_detection → shodan_search
- Quick IP assessment: nmap_quick_scan → shodan_lookup
- Vulnerability focus: nmap_vuln_scan → shodan_host
"""

# ============================================================================
# VULNERABILITY ANALYSIS (Used in Phase 3)
# ============================================================================

VULNERABILITY_ANALYSIS = """VULNERABILITY ASSESSMENT STANDARDS:

SEVERITY LEVELS:
- CRITICAL: RCE, exposed databases, unauthenticated admin panels, CVSS 9.0-10.0
- HIGH: Unknown services exposed, default configs, CVSS 7.0-8.9
- MEDIUM: HTTP without HTTPS, missing security headers, CVSS 4.0-6.9
- LOW: Best practice gaps, CVSS 0.1-3.9
- INFO: Non-security observations

ACCURACY RULES:
- Port 443 = HTTPS (secured), NOT "unsecured"
- Mark as "insecure" ONLY when: unencrypted protocol OR unauthenticated admin OR vulnerable version
- Use ONLY actual scan evidence - no assumptions
- Cross-reference Nmap + Shodan findings

REPORT FORMAT:
[SEVERITY] Vulnerability: [issue]
Location: [IP:Port]
Evidence: [quote from scan]
Recommendation: [specific fix]
"""

# ============================================================================
# OUTPUT FORMATS - Scan Type Specific (Used in Phase 3)
# ============================================================================

PORT_SCAN_FORMAT = """OUTPUT FORMAT FOR PORT SCAN:

## SCAN SUMMARY
- Target: [IP/hostname]
- Open ports found: [count]
- Services identified: [count]
- Scan type: [quick/full/aggressive/etc]

## OPEN PORTS & SERVICES

### Critical Services (High Risk)
[List ports with potentially vulnerable services - RDP, SMB, databases, etc.]

### Web Services
[List HTTP/HTTPS and related ports with versions]

### Other Services
[List remaining open ports with service details]

## SECURITY FINDINGS
[Highlight any concerning configurations, outdated versions, or exposed services]

## RECOMMENDED NEXT STEPS
[Suggest specific follow-up scans based on findings, e.g., "Run vulnerability scan on port 445 (SMB)"]

RULES:
- Focus on PORT and SERVICE information
- NO subdomain categorization
- Flag high-risk services (RDP 3389, SMB 445, databases)
- Suggest specific next steps based on open ports
"""

VULN_SCAN_FORMAT = """OUTPUT FORMAT FOR VULNERABILITY SCAN:

## VULNERABILITY SUMMARY
- Target: [IP/hostname]
- Vulnerabilities found: [count by severity]
- CVEs identified: [count]

## CRITICAL VULNERABILITIES
[List CRITICAL findings with CVE numbers and CVSS scores]

## HIGH SEVERITY
[List HIGH findings]

## MEDIUM SEVERITY
[List MEDIUM findings]

## RECOMMENDATIONS
1. [Immediate patching priorities]
2. [Mitigation steps for unpatched vulns]
3. [Configuration changes needed]

RULES:
- Focus on CVEs and vulnerability details
- Provide CVSS scores when available
- Give specific patching/mitigation advice
"""

OSINT_FORMAT = """OUTPUT FORMAT FOR OSINT/THREAT INTELLIGENCE:

## TARGET INTELLIGENCE
- IP/Domain: [target]
- Organization: [name]
- Location: [country/city]
- ISP: [provider]

## THREAT INDICATORS
[List any malicious activity, blacklist status, threat score]

## EXPOSED SERVICES
[Services visible from internet with versions]

## VULNERABILITIES (if available)
[Known CVEs from Shodan/databases]

## RISK ASSESSMENT
- Threat level: [LOW/MEDIUM/HIGH/CRITICAL]
- Attack surface: [assessment]

## RECOMMENDATIONS
[Security improvements based on OSINT findings]

RULES:
- Focus on threat intelligence and exposure
- Highlight public-facing vulnerabilities
- Assess overall risk based on exposure
"""

SUBDOMAIN_DISCOVERY_FORMAT = """OUTPUT FORMAT FOR SUBDOMAIN DISCOVERY:

## SUBDOMAIN DISCOVERY SUMMARY
- Total unique subdomains: [count]
- High-value targets: [count]

## HIGH-VALUE TARGETS
[List admin, api, dev, staging, internal, vpn, test subdomains]

## CATEGORIZED SUBDOMAINS

### Web Services (www, web, portal)
[list or "None found"]

### API Endpoints (api, rest, graphql)
[list or "None found"]

### Mail/Communication (mail, smtp, mx)
[list or "None found"]

### Development/Staging (dev, staging, test, uat)
[list or "None found"]

### Admin/Management
[list or "None found"]

### VPN/Internal
[list or "None found"]

## SECURITY CONCERNS
[Identify exposed dev/staging, admin panels, or sensitive subdomains]

## RECOMMENDED NEXT STEPS
[Suggest port scanning on high-value targets]

RULES:
- Focus on SUBDOMAIN categorization and analysis
- Flag security concerns (exposed admin, dev environments)
- Suggest next steps (port scanning priority targets)
"""

# Keep generic format as fallback
GENERIC_FORMAT = """OUTPUT FORMAT:

## EXECUTIVE SUMMARY
- Overall risk level: [CRITICAL/HIGH/MEDIUM/LOW]
- Targets scanned: [list]
- Key findings: [brief summary]

## FINDINGS

### Critical/High Severity
[List each finding with evidence from scan data]

### Medium Severity
[List medium findings]

### Low/Informational
[List low findings]

## RECOMMENDATIONS
1. [Immediate actions - 0-24h]
2. [Short-term fixes - 1-7d]
3. [Long-term improvements - 1-30d]

RULES:
- Base ALL findings on actual scan data
- Provide specific evidence from raw output
- Give actionable recommendations
"""


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_phase1_prompt(tool_list: str) -> str:
    """Build Phase 1 (Tool Selection) prompt"""
    return f"""You are SNODE AI, a security analysis agent.

PHASE 1: TOOL SELECTION
- Analyze the user's request
- Choose 1-3 appropriate tools
- Consider target type (IP, domain, URL)

AVAILABLE TOOLS:
{tool_list}

{TOOL_SELECTION_GUIDE}

Call the appropriate tool(s). Analysis comes in Phase 3."""


def get_phase3_prompt(scan_results: str, db_context: str = "{}", scan_type: str = "generic") -> str:
    """Build Phase 3 (Analysis) prompt with scan-type specific format"""
    
    # Select appropriate format based on scan type
    if scan_type == "port_scan":
        output_format = PORT_SCAN_FORMAT
    elif scan_type == "vuln_scan":
        output_format = VULN_SCAN_FORMAT
    elif scan_type == "subdomain":
        output_format = SUBDOMAIN_DISCOVERY_FORMAT
    elif scan_type == "osint" or scan_type == "shodan":
        output_format = OSINT_FORMAT
    else:
        output_format = GENERIC_FORMAT
    
    # Add minimal data detection guidance
    minimal_data_guidance = """
MINIMAL DATA DETECTION:
If the scan results show minimal or insufficient data:
- Clearly state that results are limited
- Suggest specific follow-up scans that would provide more value
- Examples:
  * "Only 3 ports open. Suggest: Run service detection scan to identify versions"
  * "No subdomains found with passive scan. Suggest: Try active subdomain scan or brute force mode"
  * "Port 80/443 open. Suggest: Run web vulnerability scan or technology detection"
  
Provide these suggestions in the RECOMMENDED NEXT STEPS section.
"""
    
    return f"""You are SNODE AI, a security analysis agent.

PHASE 3: ANALYSIS & REPORT

SCAN TYPE: {scan_type.upper()}

SCAN RESULTS:
{scan_results}

DATABASE CONTEXT:
{db_context}

{VULNERABILITY_ANALYSIS}

{output_format}

{minimal_data_guidance}"""



def get_phase4_prompt(combined_results: str, tool_count: int) -> str:
    """Build Phase 4 (Combined Analysis) prompt for multi-tool subdomain scans"""
    return f"""You are SNODE AI, a security analysis agent.

PHASE 4: COMBINED SUBDOMAIN ANALYSIS

You have received results from {tool_count} subdomain enumeration tools (Amass + BBOT).
Your task is to analyze the pre-categorized subdomain data and provide insights.

COMBINED SCAN RESULTS:
{combined_results}

NOTE: The results include:
- "categorized": Pre-categorized subdomains by type (www, api, mail, dev, staging, admin, vpn, internal, test, other)
- "category_counts": Total count for each category
- "high_value_targets": Subdomains flagged for investigation

ANALYSIS REQUIREMENTS:
1. Use the provided categorized data and counts
2. Highlight the most critical findings from high-value targets
3. Provide specific recommendations based on what was found
4. Identify security concerns (exposed dev/staging, admin panels, etc.)

OUTPUT FORMAT:

## SUBDOMAIN DISCOVERY SUMMARY
- Total unique subdomains: [use total_unique from data]
- Found by Amass: [use amass_count]
- Found by BBOT: [use bbot_count]
- Overlap (found by both): [use overlap_count]

## HIGH-VALUE TARGETS
[List the subdomains from high_value_targets that warrant further investigation]

## CATEGORIZED SUBDOMAINS

### Web Services (www, web, portal) - [use category_counts.www]
[List subdomains from categorized.www - if empty, state "None found"]

### API Endpoints (api, rest, graphql) - [use category_counts.api]
[List subdomains from categorized.api - if empty, state "None found"]

### Mail/Communication (mail, smtp, mx) - [use category_counts.mail]
[List subdomains from categorized.mail - if empty, state "None found"]

### Development/Staging (dev, staging, test, uat) - [use category_counts.dev + category_counts.staging + category_counts.test]
[List subdomains from categorized.dev, categorized.staging, categorized.test - if empty, state "None found"]

### Admin/Management (admin) - [use category_counts.admin]
[List subdomains from categorized.admin - if empty, state "None found"]

### VPN/Internal (vpn, internal) - [use category_counts.vpn + category_counts.internal]
[List subdomains from categorized.vpn, categorized.internal - if empty, state "None found"]

### Other - [use category_counts.other]
[List first 10 subdomains from categorized.other - if empty, state "None found"]

## SECURITY ANALYSIS
[Identify potential security concerns based on discovered subdomains]

## RECOMMENDATIONS
1. [Priority targets for port scanning]
2. [Suggested next steps - vulnerability scan, web app testing, etc.]
3. [Security concerns to address]
"""

