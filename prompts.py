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
- Scan type: [quick/full/aggressive/etc]
- Nmap command used: [command]
- Total ports scanned: [count]
- Port states found:
  * Open: [count]
  * Closed: [count]
  * Filtered: [count]

## PORT SCAN RESULTS

**CRITICAL: Display port information in a clear table format showing PORT STATE for all ports.**

Example format:
```
PORT      STATE      SERVICE
22/tcp    open       ssh
80/tcp    open       http
443/tcp   open       https
3306/tcp  filtered   mysql
8080/tcp  closed     http-proxy
```

### Critical Services (High Risk)
[List ports with potentially vulnerable services - RDP, SMB, databases, etc. with their states]

### Web Services
[List HTTP/HTTPS and related ports with versions and states]

### Other Open Ports
[List remaining open ports with service details and states]

### Filtered/Closed Ports (if significant)
[If there are important filtered or closed ports worth mentioning, list them here]

## SECURITY FINDINGS
[Highlight any concerning configurations, outdated versions, or exposed services]

## RECOMMENDED NEXT STEPS
[Suggest specific follow-up scans based on findings, e.g., "Run vulnerability scan on port 445 (SMB)"]

RULES:
- ALWAYS show port states (open/closed/filtered) in output
- Use table format for port listings to ensure clarity
- Focus on PORT and SERVICE information
- NO subdomain categorization
- Flag high-risk services (RDP 3389, SMB 445, databases, telnet 23)
- Mention if ports are filtered (firewall) vs closed vs open
- Include the actual nmap command that was used
- Suggest specific next steps based on open ports
"""

MASSCAN_SCAN_FORMAT = """OUTPUT FORMAT FOR MASSCAN BATCH SCAN:

**CRITICAL: Use ONLY the actual scan results provided. Do NOT use example data.**

## SCAN SUMMARY
- Targets scanned: [USE ACTUAL COUNT FROM RESULTS]
- Scan rate: [USE ACTUAL RATE FROM COMMAND]
- Total open ports found: [COUNT FROM ACTUAL RESULTS]
- Targets with open ports: [ACTUAL COUNT]/[TOTAL COUNT]
- Masscan command used: [EXACT COMMAND FROM RESULTS]

## BATCH RESULTS

**Display ACTUAL results in table format grouped by target:**

```
TARGET              OPEN PORTS
[actual_target_1]   [actual_ports_1]
[actual_target_2]   [actual_ports_2]
```

**IMPORTANT RULES:**
1. Use ONLY the IP addresses and ports found in the actual scan results
2. If a hostname was resolved to IP, show: "hostname (IP)" → ports
3. If no ports found, state "No open ports detected"
4. Do NOT invent or use example data like "subdomain1.example.com"

### Critical Findings
[List ACTUAL targets with critical ports if found: RDP (3389), SMB (445), databases (3306, 5432, 1433)]
[If NONE found, state "No critical services detected"]

### Web Services Summary
[Count of ACTUAL targets with HTTP/HTTPS (ports 80, 443, 8080, 8443)]

### Statistics
- Unique ports discovered: [LIST ACTUAL UNIQUE PORT NUMBERS FROM RESULTS]
- Port distribution: [COUNT HOW MANY TARGETS HAVE EACH PORT]

## SECURITY OBSERVATIONS
[Analyze ACTUAL findings - patterns, concerns based on what was REALLY found]

## RECOMMENDED NEXT STEPS
1. [SPECIFIC recommendations based on ACTUAL findings]
2. [Do NOT give generic recommendations - base on real results]

**REMINDER: Report must reflect ONLY the actual scan data provided, not examples or templates.**
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
    if scan_type == "masscan" or "masscan" in scan_results.lower():
        output_format = MASSCAN_SCAN_FORMAT
    elif scan_type == "port_scan":
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

**YOUR TASK**: Generate ONLY the SECURITY ANALYSIS and RECOMMENDATIONS sections.
The categorized subdomain lists will be generated programmatically for accuracy.
Focus on providing intelligent security insights based on the discovered subdomains.

COMBINED SCAN RESULTS:
{combined_results}

NOTE: The results include:
- "categorized": Pre-categorized subdomains by type (www, api, mail, dev, staging, admin, vpn, internal, test, other)
- "category_counts": Total count for each category
- "critical_targets": CRITICAL subdomains (api, admin, dev) that get comprehensive scans + Shodan
- "high_value_targets": High-value subdomains (staging, test, mail, vpn, internal) that get comprehensive scans

ANALYSIS REQUIREMENTS:
1. Analyze the critical_targets and high_value_targets lists
2. Review the categorized subdomains and their counts
3. Identify specific security concerns based on what was discovered
4. Provide actionable, specific recommendations
5. Consider the context: which subdomains pose the highest risk?

OUTPUT FORMAT - Generate ONLY these two sections:

## SECURITY ANALYSIS
[Provide detailed security analysis including:]
- Assessment of critical targets found (reference specific subdomains)
- Risk evaluation of high-value targets
- Specific concerns about exposed infrastructure (dev/staging/admin panels)
- Analysis of attack surface based on subdomain categories
- Any anomalies or particularly concerning findings

## RECOMMENDATIONS
[Provide specific, actionable recommendations:]
1. Immediate actions (0-24h) - Critical issues to address now
2. Short-term actions (1-7d) - Important security improvements
3. Long-term improvements (1-30d) - Strategic security enhancements
4. Specific scanning priorities - Which subdomains to investigate first
5. Remediation steps - How to secure exposed infrastructure

GUIDELINES:
- Be specific - reference actual subdomain names when discussing risks
- Prioritize by severity - Critical > High > Medium > Low
- Provide context - explain WHY each finding is concerning
- Give actionable steps - tell them HOW to remediate, not just WHAT to fix
- Consider the full picture - analyze patterns across all categories
"""

