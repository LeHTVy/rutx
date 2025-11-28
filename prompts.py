"""
Prompt Management System
Centralized prompts for SNODE AI 3-Phase Security Scanning

Enhanced with:
- Tool effectiveness scoring (from effectiveness.py)
- Attack pattern templates (from attack_patterns.py)
- Intelligent tool selection guidance

Version: 2.0 (Enhanced with HexStrike-inspired features)
"""

# Import effectiveness and pattern systems
try:
    from effectiveness import (
        get_tool_effectiveness,
        get_best_tools,
        detect_target_type,
        get_effectiveness_summary
    )
    from attack_patterns import (
        get_pattern,
        suggest_pattern,
        get_pattern_summary,
        get_all_patterns_summary
    )
    ENHANCED_FEATURES_AVAILABLE = True
except ImportError:
    # Fallback if files not found
    ENHANCED_FEATURES_AVAILABLE = False
    print("Warning: effectiveness.py or attack_patterns.py not found. Running in basic mode.")

# ============================================================================
# TOOL SELECTION GUIDE (Used in Phase 1) - ENHANCED
# ============================================================================

TOOL_SELECTION_GUIDE = """INTELLIGENT TOOL SELECTION:

**STEP 1: DETECT TARGET TYPE**
Automatically detect from input:
- IP address (192.168.x.x) → network_host
- Domain (example.com) → web_application  
- "subdomain" in request → subdomain_enum
- "api" in request → api_endpoint

**STEP 2: USE EFFECTIVENESS SCORES**
Each tool has effectiveness rating (0.0-1.0) for each target type:
- 0.9-1.0: EXCELLENT (primary tool for this task)
- 0.8-0.9: VERY GOOD (should consider)
- 0.7-0.8: GOOD (useful)
- <0.7: LIMITED (use only if specialized)

**STEP 3: CONSIDER ATTACK PATTERNS**
Pre-defined workflows for common scenarios:
- web_reconnaissance: Nmap → BBOT → Shodan → Nuclei (when added)
- subdomain_enumeration: Amass → BBOT
- network_discovery: Nmap quick → Nmap detailed → Shodan
- bug_bounty_recon: Amass → BBOT → Masscan → Nmap detailed

**TOOL COMBINATIONS (Current Tools):**

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

**🚨 EMERGENCY RULE - CHECK THIS FIRST:**

Before writing ANYTHING, check scan_results for masscan_data.results.

If scan_results shows:
- Empty results object: {}
- OR masscan_data.results has NO entries
- OR masscan_data.total_open_ports == 0  
- OR results object exists but all IPs have empty port arrays []

Then you MUST output EXACTLY this format and STOP:

## SCAN RESULTS
Masscan batch scan completed on [X] targets.
Scanned ports: [list actual ports from masscan_data.ports_scanned]
**Result: No open ports detected on any target.**

This indicates:
- All scanned ports are closed or filtered by firewalls
- Targets may not be responding to scans
- Network filtering may be blocking scan traffic

## RECOMMENDATIONS
1. Verify targets are reachable (basic connectivity test)
2. Perform detailed Nmap service detection on high-priority targets
3. Check if network firewall rules are blocking scan traffic
4. Consider scanning from different source IP/network

**DO NOT PROCEED FURTHER. DO NOT INVENT PORT DATA!**
**DO NOT GENERATE A GENERIC 'VULNERABILITY SCAN REPORT' WITH SECTIONS LIKE FIREWALL, MALWARE, IDS.**
**IF NO PORTS FOUND, SAY "NO PORTS FOUND" AND STOP.**

---

**ONLY IF masscan_data.results contains actual IPs with port arrays, proceed below:**

**CRITICAL: YOU MUST REPORT PER-DOMAIN, NOT GENERAL ADVICE!**

**ANTI-HALLUCINATION RULES:**
1. DO NOT invent ANY data
2. DO NOT give generic security advice
3. ONLY report what EXISTS in scan_results JSON
4. MUST show WHICH domain/IP has WHICH ports open
5. If no data, state "No data found" - DO NOT INVENT!

**STEP 1: Extract masscan_data from scan_results**

Find the "masscan_data" object containing:
- hostname_to_ip: {domain: IP}
- results: {IP: [{port, protocol, state}]}

**STEP 2: Create PER-DOMAIN table**

## SCAN RESULTS

**CRITICAL: Show EACH domain individually:**

### Domain-by-Domain Breakdown:

For EACH entry in hostname_to_ip, create:

**[DOMAIN_NAME] ([IP_ADDRESS])**
- Open Ports: [port1/tcp, port2/tcp, port3/tcp]
- Services: [service names based on ports]
- Risk Level: [CRITICAL if 3389/445/3306, HIGH if SSH only, MEDIUM if web only, LOW if no ports]

Example:
```
**api.snode.com (192.168.1.5)**
- Open Ports: 443/tcp, 22/tcp
- Services: HTTPS, SSH
- Risk Level: HIGH (SSH exposed to internet)

**admin.snode.com (192.168.1.10)**
- Open Ports: 80/tcp, 443/tcp, 3306/tcp
- Services: HTTP, HTTPS, MySQL
- Risk Level: CRITICAL (MySQL exposed)
```

Repeat for EVERY domain in the scan!

## CRITICAL FINDINGS

List domains with CRITICAL services (3389/RDP, 445/SMB, 3306/MySQL, 5432/PostgreSQL, 1433/MSSQL):
- [domain] ([IP]): port/protocol - [WHY IT'S CRITICAL]

If none: "No critical services exposed"

## HIGH-RISK FINDINGS

List domains with HIGH-RISK services (22/SSH, 21/FTP, 25/SMTP on non-mail servers):
- [domain] ([IP]): port/protocol - [WHY IT'S RISKY]

## WEB SERVICES SUMMARY

Count domains with ports 80, 443, 8080, 8443:
- Total web-facing domains: [count]
- HTTP only (no HTTPS): [list domains]
- HTTPS enabled: [list domains]

## RECOMMENDATIONS

Based ONLY on actual findings:
1. For each CRITICAL domain → Specific action
2. For each HIGH-RISK domain → Specific action
3. Overall scan summary → Next steps

**VERIFICATION CHECKLIST (before sending):**
- [ ] Did I list EACH domain individually?
- [ ] Did I show WHICH ports are open on WHICH domain?
- [ ] Did I use ONLY real data from scan_results?
- [ ] Did I avoid generic security advice?
- [ ] Did I provide domain names, not just IPs?

If you failed ANY checklist item, DELETE your report and start over!
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

# Phase 4 format for combined subdomain analysis
SUBDOMAIN_ANALYSIS_PHASE4_FORMAT = """PHASE 4: COMBINED SUBDOMAIN ANALYSIS

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


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_phase1_prompt(tool_list: str, user_request: str = "") -> str:
    """
    Build Phase 1 (Tool Selection) prompt with intelligent guidance
    
    Args:
        tool_list: Formatted list of available tools
        user_request: User's request text (optional, for pattern suggestion)
    
    Returns:
        Enhanced Phase 1 prompt with effectiveness and pattern guidance
    """
    base_prompt = f"""You are SNODE AI, a security analysis agent.

PHASE 1: TOOL SELECTION

AVAILABLE TOOLS:
{tool_list}

{TOOL_SELECTION_GUIDE}
"""
    
    # Add enhanced features if available
    if ENHANCED_FEATURES_AVAILABLE and user_request:
        # Detect target type from user request
        target_type = detect_target_type(user_request)
        
        # Get effectiveness summary for this target type
        effectiveness_info = get_effectiveness_summary(target_type)
        
        # Suggest attack pattern if applicable
        suggested_pattern = suggest_pattern(user_request, target_type)
        pattern_info = ""
        if suggested_pattern:
            pattern_info = f"\n**SUGGESTED ATTACK PATTERN:**\n{get_pattern_summary(suggested_pattern)}\n"
        
        enhanced_guidance = f"""

**INTELLIGENT GUIDANCE FOR THIS REQUEST:**

Detected Target Type: {target_type}

{effectiveness_info}
{pattern_info}

**SELECTION STRATEGY:**
1. Prioritize tools with highest effectiveness scores (0.9+)
2. Consider following the suggested pattern if applicable
3. Select 1-3 tools maximum for efficiency
4. Explain why each tool was selected

"""
        base_prompt += enhanced_guidance
    
    base_prompt += "\nCall the appropriate tool(s). Analysis comes in Phase 3."
    
    return base_prompt


def get_phase3_prompt(scan_results: str, db_context: str = "{}", scan_type: str = "generic") -> str:
    """Build Phase 3 (Analysis) prompt with scan-type specific format"""

    # Select appropriate format based on scan type
    if scan_type == "masscan" or "masscan" in scan_results.lower():
        output_format = MASSCAN_SCAN_FORMAT
    elif scan_type == "port_scan":
        output_format = PORT_SCAN_FORMAT
    elif scan_type == "vuln_scan" or "vulnerability" in scan_results.lower():
        output_format = VULN_SCAN_FORMAT
    elif scan_type == "subdomain" or "subdomain" in scan_results.lower():
        output_format = SUBDOMAIN_DISCOVERY_FORMAT
    elif scan_type == "osint":
        output_format = OSINT_FORMAT
    else:
        output_format = GENERIC_FORMAT

    # Build the complete Phase 3 prompt
    prompt = f"""You are SNODE AI, a security analysis agent.

PHASE 3: ANALYSIS

SCAN RESULTS:
{scan_results}

DATABASE CONTEXT (previous findings):
{db_context}

{VULNERABILITY_ANALYSIS}

{output_format}

CRITICAL RULES:
- Analyze the ACTUAL scan data provided above
- Cross-reference with database context if relevant
- Follow the output format for scan type: {scan_type}
- Be specific and evidence-based
- Provide actionable recommendations
"""

    return prompt

