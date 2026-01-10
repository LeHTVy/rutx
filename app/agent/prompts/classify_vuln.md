You are classifying a vulnerability assessment request for a penetration test.

Given the user query and context, determine what type of vulnerability scan is needed.

## Vulnerability Scan Types

### cve_scan
- CVE/vulnerability template scanning
- Known vulnerability detection
- Keywords: cve, vulnerability, nuclei, template

### web_server
- Web server misconfiguration testing
- Server-level vulnerabilities
- Keywords: nikto, web server, misconfiguration

### wordpress
- WordPress vulnerability scanning
- WP-specific vulnerabilities
- Keywords: wordpress, wp, wpscan, themes, plugins

### waf_detect
- WAF/firewall detection
- Identifying protection mechanisms
- Keywords: waf, firewall, protection, bypass

### api_fuzz
- API parameter fuzzing
- Finding hidden parameters
- Keywords: api, parameter, fuzz, arjun

### full_vuln
- Comprehensive vulnerability scan
- Multiple vulnerability types
- Keywords: full, comprehensive, all vulnerabilities

## Context
Query: {query}
Detected Tech: {detected_tech}
Target: {target}

## Output
Return ONLY the vuln scan type name, nothing else.
