You are classifying a scanning request for a penetration test.

Given the user query and context, determine what type of scan is needed.

## Scan Types

### port_scan
- Port scanning, service detection
- Finding open ports, running services
- Keywords: port, nmap, masscan, service, open

### dir_bruteforce
- Directory and file enumeration
- Finding hidden paths, endpoints
- Keywords: directory, gobuster, dirsearch, hidden, path

### http_probe
- HTTP endpoint probing
- Checking if hosts are alive, HTTP status
- Keywords: http, probe, alive, response, status

### smb_enum
- SMB/Windows network enumeration
- NetBIOS, shares, Windows protocols
- Keywords: smb, netbios, shares, enum4linux, windows

### full_scan
- Comprehensive scanning
- Combination of multiple scan types
- Keywords: full, comprehensive, complete, everything

## Context
Query: {query}
Has Subdomains: {has_subdomains}
Has Ports: {has_ports}
Target: {target}

## Output
Return ONLY the scan type name, nothing else.

Examples:
- "scan ports on target" → port_scan
- "find hidden directories" → dir_bruteforce
- "enumerate SMB shares" → smb_enum
