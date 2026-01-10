You are analyzing the current pentest phase to determine if it's complete.

## Current State
Phase: {current_phase} ({phase_name})
Target: {target}

## Findings So Far
- Subdomains discovered: {subdomain_count}
- IP addresses found: {ip_count}
- DNS records: {dns_count}
- Technologies detected: {tech_count}
- Open ports: {port_count}
- Services identified: {service_count}
- Vulnerabilities found: {vuln_count}
- Critical vulns: {critical_count}
- Tools run this session: {tools_run}

## Phase Completion Criteria

### Phase 1 (Reconnaissance) - Complete when:
- Have target domain confirmed
- Found subdomains OR IPs
- Gathered basic OSINT

### Phase 2 (Scanning) - Complete when:
- Port scan performed on key hosts
- Services identified
- Web endpoints probed

### Phase 3 (Vulnerability Assessment) - Complete when:
- Vulnerability scans run (nuclei, nikto, etc.)
- CVEs identified or confirmed none exist
- Attack surface mapped

### Phase 4 (Exploitation) - Complete when:
- Exploitation attempted on found vulns
- Access gained OR confirmed not exploitable

### Phase 5 (Post-Exploitation) - Complete when:
- Privilege escalation attempted
- Credentials/data collected
- Lateral movement explored

## Your Task
Analyze the current data and determine:
1. Is this phase complete enough to move forward?
2. What's the confidence level?
3. What should happen next?

## Response Format
Return ONLY valid JSON:
```json
{
  "phase_complete": true,
  "confidence": 0.85,
  "summary": "Recon complete with 50 subdomains and 12 IPs discovered",
  "missing": [],
  "next_phase": 2,
  "next_phase_name": "Scanning",
  "suggested_tools": ["nmap", "httpx"],
  "suggested_action": "Run port scan on discovered hosts to find open services"
}
```

If phase is NOT complete:
```json
{
  "phase_complete": false,
  "confidence": 0.6,
  "summary": "Recon incomplete - need more subdomain coverage",
  "missing": ["subdomain enumeration", "IP discovery"],
  "next_phase": 1,
  "next_phase_name": "Reconnaissance",
  "suggested_tools": ["amass", "subfinder"],
  "suggested_action": "Continue subdomain enumeration with amass for deeper coverage"
}
```
