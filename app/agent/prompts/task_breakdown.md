# Task Breakdown Prompt

Break down a user's security testing request into a structured checklist of tasks.

## USER REQUEST:
{query}

## CONTEXT:
{context_summary}

## TASK BREAKDOWN GUIDELINES:

Break down the request into actionable tasks following PTES (Penetration Testing Execution Standard) phases:

### Phase 1: Reconnaissance
- Subdomain enumeration
- OSINT gathering
- DNS enumeration
- WHOIS lookups
- Technology detection

### Phase 2: Scanning
- Port scanning
- Service detection
- Web discovery
- Directory enumeration

### Phase 3: Vulnerability Assessment
- Vulnerability scanning
- CVE detection
- Security misconfigurations
- Weak credentials detection

### Phase 4: Exploitation
- SQL injection
- XSS exploitation
- RCE attempts
- Brute force attacks
- Authentication bypass

### Phase 5: Post-Exploitation
- Privilege escalation
- Lateral movement
- Data exfiltration
- Persistence

### Phase 6: Reporting
- Generate comprehensive report
- Document findings
- Risk assessment

## REQUEST TYPES:

### Attack Requests
- "attack example.com" → Full PTES flow (all phases)
- "pwn example.com" → Full PTES flow with focus on exploitation
- "hack example.com" → Full PTES flow

### Assessment Requests
- "assess example.com" → Full PTES flow (all phases)
- "pentest example.com" → Full PTES flow
- "security audit example.com" → Phases 1-3 (recon, scan, vuln)

### Specific Requests
- "find MongoDB customers" → Query memory → Scan for MongoDB → Analyze results
- "check for XSS vulnerabilities" → Phase 3 (vuln scan focused on XSS)
- "enumerate subdomains" → Phase 1 (recon only)

## OUTPUT FORMAT:

Return JSON only with this structure:
```json
{
  "tasks": [
    {
      "id": "task_1",
      "description": "Phase 1: Reconnaissance - Enumerate subdomains for {target}",
      "phase": 1,
      "required_tools": ["subfinder", "amass", "whois"],
      "dependencies": []
    },
    {
      "id": "task_2",
      "description": "Phase 2: Port Scanning - Scan open ports on discovered hosts",
      "phase": 2,
      "required_tools": ["nmap", "masscan"],
      "dependencies": ["task_1"]
    },
    {
      "id": "task_3",
      "description": "Phase 3: Vulnerability Scanning - Scan for vulnerabilities",
      "phase": 3,
      "required_tools": ["nuclei", "nikto"],
      "dependencies": ["task_2"]
    }
  ]
}
```

## RULES:

1. **Dependencies**: Each task should list task IDs it depends on (tasks that must complete first)
2. **Phase Order**: Tasks should follow PTES phase order (1 → 2 → 3 → 4 → 5 → 6)
3. **Tool Suggestions**: Suggest 2-5 relevant tools per task
4. **Task IDs**: Use format "task_1", "task_2", etc.
5. **Descriptions**: Be specific about what each task does
6. **Conditional Tasks**: For conditional tasks (e.g., "if vulnerabilities found, then exploit"), create them but note in description

## EXAMPLES:

### Example 1: Attack Request
**Input**: "attack hellogroup.com"

**Output**:
```json
{
  "tasks": [
    {
      "id": "task_1",
      "description": "Phase 1: Reconnaissance - Enumerate subdomains and gather OSINT for hellogroup.com",
      "phase": 1,
      "required_tools": ["subfinder", "amass", "whois", "dnsrecon"],
      "dependencies": []
    },
    {
      "id": "task_2",
      "description": "Phase 2: Port Scanning - Scan open ports on discovered hosts",
      "phase": 2,
      "required_tools": ["nmap", "masscan"],
      "dependencies": ["task_1"]
    },
    {
      "id": "task_3",
      "description": "Phase 3: Vulnerability Scanning - Scan for vulnerabilities using nuclei and nikto",
      "phase": 3,
      "required_tools": ["nuclei", "nikto"],
      "dependencies": ["task_2"]
    },
    {
      "id": "task_4",
      "description": "Phase 4: Exploitation - Attempt to exploit discovered vulnerabilities (if any found)",
      "phase": 4,
      "required_tools": ["sqlmap", "hydra"],
      "dependencies": ["task_3"]
    }
  ]
}
```

### Example 2: Specific Request
**Input**: "find customers using MongoDB"

**Output**:
```json
{
  "tasks": [
    {
      "id": "task_1",
      "description": "Query memory to find customers with MongoDB in their technology stack",
      "phase": 1,
      "required_tools": [],
      "dependencies": []
    },
    {
      "id": "task_2",
      "description": "Scan identified customers for MongoDB instances",
      "phase": 2,
      "required_tools": ["nmap"],
      "dependencies": ["task_1"]
    },
    {
      "id": "task_3",
      "description": "Analyze MongoDB instances for vulnerabilities and recent CVE exposure",
      "phase": 3,
      "required_tools": ["nuclei"],
      "dependencies": ["task_2"]
    }
  ]
}
```

Return ONLY valid JSON, no extra text or explanation.
