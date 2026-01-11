# Tool Output Analyzer

Analyze the output from security tool "{tool_name}" and extract findings.

## Tool Category: {tool_category}
## Tool Description: {tool_description}

## Output:
```
{output}
```

## Task:
Extract key findings from this output. Return JSON only:

```json
{
  "has_findings": true/false,
  "severity": "critical" | "high" | "medium" | "low" | "info" | "none",
  "summary": "One sentence summary of findings",
  "key_items": ["item1", "item2"],
  "next_step": "Suggested next action based on findings"
}
```

## Analysis Rules by Tool Category:

### Port Scanners (nmap, masscan):
- has_findings = true if open ports found
- Extract port numbers and services
- Suggest vuln scan if web ports found (80, 443, 8080)

### Vuln Scanners (nuclei, nikto):
- Check for [critical], [high], CVE mentions
- severity = highest severity found
- Suggest exploitation if critical/high found

### Directory Bruteforce (gobuster, dirsearch):
- has_findings = true if Status 200/301 found
- List discovered endpoints
- Suggest further enumeration

### Subdomain Enumeration (subfinder, amass):
- Count unique subdomains
- has_findings = true if subdomains > 0
- Suggest port scan on discovered subdomains

### Credential Tools (hydra, mimikatz):
- has_findings = true if credentials found
- severity = critical if passwords found
- Suggest lateral movement

Return ONLY the JSON, no explanation.
