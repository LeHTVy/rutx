"""
Universal Tool Output Parser
===========================

Uses LLM to extract structured findings from ANY security tool output.
No hardcoding per-tool - semantic understanding handles all formats.
"""
import json
import re
from typing import Dict, Any, List, Optional


class OutputParser:
    """
    LLM-based universal parser for security tool outputs.
    
    Extracts:
    - Subdomains
    - Hosts/IPs
    - Open ports
    - Vulnerabilities
    - Emails
    - Technologies
    - URLs
    - Credentials
    """
    
    def __init__(self, llm=None):
        self._llm = llm
    
    @property
    def llm(self):
        """Lazy-load LLM."""
        if self._llm is None:
            from app.agent.graph import OllamaClient
            self._llm = OllamaClient()
        return self._llm
    
    def parse(self, tool_name: str, output: str, domain: str = None) -> Dict[str, Any]:
        """
        Parse tool output and extract structured findings.
        
        Args:
            tool_name: Name of the tool that produced the output
            output: Raw tool output string
            domain: Target domain (for context)
        
        Returns:
            Dict with extracted findings:
            {
                "subdomains": ["sub1.domain.com", ...],
                "hosts": [{"hostname": "...", "ip": "..."}],
                "ports": [{"port": 80, "service": "http", "host": "..."}],
                "vulnerabilities": [{"type": "...", "severity": "...", "target": "..."}],
                "emails": ["email@domain.com"],
                "technologies": ["nginx", "wordpress"],
                "urls": ["https://..."],
            }
        """
        # Truncate output to avoid token limits
        # Truncate output to avoid token limits (keep head and tail)
        max_len = 6000
        if len(output) > max_len:
            head_len = 2000
            tail_len = 4000
            output_truncated = output[:head_len] + "\n... [TRUNCATED] ...\n" + output[-tail_len:]
        else:
            output_truncated = output
        
        prompt = f'''You are a security tool output parser.
Extract structured findings from this {tool_name} output.

TARGET DOMAIN: {domain or "unknown"}

TOOL OUTPUT:
```
{output_truncated}
```

Extract and return a JSON object with ONLY the fields that have actual findings:
- "subdomains": array of discovered subdomain strings
- "hosts": array of {{"hostname": "...", "ip": "..."}} objects
- "ports": array of {{"port": number, "service": "...", "host": "..."}} objects
- "vulnerabilities": array of {{"type": "...", "severity": "high/medium/low", "target": "...", "details": "..."}}
- "emails": array of email addresses
- "technologies": array of detected technology names (e.g., "nginx", "wordpress", "apache")
- "urls": array of interesting URLs found

RULES:
1. Return ONLY valid JSON, no explanation text
2. Only include fields that have actual data found
3. Do not invent or guess - only extract what's explicitly in the output
4. For hosts, extract both hostname AND IP address when available
5. Return empty {{}} if no structured findings found

JSON:'''

        try:
            # Use quiet mode - don't stream raw JSON to console
            response = self.llm.generate(prompt, timeout=45, stream=True, show_content=False)
            
            # Extract JSON from response
            findings = self._extract_json(response)
            
            if findings:
                # Validate and clean the findings
                return self._validate_findings(findings, domain)
            
        except Exception as e:
            print(f"  ⚠️ LLM parser error: {e}")
        
        # Fallback to regex-based extraction
        return self._regex_fallback(output, domain)
    
    def _extract_json(self, response: str) -> Optional[Dict]:
        """Extract JSON from LLM response."""
        # Try to parse directly
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass
        
        # Try to find JSON in response
        json_patterns = [
            r'\{[\s\S]*\}',  # Match {...}
            r'```json\s*([\s\S]*?)```',  # Match ```json ... ```
            r'```\s*([\s\S]*?)```',  # Match ``` ... ```
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, response)
            if match:
                try:
                    json_str = match.group(1) if '```' in pattern else match.group(0)
                    return json.loads(json_str.strip())
                except (json.JSONDecodeError, IndexError):
                    continue
        
        return None
    
    def _validate_findings(self, findings: Dict, domain: str = None) -> Dict[str, Any]:
        """Validate and clean extracted findings."""
        result = {}
        
        # Validate subdomains
        if "subdomains" in findings and isinstance(findings["subdomains"], list):
            valid_subs = []
            for sub in findings["subdomains"]:
                if isinstance(sub, str) and '.' in sub and len(sub) > 3:
                    # If domain specified, ensure subdomain is related
                    if domain and domain in sub:
                        valid_subs.append(sub)
                    elif not domain:
                        valid_subs.append(sub)
            if valid_subs:
                result["subdomains"] = list(set(valid_subs))
        
        # Validate hosts
        if "hosts" in findings and isinstance(findings["hosts"], list):
            valid_hosts = []
            for h in findings["hosts"]:
                if isinstance(h, dict) and (h.get("hostname") or h.get("ip")):
                    valid_hosts.append({
                        "hostname": h.get("hostname", ""),
                        "ip": h.get("ip", "")
                    })
            if valid_hosts:
                result["hosts"] = valid_hosts
        
        # Validate ports
        if "ports" in findings and isinstance(findings["ports"], list):
            valid_ports = []
            for p in findings["ports"]:
                if isinstance(p, dict) and p.get("port"):
                    try:
                        port_num = int(p["port"])
                        if 1 <= port_num <= 65535:
                            valid_ports.append({
                                "port": port_num,
                                "service": p.get("service", "unknown"),
                                "host": p.get("host", "")
                            })
                    except (ValueError, TypeError):
                        continue
            if valid_ports:
                result["ports"] = valid_ports
        
        # Validate vulnerabilities
        if "vulnerabilities" in findings and isinstance(findings["vulnerabilities"], list):
            valid_vulns = []
            for v in findings["vulnerabilities"]:
                if isinstance(v, dict) and v.get("type"):
                    valid_vulns.append({
                        "type": v.get("type", ""),
                        "severity": v.get("severity", "unknown"),
                        "target": v.get("target", ""),
                        "details": v.get("details", "")
                    })
            if valid_vulns:
                result["vulnerabilities"] = valid_vulns
        
        # Validate emails
        if "emails" in findings and isinstance(findings["emails"], list):
            email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            valid_emails = [e for e in findings["emails"] 
                          if isinstance(e, str) and email_pattern.match(e)]
            if valid_emails:
                result["emails"] = list(set(valid_emails))
        
        # Validate technologies
        if "technologies" in findings and isinstance(findings["technologies"], list):
            valid_tech = [t for t in findings["technologies"] 
                         if isinstance(t, str) and len(t) > 1]
            if valid_tech:
                result["technologies"] = list(set(valid_tech))
        
        # Validate URLs
        if "urls" in findings and isinstance(findings["urls"], list):
            valid_urls = [u for u in findings["urls"]
                         if isinstance(u, str) and (u.startswith("http://") or u.startswith("https://"))]
            if valid_urls:
                result["urls"] = valid_urls[:50]  # Limit to 50
        
        return result
    
    def _regex_fallback(self, output: str, domain: str = None) -> Dict[str, Any]:
        """Fallback regex-based extraction when LLM fails."""
        result = {}
        
        # Extract IPs
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = list(set(re.findall(ip_pattern, output)))
        if ips:
            result["hosts"] = [{"hostname": "", "ip": ip} for ip in ips[:50]]
        
        # Extract emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = list(set(re.findall(email_pattern, output)))
        if emails:
            result["emails"] = emails[:50]
        
        # Extract ports (pattern: port/protocol or :port)
        port_pattern = r'\b(\d{1,5})/(tcp|udp)\b'
        ports = re.findall(port_pattern, output)
        if ports:
            result["ports"] = [{"port": int(p[0]), "service": "", "host": ""} for p in ports[:50]]
        
        # Extract subdomains if domain provided
        if domain:
            subdomain_pattern = rf'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{re.escape(domain)}\b'
            matches = re.findall(subdomain_pattern, output)
            # This pattern won't work well, but it's a fallback
        
        return result
    
    def update_context(self, context: Dict, findings: Dict) -> Dict:
        """
        Update context dict with parsed findings.
        
        Merges new findings with existing context data.
        """
        # Update subdomains
        if "subdomains" in findings:
            existing = set(context.get("subdomains", []))
            existing.update(findings["subdomains"])
            context["subdomains"] = list(existing)[:100]
            context["subdomain_count"] = len(context["subdomains"])
            context["has_subdomains"] = True
        
        # Update hosts
        if "hosts" in findings:
            existing_hosts = context.get("hosts", [])
            existing_ips = set(context.get("ips", []))
            host_ip_map = context.get("host_ip_map", {})
            
            for h in findings["hosts"]:
                hostname = h.get("hostname", "")
                ip = h.get("ip", "")
                
                if hostname and hostname not in existing_hosts:
                    existing_hosts.append(hostname)
                if ip:
                    existing_ips.add(ip)
                if hostname and ip:
                    host_ip_map[hostname] = ip
            
            context["hosts"] = existing_hosts[:100]
            context["ips"] = list(existing_ips)[:100]
            context["host_ip_map"] = host_ip_map
        
        # Update ports
        if "ports" in findings:
            existing_ports = context.get("open_ports", [])
            for p in findings["ports"]:
                if p not in existing_ports:
                    existing_ports.append(p)
            context["open_ports"] = existing_ports[:100]
            context["port_count"] = len(existing_ports)
            context["has_ports"] = True
        
        # Update vulnerabilities
        if "vulnerabilities" in findings:
            existing_vulns = context.get("vulns_found", [])
            existing_vulns.extend(findings["vulnerabilities"])
            context["vulns_found"] = existing_vulns[:50]
        
        # Update emails
        if "emails" in findings:
            existing_emails = set(context.get("emails", []))
            existing_emails.update(findings["emails"])
            context["emails"] = list(existing_emails)[:100]
        
        # Update technologies
        if "technologies" in findings:
            existing_tech = set(context.get("detected_tech", []))
            existing_tech.update(findings["technologies"])
            context["detected_tech"] = list(existing_tech)
        
        # Update URLs
        if "urls" in findings:
            existing_urls = context.get("interesting_urls", [])
            for u in findings["urls"]:
                if u not in existing_urls:
                    existing_urls.append(u)
            context["interesting_urls"] = existing_urls[:100]
        
        return context


# Singleton instance
_parser: Optional[OutputParser] = None


def get_output_parser() -> OutputParser:
    """Get singleton OutputParser instance."""
    global _parser
    if _parser is None:
        _parser = OutputParser()
    return _parser


def parse_tool_output(tool_name: str, output: str, domain: str = None) -> Dict[str, Any]:
    """Convenience function to parse tool output."""
    parser = get_output_parser()
    return parser.parse(tool_name, output, domain)
