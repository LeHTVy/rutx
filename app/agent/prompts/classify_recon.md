You are classifying a reconnaissance request for a penetration test.

Given the user query and context, determine what type of reconnaissance is needed.

## Recon Types

### subdomain_enum
- Subdomain enumeration
- Finding subdomains of a domain
- Keywords: subdomain, enumerate, subfinder, amass

### osint
- Open Source Intelligence gathering
- Emails, public information
- Keywords: osint, email, harvester, information

### dns_info
- DNS enumeration and lookup
- WHOIS, DNS records
- Keywords: dns, whois, records, nameserver

### waf_detect
- WAF/CDN detection
- Identifying protection
- Keywords: waf, cdn, firewall, cloudflare

### tech_fingerprint
- Technology stack identification
- Detecting frameworks, CMS
- Keywords: technology, tech stack, what is, identify

### device_search
- Shodan/device search
- Finding exposed devices
- Keywords: shodan, exposed, devices, iot

### general_recon
- General reconnaissance
- Starting point for target
- Keywords: recon, discover, information gather

## Context
Query: {query}
Has Domain: {has_domain}
Has Subdomains: {has_subdomains}

## Output
Return ONLY the recon type name, nothing else.
