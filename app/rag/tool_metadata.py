"""Comprehensive metadata for all security tools and their commands.
Used for semantic search and intelligent tool selection.

Each tool includes:
- category: Tool category for grouping
- phase: Pentest phase (1=Recon, 2=Scanning, 3=Exploitation, 4=Reporting)
- description: What the tool does
- tags: Keywords for semantic matching
- commands: Dict of command -> {description, use_cases, params}
"""
from typing import Dict, Any, List


# Pentest Phase Definitions
PHASE_NAMES = {
    1: "Reconnaissance",
    2: "Scanning & Enumeration", 
    3: "Exploitation",
    4: "Reporting"
}

# Category to Phase mapping
CATEGORY_PHASE_MAP = {
    "recon": 1,
    "osint": 1,
    "scanning": 2,
    "vuln_scan": 2,
    "web_discovery": 2,
    "web": 2,
    "network": 2,
    "brute_force": 3,
    "exploit": 3,
    "cloud": 2,
}





TOOL_METADATA: Dict[str, Dict[str, Any]] = {
    # ═══════════════════════════════════════════════════════════════
    # SCANNING TOOLS
    # ═══════════════════════════════════════════════════════════════
    "httpx": {
        "category": "scanning",
        "description": "Fast HTTP probing with technology detection",
        "tags": ["http", "web", "probe", "technology", "fingerprint", "status", "title", "alive"],
        "commands": {
            "probe": {
                "description": "Probe single target for HTTP status, title, and tech",
                "use_cases": ["check if host is alive", "detect web server", "get http status", "check web availability"],
                "params": ["target"],
            },
            "probe_list": {
                "description": "Probe multiple targets from file",
                "use_cases": ["batch probe hosts", "check multiple subdomains", "mass http check"],
                "params": ["file"],
            },
            "tech_detect": {
                "description": "Detect technologies with JSON output",
                "use_cases": ["fingerprint tech stack", "identify CMS", "detect frameworks"],
                "params": ["target"],
            },
        },
    },
    "nmap": {
        "category": "scanning",
        "description": "Network port scanner with service and version detection",
        "tags": ["port", "scan", "service", "version", "network", "tcp", "udp", "open ports", "firewall"],
        "commands": {
            "quick_scan": {
                "description": "Fast scan of common ports",
                "use_cases": ["quick port check", "initial reconnaissance", "fast scan"],
                "params": ["target"],
            },
            "syn_scan": {
                "description": "Stealth TCP SYN scan (requires root)",
                "use_cases": ["stealth scan", "evade detection", "firewall bypass"],
                "params": ["target", "ports"],
            },
            "tcp_scan": {
                "description": "TCP connect scan (no root needed)",
                "use_cases": ["port scan without root", "reliable scan"],
                "params": ["target", "ports"],
            },
            "udp_scan": {
                "description": "UDP port scan (requires root, slow)",
                "use_cases": ["find UDP services", "DNS scan", "SNMP scan"],
                "params": ["target"],
            },
            "service_scan": {
                "description": "Service version and script scan",
                "use_cases": ["identify services", "version detection", "service fingerprinting"],
                "params": ["target", "ports"],
            },
            "version_scan": {
                "description": "Version detection only",
                "use_cases": ["get service versions", "identify software"],
                "params": ["target", "ports"],
            },
            "os_detect": {
                "description": "Operating system detection (requires root)",
                "use_cases": ["identify OS", "fingerprint operating system"],
                "params": ["target"],
            },
            "aggressive": {
                "description": "OS detection, version, scripts, traceroute",
                "use_cases": ["comprehensive scan", "full enumeration"],
                "params": ["target", "ports"],
            },
            "full_scan": {
                "description": "Full port scan with version detection",
                "use_cases": ["scan all ports", "thorough scan", "complete enumeration"],
                "params": ["target"],
            },
            "vuln_scan": {
                "description": "NSE vulnerability scripts",
                "use_cases": ["find vulnerabilities", "security audit", "vuln detection"],
                "params": ["target", "ports"],
            },
            "default_scripts": {
                "description": "Default NSE scripts",
                "use_cases": ["basic enumeration", "common checks"],
                "params": ["target", "ports"],
            },
            "ping_sweep": {
                "description": "Ping scan, no port scan",
                "use_cases": ["find live hosts", "host discovery", "network sweep"],
                "params": ["target"],
            },
            "top_ports": {
                "description": "Scan top N ports",
                "use_cases": ["scan most common ports", "quick service scan"],
                "params": ["target", "count"],
            },
            "from_file": {
                "description": "Scan targets from file",
                "use_cases": ["batch scan", "scan subdomains", "multiple targets"],
                "params": ["file", "ports"],
            },
        },
    },
    "masscan": {
        "category": "scanning",
        "description": "Ultra-fast port scanner for large IP ranges",
        "tags": ["port", "fast", "scan", "large scale", "network", "mass"],
        "commands": {
            "scan": {
                "description": "Standard masscan",
                "use_cases": ["fast port scan", "large network scan", "quick discovery"],
                "params": ["target", "ports"],
            },
            "fast_scan": {
                "description": "High-speed scan (10k rate)",
                "use_cases": ["very fast scan", "large scale enumeration"],
                "params": ["target", "ports"],
            },
        },
    },
    
    # ═══════════════════════════════════════════════════════════════
    # RECONNAISSANCE TOOLS
    # ═══════════════════════════════════════════════════════════════
    "subfinder": {
        "category": "recon",
        "description": "Fast passive subdomain discovery tool",
        "tags": ["subdomain", "passive", "discovery", "enumeration", "dns"],
        "commands": {
            "enum": {
                "description": "Standard subdomain enumeration",
                "use_cases": ["find subdomains", "subdomain discovery", "passive recon"],
                "params": ["domain"],
            },
            "enum_all": {
                "description": "All sources subdomain enumeration",
                "use_cases": ["comprehensive subdomain search", "thorough enumeration"],
                "params": ["domain"],
            },
            "to_file": {
                "description": "Save subdomains to file",
                "use_cases": ["export subdomains", "save for later scanning"],
                "params": ["domain", "output"],
            },
        },
    },
    "amass": {
        "category": "recon",
        "description": "In-depth attack surface mapping and subdomain enumeration",
        "tags": ["subdomain", "attack surface", "dns", "osint", "comprehensive"],
        "commands": {
            "passive": {
                "description": "Passive subdomain enumeration",
                "use_cases": ["stealthy subdomain discovery", "passive recon"],
                "params": ["domain"],
            },
            "active": {
                "description": "Active subdomain enumeration with DNS resolution",
                "use_cases": ["thorough subdomain discovery", "active dns enumeration"],
                "params": ["domain"],
            },
        },
    },
    "bbot": {
        "category": "recon",
        "description": "Recursive internet scanner with subdomain enumeration",
        "tags": ["subdomain", "recon", "crawler", "osint", "recursive"],
        "commands": {
            "subdomains": {
                "description": "Subdomain enumeration preset",
                "use_cases": ["find subdomains", "comprehensive subdomain scan"],
                "params": ["domain"],
            },
            "web": {
                "description": "Web-focused reconnaissance",
                "use_cases": ["web recon", "discover web assets"],
                "params": ["domain"],
            },
            "full": {
                "description": "Full reconnaissance scan",
                "use_cases": ["complete recon", "comprehensive scan"],
                "params": ["domain"],
            },
        },
    },
    "katana": {
        "category": "recon",
        "description": "Fast web crawler for endpoint discovery",
        "tags": ["crawler", "spider", "endpoint", "url", "discovery", "web"],
        "commands": {
            "crawl": {
                "description": "Standard crawl with depth 3",
                "use_cases": ["find endpoints", "crawl website", "discover urls"],
                "params": ["url"],
            },
            "js": {
                "description": "JavaScript-aware crawling",
                "use_cases": ["find js endpoints", "api discovery", "spa crawling"],
                "params": ["url"],
            },
        },
    },
    "whois": {
        "category": "recon",
        "description": "Domain/IP registration lookup",
        "tags": ["domain", "registration", "owner", "registrar", "contact"],
        "commands": {
            "lookup": {
                "description": "WHOIS lookup",
                "use_cases": ["who owns domain", "domain registration", "contact info"],
                "params": ["target"],
            },
        },
    },
    "dig": {
        "category": "recon",
        "description": "DNS query and lookup tool",
        "tags": ["dns", "records", "mx", "ns", "txt", "lookup"],
        "commands": {
            "any": {
                "description": "Query ANY DNS records",
                "use_cases": ["get all dns records", "dns enumeration"],
                "params": ["domain"],
            },
            "mx": {
                "description": "Query MX records",
                "use_cases": ["find mail servers", "email infrastructure"],
                "params": ["domain"],
            },
            "ns": {
                "description": "Query NS records",
                "use_cases": ["find name servers", "dns infrastructure"],
                "params": ["domain"],
            },
            "txt": {
                "description": "Query TXT records",
                "use_cases": ["find SPF/DKIM", "txt records", "verification records"],
                "params": ["domain"],
            },
        },
    },
    "theHarvester": {
        "category": "osint",
        "description": "Email and subdomain harvesting from public sources",
        "tags": ["email", "harvest", "osint", "subdomain", "gathering"],
        "commands": {
            "quick": {
                "description": "Quick harvest with common sources",
                "use_cases": ["find emails", "quick osint", "email discovery"],
                "params": ["domain"],
            },
            "all": {
                "description": "All sources harvest",
                "use_cases": ["comprehensive email search", "thorough osint"],
                "params": ["domain"],
            },
            "subdomains": {
                "description": "Focus on subdomain discovery",
                "use_cases": ["find subdomains via osint"],
                "params": ["domain"],
            },
        },
    },
    
    # ═══════════════════════════════════════════════════════════════
    # VULNERABILITY SCANNING
    # ═══════════════════════════════════════════════════════════════
    "nuclei": {
        "category": "vuln_scan",
        "description": "Template-based vulnerability scanner with CVE detection",
        "tags": ["vulnerability", "cve", "security", "template", "scanner", "exploit", "rce", "sqli", "xss"],
        "commands": {
            "scan": {
                "description": "Standard scan with critical/high severity",
                "use_cases": ["find vulnerabilities", "security scan", "cve detection"],
                "params": ["target"],
            },
            "scan_fast": {
                "description": "Fast scan with top CVE/RCE templates",
                "use_cases": ["quick vuln check", "rce detection", "critical vulns only"],
                "params": ["target"],
            },
            "scan_json": {
                "description": "Scan with JSON output",
                "use_cases": ["parse results", "automation", "structured output"],
                "params": ["target"],
            },
            "scan_all": {
                "description": "Scan with all severity levels",
                "use_cases": ["comprehensive vuln scan", "full security audit"],
                "params": ["target"],
            },
            "scan_list": {
                "description": "Scan multiple targets from file",
                "use_cases": ["batch vulnerability scan", "scan subdomains"],
                "params": ["file"],
            },
        },
    },
    "nikto": {
        "category": "vuln_scan",
        "description": "Web server vulnerability scanner for misconfigurations",
        "tags": ["web", "vulnerability", "misconfiguration", "server", "scanner"],
        "commands": {
            "scan_https": {
                "description": "HTTPS scan on port 443",
                "use_cases": ["scan https server", "web vuln scan"],
                "params": ["host"],
            },
            "scan_http": {
                "description": "HTTP scan on port 80",
                "use_cases": ["scan http server", "web security check"],
                "params": ["host"],
            },
            "scan": {
                "description": "Custom port scan",
                "use_cases": ["scan specific port", "web server audit"],
                "params": ["host", "port"],
            },
        },
    },
    "sqlmap": {
        "category": "vuln_scan",
        "description": "Automatic SQL injection detection and exploitation",
        "tags": ["sql", "injection", "sqli", "database", "exploit", "web"],
        "commands": {
            "test": {
                "description": "Basic SQL injection test",
                "use_cases": ["check for sqli", "sql injection test", "database vuln"],
                "params": ["url"],
            },
            "deep_test": {
                "description": "Deep SQL injection test (level 3, risk 2)",
                "use_cases": ["thorough sqli test", "advanced injection"],
                "params": ["url"],
            },
            "dump": {
                "description": "Dump database contents",
                "use_cases": ["extract database", "data exfiltration"],
                "params": ["url"],
            },
        },
    },
    "gobuster": {
        "category": "web_discovery",
        "description": "Directory and file brute-forcing tool",
        "tags": ["directory", "brute", "discovery", "hidden", "files", "paths", "web"],
        "commands": {
            "dir": {
                "description": "Directory brute-force",
                "use_cases": ["find hidden directories", "discover paths", "web content discovery"],
                "params": ["url", "wordlist"],
            },
            "dir_redirects": {
                "description": "Directory scan excluding redirects",
                "use_cases": ["find directories ignoring redirects"],
                "params": ["url", "wordlist"],
            },
            "dns": {
                "description": "DNS subdomain brute-force",
                "use_cases": ["brute force subdomains", "dns enumeration"],
                "params": ["domain", "wordlist"],
            },
        },
    },
    "ffuf": {
        "category": "web_discovery",
        "description": "Fast web fuzzer for directories, parameters, and endpoints",
        "tags": ["fuzz", "web", "parameter", "directory", "fast", "discovery"],
        "commands": {
            "fuzz": {
                "description": "Standard fuzzing",
                "use_cases": ["web fuzzing", "find hidden content", "parameter discovery"],
                "params": ["url", "wordlist"],
            },
            "fuzz_json": {
                "description": "Fuzzing with JSON output",
                "use_cases": ["parse fuzz results", "automation"],
                "params": ["url", "wordlist"],
            },
        },
    },
    
    # ═══════════════════════════════════════════════════════════════
    # BRUTE FORCE TOOLS
    # ═══════════════════════════════════════════════════════════════
    "hydra": {
        "category": "brute_force",
        "description": "Fast network login cracker for SSH, FTP, HTTP, etc.",
        "tags": ["brute", "password", "crack", "login", "ssh", "ftp", "http", "authentication"],
        "commands": {
            "ssh": {
                "description": "SSH brute-force",
                "use_cases": ["crack ssh password", "ssh login attack"],
                "params": ["target", "user", "wordlist"],
            },
            "ftp": {
                "description": "FTP brute-force",
                "use_cases": ["crack ftp password", "ftp login attack"],
                "params": ["target", "user", "wordlist"],
            },
            "http_post": {
                "description": "HTTP POST form brute-force",
                "use_cases": ["web login crack", "form brute force"],
                "params": ["target", "user", "wordlist", "path", "form", "fail_msg"],
            },
            "http_get": {
                "description": "HTTP Basic/Digest auth brute-force",
                "use_cases": ["basic auth crack", "http authentication"],
                "params": ["target", "user", "wordlist", "path"],
            },
            "cpanel": {
                "description": "cPanel WHM brute-force",
                "use_cases": ["cpanel login attack", "whm crack"],
                "params": ["target", "user", "wordlist"],
            },
            "rdp": {
                "description": "RDP brute-force",
                "use_cases": ["windows rdp crack", "remote desktop attack"],
                "params": ["target", "user", "wordlist"],
            },
            "smb": {
                "description": "SMB brute-force",
                "use_cases": ["windows smb crack", "file share attack"],
                "params": ["target", "user", "wordlist"],
            },
        },
    },
    "medusa": {
        "category": "brute_force",
        "description": "Speedy parallel network login auditor",
        "tags": ["brute", "password", "parallel", "login", "auditor"],
        "commands": {
            "http": {
                "description": "HTTP Basic Auth brute-force",
                "use_cases": ["http auth crack", "basic authentication"],
                "params": ["target", "user", "wordlist"],
            },
            "ssh": {
                "description": "SSH brute-force",
                "use_cases": ["ssh password crack"],
                "params": ["target", "user", "wordlist"],
            },
            "ftp": {
                "description": "FTP brute-force",
                "use_cases": ["ftp password crack"],
                "params": ["target", "user", "wordlist"],
            },
            "mysql": {
                "description": "MySQL brute-force",
                "use_cases": ["mysql database crack", "db authentication"],
                "params": ["target", "user", "wordlist"],
            },
            "rdp": {
                "description": "RDP brute-force",
                "use_cases": ["rdp password crack"],
                "params": ["target", "user", "wordlist"],
            },
        },
    },
    "john": {
        "category": "brute_force",
        "description": "John the Ripper password hash cracker",
        "tags": ["hash", "crack", "password", "offline", "recovery"],
        "commands": {
            "crack": {
                "description": "Crack hashes with wordlist",
                "use_cases": ["crack password hashes", "offline attack"],
                "params": ["hashfile", "wordlist"],
            },
            "show": {
                "description": "Show cracked passwords",
                "use_cases": ["display cracked passwords"],
                "params": ["hashfile"],
            },
            "format": {
                "description": "Crack specific hash format",
                "use_cases": ["crack specific hash type"],
                "params": ["hashfile", "wordlist", "format"],
            },
        },
    },
    "hashcat": {
        "category": "brute_force",
        "description": "Advanced GPU-accelerated password recovery",
        "tags": ["hash", "crack", "gpu", "password", "recovery", "fast"],
        "commands": {
            "crack": {
                "description": "Crack hashes with GPU",
                "use_cases": ["gpu hash cracking", "fast password recovery"],
                "params": ["hashfile", "wordlist", "mode"],
            },
            "benchmark": {
                "description": "Benchmark hash cracking speed",
                "use_cases": ["test gpu speed", "performance check"],
                "params": [],
            },
        },
    },
    "crackmapexec": {
        "category": "brute_force",
        "description": "Swiss army knife for pentesting AD environments",
        "tags": ["active directory", "windows", "smb", "ldap", "ad", "network"],
        "commands": {
            "smb_enum": {
                "description": "SMB share enumeration",
                "use_cases": ["find smb shares", "windows enumeration"],
                "params": ["target"],
            },
            "smb_auth": {
                "description": "SMB authentication test",
                "use_cases": ["test credentials", "validate password"],
                "params": ["target", "user", "password"],
            },
            "smb_pass_spray": {
                "description": "SMB password spraying",
                "use_cases": ["password spray attack", "test common passwords"],
                "params": ["target", "userlist", "password"],
            },
        },
    },
    
    # ═══════════════════════════════════════════════════════════════
    # WEB TOOLS
    # ═══════════════════════════════════════════════════════════════
    "wfuzz": {
        "category": "web",
        "description": "Web application bruteforcer and fuzzer",
        "tags": ["fuzz", "web", "brute", "parameter", "injection"],
        "commands": {
            "dir": {
                "description": "Directory fuzzing",
                "use_cases": ["find directories", "content discovery"],
                "params": ["url", "wordlist"],
            },
            "param": {
                "description": "Parameter fuzzing",
                "use_cases": ["find parameters", "injection points"],
                "params": ["url", "wordlist", "param"],
            },
        },
    },
    "feroxbuster": {
        "category": "web",
        "description": "Fast, recursive content discovery tool",
        "tags": ["directory", "recursive", "discovery", "fast", "web"],
        "commands": {
            "scan": {
                "description": "Standard directory scan",
                "use_cases": ["find hidden content", "directory discovery"],
                "params": ["url", "wordlist"],
            },
            "recursive": {
                "description": "Recursive directory scan",
                "use_cases": ["deep content discovery", "recursive enumeration"],
                "params": ["url", "wordlist"],
            },
        },
    },
    "wpscan": {
        "category": "web",
        "description": "WordPress vulnerability scanner (with WAF bypass)",
        "tags": ["wordpress", "cms", "vulnerability", "plugin", "theme", "waf"],
        "commands": {
            "enum": {
                "description": "Enumerate plugins, themes, users (with random user-agent)",
                "use_cases": ["find wp vulnerabilities", "wordpress audit", "wp security scan"],
                "params": ["url"],
            },
            "brute": {
                "description": "WordPress login brute-force",
                "use_cases": ["crack wp login", "wordpress password"],
                "params": ["url", "users", "wordlist"],
            },
            "stealth": {
                "description": "Slow stealth scan with throttling to evade WAF",
                "use_cases": ["bypass waf", "slow wordpress scan", "evade detection"],
                "params": ["url"],
            },
        },
    },
    "whatweb": {
        "category": "web",
        "description": "Web technology fingerprinting",
        "tags": ["technology", "fingerprint", "cms", "framework", "detection"],
        "commands": {
            "scan": {
                "description": "Aggressive technology scan",
                "use_cases": ["identify technology", "fingerprint web app"],
                "params": ["url"],
            },
            "quick": {
                "description": "Quick technology check",
                "use_cases": ["fast tech detection"],
                "params": ["url"],
            },
        },
    },
    "wafw00f": {
        "category": "web",
        "description": "Web Application Firewall detection tool",
        "tags": ["waf", "firewall", "detection", "bypass", "security"],
        "commands": {
            "detect": {
                "description": "Detect WAF",
                "use_cases": ["find waf", "detect firewall", "check protection"],
                "params": ["url"],
            },
        },
    },
    "arjun": {
        "category": "web",
        "description": "HTTP parameter discovery suite",
        "tags": ["parameter", "discovery", "hidden", "http", "web"],
        "commands": {
            "discover": {
                "description": "Discover hidden parameters",
                "use_cases": ["find hidden params", "parameter enumeration"],
                "params": ["url"],
            },
        },
    },
    "dirsearch": {
        "category": "web",
        "description": "Web path scanner",
        "tags": ["directory", "path", "scanner", "discovery", "web"],
        "commands": {
            "scan": {
                "description": "Standard path scan",
                "use_cases": ["find paths", "directory discovery"],
                "params": ["url"],
            },
            "ext": {
                "description": "Scan specific extensions",
                "use_cases": ["find specific files", "extension-based scan"],
                "params": ["url", "extensions"],
            },
        },
    },
    
    # ═══════════════════════════════════════════════════════════════
    # OSINT TOOLS
    # ═══════════════════════════════════════════════════════════════
    "shodan": {
        "category": "osint",
        "description": "Search engine for Internet-connected devices",
        "tags": ["osint", "iot", "devices", "search", "exposed", "internet"],
        "commands": {
            "host": {
                "description": "Host information lookup",
                "use_cases": ["get ip info from shodan", "find exposed services"],
                "params": ["target"],
            },
            "search": {
                "description": "Search Shodan database",
                "use_cases": ["find vulnerable devices", "search internet"],
                "params": ["query"],
            },
            "domain": {
                "description": "Domain information",
                "use_cases": ["domain intelligence", "shodan domain info"],
                "params": ["domain"],
            },
        },
    },
    "securitytrails": {
        "category": "osint",
        "description": "SecurityTrails API: Historical DNS records, origin IP discovery, associated domains. Best tool for bypassing CDN/WAF like Cloudflare by finding pre-CDN IP addresses.",
        "tags": ["osint", "dns", "history", "origin", "cloudflare", "bypass", "cdn", "waf", "historical", "associated"],
        "commands": {
            "history": {
                "description": "Historical DNS records - find origin IP before CDN was added",
                "use_cases": ["bypass cloudflare", "find origin ip", "historical dns", "pre-cdn ip", "origin server"],
                "params": ["domain"],
            },
            "domain": {
                "description": "Current DNS data for domain",
                "use_cases": ["dns info", "domain intelligence"],
                "params": ["domain"],
            },
            "subdomains": {
                "description": "Enumerate subdomains",
                "use_cases": ["subdomain enumeration", "find subdomains"],
                "params": ["domain"],
            },
            "associated": {
                "description": "Find associated/related domains",
                "use_cases": ["related domains", "associated domains", "domain correlation"],
                "params": ["domain"],
            },
            "whois": {
                "description": "WHOIS history",
                "use_cases": ["whois history", "ownership history"],
                "params": ["domain"],
            },
        },
    },
    "dnsrecon": {
        "category": "recon",
        "description": "DNS enumeration and reconnaissance",
        "tags": ["dns", "enumeration", "zone", "transfer", "records"],
        "commands": {
            "std": {
                "description": "Standard DNS enumeration",
                "use_cases": ["dns recon", "enumerate dns records"],
                "params": ["domain"],
            },
            "zone": {
                "description": "Zone transfer attempt",
                "use_cases": ["axfr attack", "zone transfer"],
                "params": ["domain"],
            },
            "brute": {
                "description": "DNS brute-force",
                "use_cases": ["brute force subdomains via dns"],
                "params": ["domain", "wordlist"],
            },
        },
    },
    "clatscope": {
        "category": "osint",
        "description": "Intelligent OSINT: IP, WHOIS, DNS, subdomains, SSL, email breach, phone, origin IP discovery (CDN bypass). Use find_origin to bypass Cloudflare/CDN.",
        "tags": ["osint", "ip", "whois", "dns", "subdomain", "ssl", "email", "breach", "phone", "origin", "bypass", "cloudflare", "cdn"],
        "commands": {
            "ip": {
                "description": "IP geolocation and info",
                "use_cases": ["ip lookup", "geolocation", "isp info"],
                "params": ["target"],
            },
            "dns": {
                "description": "DNS records lookup",
                "use_cases": ["get dns records", "dns info"],
                "params": ["domain"],
            },
            "whois": {
                "description": "WHOIS lookup",
                "use_cases": ["domain registration", "owner info"],
                "params": ["domain"],
            },
            "subdomain": {
                "description": "Subdomain enumeration",
                "use_cases": ["find subdomains"],
                "params": ["domain"],
            },
            "ssl": {
                "description": "SSL certificate info",
                "use_cases": ["check ssl cert", "certificate details"],
                "params": ["domain"],
            },
            "metadata": {
                "description": "Web metadata extraction",
                "use_cases": ["get page metadata", "web info"],
                "params": ["url"],
            },
            "robots": {
                "description": "Robots.txt and sitemap",
                "use_cases": ["check robots.txt", "find sitemap"],
                "params": ["domain"],
            },
            "phone": {
                "description": "Phone number lookup",
                "use_cases": ["phone validation", "carrier info"],
                "params": ["phone"],
            },
            "email": {
                "description": "Email validation",
                "use_cases": ["validate email", "email format check"],
                "params": ["email"],
            },
            "breach": {
                "description": "Email breach check",
                "use_cases": ["check if email was breached", "hibp check"],
                "params": ["email"],
            },
            "reverse_dns": {
                "description": "Reverse DNS lookup",
                "use_cases": ["ip to hostname", "ptr record"],
                "params": ["ip"],
            },
            "find_origin": {
                "description": "Find origin IP behind CDN/WAF using historical DNS and wayback",
                "use_cases": ["bypass cloudflare", "find origin ip", "cdn bypass", "waf bypass", "real ip", "origin server"],
                "params": ["domain"],
            },
            "full": {
                "description": "Full OSINT scan: IP + DNS + WHOIS + SSL combined",
                "use_cases": ["full osint", "comprehensive scan", "all info"],
                "params": ["domain"],
            },
        },
    },
    "recon-ng": {
        "category": "osint",
        "description": "Full-featured OSINT reconnaissance framework",
        "tags": ["osint", "framework", "recon", "intelligence", "contacts"],
        "commands": {
            "hosts": {
                "description": "Find hosts via HackerTarget",
                "use_cases": ["discover hosts", "osint hosts"],
                "params": ["domain"],
            },
            "whois": {
                "description": "WHOIS via BuiltWith",
                "use_cases": ["domain osint", "builtwith lookup"],
                "params": ["domain"],
            },
        },
    },
    "fierce": {
        "category": "recon",
        "description": "DNS reconnaissance tool",
        "tags": ["dns", "recon", "enumeration", "discovery"],
        "commands": {
            "scan": {
                "description": "DNS reconnaissance scan",
                "use_cases": ["dns recon", "domain enumeration"],
                "params": ["domain"],
            },
        },
    },
    
    # ═══════════════════════════════════════════════════════════════
    # NETWORK TOOLS
    # ═══════════════════════════════════════════════════════════════
    "nc": {
        "category": "network",
        "description": "Netcat - read/write network connections",
        "tags": ["netcat", "network", "connection", "banner", "listener", "shell"],
        "commands": {
            "connect": {
                "description": "Connect to host/port",
                "use_cases": ["test connection", "grab banner", "connect to service"],
                "params": ["host", "port"],
            },
            "listen": {
                "description": "Listen on port",
                "use_cases": ["reverse shell listener", "catch connection"],
                "params": ["port"],
            },
            "scan": {
                "description": "Port scan",
                "use_cases": ["quick port scan", "test ports"],
                "params": ["host", "port_range"],
            },
        },
    },
    "enum4linux": {
        "category": "network",
        "description": "Windows/Samba enumeration tool",
        "tags": ["smb", "windows", "samba", "enumeration", "shares", "users"],
        "commands": {
            "all": {
                "description": "Full enumeration",
                "use_cases": ["enumerate windows/samba", "smb enumeration"],
                "params": ["target"],
            },
            "users": {
                "description": "User enumeration",
                "use_cases": ["find users", "list smb users"],
                "params": ["target"],
            },
        },
    },
    "nbtscan": {
        "category": "network",
        "description": "NetBIOS name scanner",
        "tags": ["netbios", "scan", "windows", "network"],
        "commands": {
            "scan": {
                "description": "NetBIOS scan",
                "use_cases": ["find netbios names", "windows discovery"],
                "params": ["target"],
            },
        },
    },
    "smbclient": {
        "category": "network",
        "description": "SMB/CIFS client for Windows shares",
        "tags": ["smb", "cifs", "shares", "windows", "file"],
        "commands": {
            "list": {
                "description": "List shares (null session)",
                "use_cases": ["find smb shares", "anonymous access"],
                "params": ["target"],
            },
            "connect": {
                "description": "Connect to share",
                "use_cases": ["access share", "browse files"],
                "params": ["target", "share", "user", "password"],
            },
        },
    },
    "responder": {
        "category": "network",
        "description": "LLMNR, NBT-NS and MDNS poisoner",
        "tags": ["llmnr", "nbt-ns", "poison", "mitm", "capture", "credentials"],
        "commands": {
            "analyze": {
                "description": "Analyze mode (passive)",
                "use_cases": ["monitor network", "passive capture"],
                "params": ["interface"],
            },
            "poison": {
                "description": "Active poisoning",
                "use_cases": ["capture credentials", "mitm attack"],
                "params": ["interface"],
            },
        },
    },
    "tcpdump": {
        "category": "network",
        "description": "Network packet analyzer",
        "tags": ["packet", "capture", "sniffer", "network", "pcap"],
        "commands": {
            "capture": {
                "description": "Capture packets to file",
                "use_cases": ["capture traffic", "packet capture"],
                "params": ["interface", "count", "output"],
            },
            "read": {
                "description": "Read pcap file",
                "use_cases": ["analyze capture", "read pcap"],
                "params": ["file"],
            },
        },
    },
    
    # ═══════════════════════════════════════════════════════════════
    # CLOUD & CONTAINER TOOLS
    # ═══════════════════════════════════════════════════════════════
    "trufflehog": {
        "category": "cloud",
        "description": "Find leaked credentials in git repos",
        "tags": ["secrets", "credentials", "git", "leak", "api key", "password"],
        "commands": {
            "git": {
                "description": "Scan git repository",
                "use_cases": ["find secrets in repo", "credential leak detection"],
                "params": ["repo_url"],
            },
            "github": {
                "description": "Scan GitHub organization",
                "use_cases": ["org secret scan", "github audit"],
                "params": ["org"],
            },
            "filesystem": {
                "description": "Scan filesystem",
                "use_cases": ["find secrets in files", "local scan"],
                "params": ["path"],
            },
        },
    },
    "gitleaks": {
        "category": "cloud",
        "description": "Scan git repos for secrets and keys",
        "tags": ["secrets", "git", "leak", "keys", "credentials"],
        "commands": {
            "detect": {
                "description": "Detect secrets in repo",
                "use_cases": ["find secrets", "git audit"],
                "params": ["path"],
            },
            "protect": {
                "description": "Protect mode (pre-commit)",
                "use_cases": ["prevent secret commits"],
                "params": ["path"],
            },
        },
    },
    "trivy": {
        "category": "cloud",
        "description": "Vulnerability scanner for containers and IaC",
        "tags": ["container", "docker", "vulnerability", "iac", "security"],
        "commands": {
            "image": {
                "description": "Scan container image",
                "use_cases": ["docker security", "container vulnerabilities"],
                "params": ["image"],
            },
            "fs": {
                "description": "Scan filesystem",
                "use_cases": ["find vulns in files", "dependency scan"],
                "params": ["path"],
            },
            "repo": {
                "description": "Scan git repository",
                "use_cases": ["repo security scan", "code vulnerabilities"],
                "params": ["repo_url"],
            },
        },
    },
    "prowler": {
        "category": "cloud",
        "description": "AWS security best practices checker",
        "tags": ["aws", "cloud", "security", "audit", "compliance"],
        "commands": {
            "aws": {
                "description": "Full AWS audit",
                "use_cases": ["aws security audit", "cloud compliance"],
                "params": [],
            },
            "aws_service": {
                "description": "Audit specific AWS service",
                "use_cases": ["service-specific audit"],
                "params": ["service"],
            },
        },
    },
    "docker": {
        "category": "cloud",
        "description": "Container runtime and management",
        "tags": ["container", "docker", "runtime", "management"],
        "commands": {
            "ps": {
                "description": "List containers",
                "use_cases": ["show running containers", "list docker"],
                "params": [],
            },
            "images": {
                "description": "List images",
                "use_cases": ["show docker images"],
                "params": [],
            },
            "inspect": {
                "description": "Inspect container",
                "use_cases": ["container details", "inspect config"],
                "params": ["container"],
            },
        },
    },
    "kubectl": {
        "category": "cloud",
        "description": "Kubernetes command-line tool",
        "tags": ["kubernetes", "k8s", "cluster", "container", "orchestration"],
        "commands": {
            "get_pods": {
                "description": "List all pods",
                "use_cases": ["show pods", "k8s enumeration"],
                "params": [],
            },
            "get_secrets": {
                "description": "List secrets",
                "use_cases": ["find k8s secrets", "secret enumeration"],
                "params": [],
            },
            "describe": {
                "description": "Describe resource",
                "use_cases": ["get resource details"],
                "params": ["resource", "name"],
            },
        },
    },
    
    # ═══════════════════════════════════════════════════════════════
    # EXPLOITATION TOOLS
    # ═══════════════════════════════════════════════════════════════
    "msfconsole": {
        "category": "exploit",
        "description": "Metasploit Framework - exploitation and post-exploitation",
        "tags": ["metasploit", "exploit", "shell", "payload", "post-exploitation", "cve", "lfi", "rce"],
        "commands": {
            "search": {
                "description": "Search for exploits and modules",
                "use_cases": ["find exploit", "search vulnerability", "find cve module"],
                "params": ["query"],
            },
            "exec": {
                "description": "Execute single MSF command",
                "use_cases": ["run metasploit command", "msf automation"],
                "params": ["command"],
            },
            "info": {
                "description": "Get info about a module",
                "use_cases": ["module details", "exploit info"],
                "params": ["module"],
            },
            "aux_scan": {
                "description": "Run auxiliary scanner module against target",
                "use_cases": ["scan with metasploit", "aux module run"],
                "params": ["module", "target"],
            },
            "resource": {
                "description": "Run resource script",
                "use_cases": ["automated exploitation", "msf script"],
                "params": ["resource_file"],
            },
        },
    },
    "msfvenom": {
        "category": "exploit",
        "description": "Generate payloads for various platforms",
        "tags": ["payload", "generate", "shell", "reverse", "metasploit"],
        "commands": {
            "list_payloads": {
                "description": "List available payloads",
                "use_cases": ["show payloads", "payload options"],
                "params": [],
            },
            "generate": {
                "description": "Generate custom payload",
                "use_cases": ["create payload", "generate shell"],
                "params": ["payload", "lhost", "lport", "format", "output"],
            },
            "generate_shell": {
                "description": "Generate Linux reverse shell",
                "use_cases": ["linux shell", "reverse connection"],
                "params": ["lhost", "lport", "output"],
            },
        },
    },
    "searchsploit": {
        "category": "exploit",
        "description": "Search Exploit-DB for known exploits",
        "tags": ["exploit", "exploit-db", "cve", "vulnerability", "poc"],
        "commands": {
            "search": {
                "description": "Search for exploits",
                "use_cases": ["find exploits", "search exploit-db"],
                "params": ["query"],
            },
            "search_json": {
                "description": "Search with JSON output",
                "use_cases": ["parse exploit results", "automation"],
                "params": ["query"],
            },
            "examine": {
                "description": "Examine specific exploit",
                "use_cases": ["view exploit code", "read poc"],
                "params": ["exploit_id"],
            },
        },
    },
    
    # ═══════════════════════════════════════════════════════════════
    # CUSTOM SNODE TOOLS
    # ═══════════════════════════════════════════════════════════════
    "passgen": {
        "category": "brute_force",
        "description": "Smart targeted password generator based on company/keywords",
        "tags": ["password", "generate", "wordlist", "targeted", "custom"],
        "commands": {
            "generate": {
                "description": "Generate wordlist from company name",
                "use_cases": ["create targeted wordlist", "custom passwords"],
                "params": ["company"],
            },
            "keywords": {
                "description": "Generate with additional keywords",
                "use_cases": ["keyword-based wordlist"],
                "params": ["company", "keywords"],
            },
        },
    },
    "credcheck": {
        "category": "osint",
        "description": "Check credentials against leaked databases (HaveIBeenPwned)",
        "tags": ["credentials", "breach", "leak", "hibp", "password"],
        "commands": {
            "password": {
                "description": "Check password breach status",
                "use_cases": ["check if password leaked", "hibp password"],
                "params": ["password"],
            },
            "email": {
                "description": "Check email breach status",
                "use_cases": ["check email breaches", "hibp email"],
                "params": ["email"],
            },
            "wordlist": {
                "description": "Check passwords from wordlist",
                "use_cases": ["batch password check"],
                "params": ["wordlist"],
            },
            "domain": {
                "description": "Check domain-related breaches",
                "use_cases": ["domain breach check"],
                "params": ["domain"],
            },
        },
    },
    "cpanelbrute": {
        "category": "brute_force",
        "description": "Dedicated cPanel/WHM brute force tool",
        "tags": ["cpanel", "whm", "brute", "hosting", "login"],
        "commands": {
            "cpanel": {
                "description": "cPanel login brute-force",
                "use_cases": ["crack cpanel", "hosting attack"],
                "params": ["target", "user", "wordlist"],
            },
            "whm": {
                "description": "WHM admin brute-force",
                "use_cases": ["crack whm", "root cpanel attack"],
                "params": ["target", "wordlist"],
            },
        },
    },
}


def get_all_tools() -> List[str]:
    """Get list of all tool names."""
    return list(TOOL_METADATA.keys())


def get_tool_commands(tool_name: str) -> List[str]:
    """Get list of commands for a tool."""
    tool = TOOL_METADATA.get(tool_name, {})
    return list(tool.get("commands", {}).keys())


def get_categories() -> List[str]:
    """Get unique categories."""
    return list(set(t["category"] for t in TOOL_METADATA.values()))


def get_tools_by_category(category: str) -> List[str]:
    """Get tools in a specific category."""
    return [name for name, data in TOOL_METADATA.items() 
            if data["category"] == category]


def get_tool_phase(tool_name: str) -> int:
    """Get the pentest phase for a tool (1-4)."""
    tool = TOOL_METADATA.get(tool_name, {})
    category = tool.get("category", "recon")
    return CATEGORY_PHASE_MAP.get(category, 1)


def get_tools_by_phase(phase: int) -> List[str]:
    """Get all tools appropriate for a specific phase."""
    tools = []
    for name, data in TOOL_METADATA.items():
        category = data.get("category", "")
        tool_phase = CATEGORY_PHASE_MAP.get(category, 1)
        if tool_phase <= phase:  # Include all tools up to current phase
            tools.append(name)
    return tools


def get_phase_for_category(category: str) -> int:
    """Get phase number for a category."""
    return CATEGORY_PHASE_MAP.get(category, 1)
