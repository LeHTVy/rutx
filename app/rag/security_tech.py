"""
Security Technology Knowledge Base
===================================

Built-in knowledge about common security products and bypass techniques.
Used by SNODE to suggest intelligent attack strategies based on detected defenses.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class SecurityTech:
    """Represents a security technology with bypass information."""
    name: str
    category: str  # waf, cdn, firewall, ids, etc.
    description: str
    detection_headers: List[str]  # HTTP headers that indicate this tech
    detection_patterns: List[str]  # Patterns in responses
    bypass_methods: List[Dict[str, str]]  # {method, description, tool}
    origin_discovery: List[str]  # Methods to find real IP/origin


# ============================================================
# SECURITY TECHNOLOGY DATABASE
# ============================================================

SECURITY_TECH_DB: Dict[str, SecurityTech] = {
    
    # ─────────────────────────────────────────────────────────
    # CLOUDFLARE
    # ─────────────────────────────────────────────────────────
    "cloudflare": SecurityTech(
        name="Cloudflare",
        category="cdn_waf",
        description="Popular CDN and WAF that hides origin IP and filters malicious requests",
        detection_headers=[
            "cf-ray", "cf-cache-status", "cf-request-id",
            "server: cloudflare", "cf-connecting-ip"
        ],
        detection_patterns=[
            "cloudflare", "cf-ray:", "__cfduid", "cloudflare-nginx"
        ],
        bypass_methods=[
            {
                "method": "Historical DNS",
                "description": "Check DNS history for pre-Cloudflare IP records",
                "tool": "securitytrails",
                "command": "Use SecurityTrails or DNSlytics to find historical A records"
            },
            {
                "method": "Shodan SSL Search",
                "description": "Search Shodan for SSL certificate matching the domain",
                "tool": "shodan",
                "command": "shodan search ssl.cert.subject.cn:example.com"
            },
            {
                "method": "Mail Server MX",
                "description": "MX records often point to origin server, not CDN",
                "tool": "dig",
                "command": "dig MX example.com - then resolve the mail server IP"
            },
            {
                "method": "Subdomains",
                "description": "Some subdomains (dev, staging, api) may not be behind CF",
                "tool": "subfinder",
                "command": "Find subdomains and check which bypass Cloudflare"
            },
            {
                "method": "IPv6 Range",
                "description": "IPv6 addresses may expose origin if CF only proxies IPv4",
                "tool": "nmap",
                "command": "nmap -6 example.com"
            },
            {
                "method": "Censys Search",
                "description": "Search Censys for certificates containing the domain",
                "tool": "censys",
                "command": "Search parsed.extensions.subject_alt_name.dns_names:example.com"
            }
        ],
        origin_discovery=[
            "SecurityTrails historical DNS",
            "Shodan ssl:example.com",
            "Check MX records",
            "Scan subdomains for non-CF hosts",
            "Censys certificate search"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # BITNINJA
    # ─────────────────────────────────────────────────────────
    "bitninja": SecurityTech(
        name="BitNinja",
        category="waf",
        description="Server security suite with WAF, malware scanner, and IP reputation",
        detection_headers=[
            "x-bitninja", "x-bitninja-waf", "server: bitninja"
        ],
        detection_patterns=[
            "bitninja", "blocked by bitninja", "captcha.bitninja"
        ],
        bypass_methods=[
            {
                "method": "Slow Requests",
                "description": "Send requests slowly to avoid rate limiting",
                "tool": "custom",
                "command": "Add delays between requests (2-5 seconds)"
            },
            {
                "method": "User-Agent Rotation",
                "description": "Use legitimate browser User-Agents",
                "tool": "wpscan",
                "command": "wpscan --random-user-agent"
            },
            {
                "method": "IP Rotation",
                "description": "Use proxy rotation to avoid IP-based blocking",
                "tool": "proxychains",
                "command": "proxychains4 -f proxy.conf tool command"
            },
            {
                "method": "Clean IP",
                "description": "Use a fresh IP not in BitNinja's reputation DB",
                "tool": "vpn",
                "command": "Connect through residential VPN or fresh proxy"
            },
            {
                "method": "Captcha Solve",
                "description": "If shown captcha, solve manually or use service",
                "tool": "manual",
                "command": "Visit site in browser, solve captcha, extract cookies"
            }
        ],
        origin_discovery=[
            "BitNinja does not hide origin IP (unlike CDNs)",
            "Direct connection to server IP works"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # AKAMAI
    # ─────────────────────────────────────────────────────────
    "akamai": SecurityTech(
        name="Akamai",
        category="cdn_waf",
        description="Enterprise CDN and WAF used by large organizations",
        detection_headers=[
            "x-akamai-transformed", "akamai-origin-hop",
            "server: akamaighost", "x-akamai-request-id"
        ],
        detection_patterns=[
            "akamai", "akamaiedge", "akamaihd", "akam"
        ],
        bypass_methods=[
            {
                "method": "Origin Header Leak",
                "description": "Some configs leak origin in error pages",
                "tool": "curl",
                "command": "curl -H 'Host: invalid' https://target.com"
            },
            {
                "method": "SSL Cert Search",
                "description": "Find origin by searching for matching SSL certs",
                "tool": "shodan",
                "command": "shodan search ssl:target.com"
            },
            {
                "method": "Cache Poisoning",
                "description": "Exploit caching behavior to bypass WAF",
                "tool": "custom",
                "command": "Try X-Forwarded-Host header manipulation"
            }
        ],
        origin_discovery=[
            "Shodan SSL certificate search",
            "Historical DNS records",
            "Error page analysis"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # AWS WAF / CloudFront
    # ─────────────────────────────────────────────────────────
    "aws_waf": SecurityTech(
        name="AWS WAF / CloudFront",
        category="cdn_waf",
        description="Amazon's CDN and WAF service protecting web applications",
        detection_headers=[
            "x-amz-cf-id", "x-amz-cf-pop", "via: cloudfront",
            "x-cache: hit from cloudfront", "server: cloudfront"
        ],
        detection_patterns=[
            "cloudfront", "amazonaws", "x-amz-", "aws"
        ],
        bypass_methods=[
            {
                "method": "Unicode Bypass",
                "description": "Use Unicode characters to bypass WAF rules",
                "tool": "sqlmap",
                "command": "sqlmap --tamper=charunicodeescape"
            },
            {
                "method": "Chunked Encoding",
                "description": "Split payloads across chunks to evade detection",
                "tool": "custom",
                "command": "Use Transfer-Encoding: chunked with split payload"
            },
            {
                "method": "Origin Discovery",
                "description": "Find S3 buckets or EC2 instances directly",
                "tool": "s3scanner",
                "command": "Check for exposed S3 buckets: s3://target-backups"
            }
        ],
        origin_discovery=[
            "Search for exposed S3 buckets",
            "EC2 instance enumeration",
            "Lambda function URLs"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # CPANEL / MODSECURITY
    # ─────────────────────────────────────────────────────────
    "modsecurity": SecurityTech(
        name="ModSecurity",
        category="waf",
        description="Open-source WAF, often bundled with cPanel/Apache",
        detection_headers=[
            "server: apache", "mod_security", "modsecurity"
        ],
        detection_patterns=[
            "mod_security", "modsecurity", "not acceptable", 
            "406 not acceptable", "blocked by mod_security"
        ],
        bypass_methods=[
            {
                "method": "Case Variation",
                "description": "Use mixed case to bypass string matching",
                "tool": "sqlmap",
                "command": "sqlmap --tamper=randomcase"
            },
            {
                "method": "Comment Injection",
                "description": "Use SQL comments to split keywords",
                "tool": "sqlmap",
                "command": "sqlmap --tamper=space2comment"
            },
            {
                "method": "HPP (Parameter Pollution)",
                "description": "Use duplicate parameters to confuse WAF",
                "tool": "custom",
                "command": "?id=1&id=2 - WAF may check first, app uses second"
            },
            {
                "method": "Encoding Bypass",
                "description": "URL encode, double encode, or hex encode payloads",
                "tool": "sqlmap",
                "command": "sqlmap --tamper=charencode"
            }
        ],
        origin_discovery=[
            "WAF is on origin server - no CDN bypass needed"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # SUCURI
    # ─────────────────────────────────────────────────────────
    "sucuri": SecurityTech(
        name="Sucuri",
        category="waf",
        description="Website security platform with WAF and monitoring",
        detection_headers=[
            "x-sucuri-id", "server: sucuri", "x-sucuri-cache"
        ],
        detection_patterns=[
            "sucuri", "access denied - sucuri", "sucuri cloudproxy"
        ],
        bypass_methods=[
            {
                "method": "Origin IP Discovery",
                "description": "Sucuri proxies traffic - find origin like Cloudflare",
                "tool": "securitytrails",
                "command": "Check historical DNS for pre-Sucuri records"
            },
            {
                "method": "Whitelist Bypass",
                "description": "Some IPs may be whitelisted",
                "tool": "custom",
                "command": "Try from different geographic locations"
            }
        ],
        origin_discovery=[
            "Historical DNS records",
            "SSL certificate search"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # GOOGLE CLOUD / GCP
    # ─────────────────────────────────────────────────────────
    "gcp": SecurityTech(
        name="Google Cloud Platform",
        category="cdn_waf",
        description="Google's cloud infrastructure with Cloud Armor WAF",
        detection_headers=[
            "via: google", "server: google", "x-goog-", "x-cloud-trace"
        ],
        detection_patterns=[
            "googleusercontent", "googleapis", "gstatic", "google cloud", "cloud armor"
        ],
        bypass_methods=[
            {
                "method": "GCP Bucket Enum",
                "description": "Find exposed Google Cloud Storage buckets",
                "tool": "gcp_scanner",
                "command": "Check gs://target-bucket for exposed data"
            },
            {
                "method": "Cloud Armor Bypass",
                "description": "Use encoding tricks to bypass Cloud Armor rules",
                "tool": "sqlmap",
                "command": "sqlmap --tamper=between,randomcase"
            }
        ],
        origin_discovery=[
            "Search for exposed GCS buckets",
            "Compute Engine instance enumeration",
            "Cloud Functions URLs"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # AZURE / MICROSOFT
    # ─────────────────────────────────────────────────────────
    "azure": SecurityTech(
        name="Microsoft Azure",
        category="cdn_waf",
        description="Microsoft's cloud platform with Azure Front Door/WAF",
        detection_headers=[
            "x-azure-ref", "x-ms-request-id", "x-fd-healthprobe"
        ],
        detection_patterns=[
            "azure", "azurewebsites", "blob.core.windows.net", "azure front door"
        ],
        bypass_methods=[
            {
                "method": "Blob Storage Enum",
                "description": "Find exposed Azure Blob Storage containers",
                "tool": "azure_scanner",
                "command": "Check https://target.blob.core.windows.net"
            },
            {
                "method": "App Service Bypass",
                "description": "Direct access to .azurewebsites.net subdomain",
                "tool": "curl",
                "command": "curl https://target.azurewebsites.net"
            }
        ],
        origin_discovery=[
            "Check azurewebsites.net subdomains",
            "Azure Blob Storage enumeration",
            "Historical DNS for pre-Azure records"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # DIGITALOCEAN
    # ─────────────────────────────────────────────────────────
    "digitalocean": SecurityTech(
        name="DigitalOcean",
        category="cloud",
        description="Cloud hosting platform (droplets, spaces, apps)",
        detection_headers=[
            "server: nginx"  # Common but not definitive
        ],
        detection_patterns=[
            "digitalocean", "spaces.digitaloceancdn", "ondigitalocean.app"
        ],
        bypass_methods=[
            {
                "method": "Spaces Enum",
                "description": "Find exposed DigitalOcean Spaces buckets",
                "tool": "s3scanner",
                "command": "Check https://target.sfo3.digitaloceanspaces.com"
            },
            {
                "method": "Direct Droplet Access",
                "description": "DigitalOcean doesn't hide origin IPs by default",
                "tool": "nmap",
                "command": "Scan the droplet IP directly"
            }
        ],
        origin_discovery=[
            "DigitalOcean typically doesn't proxy - direct IP access works",
            "Check Spaces for exposed data"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # FASTLY
    # ─────────────────────────────────────────────────────────
    "fastly": SecurityTech(
        name="Fastly CDN",
        category="cdn_waf",
        description="Edge cloud platform with CDN and WAF capabilities",
        detection_headers=[
            "x-served-by", "x-cache", "fastly-restarts"
        ],
        detection_patterns=[
            "fastly", "fastly-", "served by fastly"
        ],
        bypass_methods=[
            {
                "method": "Origin Header Leak",
                "description": "Check for origin IP in error responses",
                "tool": "curl",
                "command": "curl -H 'Host: invalid' https://target.com"
            },
            {
                "method": "Historical DNS",
                "description": "Find pre-Fastly DNS records",
                "tool": "securitytrails",
                "command": "Check SecurityTrails for historical A records"
            }
        ],
        origin_discovery=[
            "SecurityTrails historical DNS",
            "SSL certificate search on Shodan",
            "Error page analysis"
        ]
    ),
    
    # ─────────────────────────────────────────────────────────
    # INCAPSULA / IMPERVA
    # ─────────────────────────────────────────────────────────
    "incapsula": SecurityTech(
        name="Imperva/Incapsula",
        category="cdn_waf",
        description="Enterprise WAF and DDoS protection service",
        detection_headers=[
            "x-cdn", "x-iinfo", "incap_ses"
        ],
        detection_patterns=[
            "incapsula", "imperva", "_incap_", "visid_incap"
        ],
        bypass_methods=[
            {
                "method": "Cookie Analysis",
                "description": "Analyze Incapsula cookies for bypass",
                "tool": "burp",
                "command": "Check incap_ses and visid_incap cookies"
            },
            {
                "method": "Historical DNS",
                "description": "Find origin IP from pre-Incapsula records",
                "tool": "securitytrails",
                "command": "DNS history lookup"
            }
        ],
        origin_discovery=[
            "Historical DNS records",
            "SSL certificate search",
            "MX record analysis"
        ]
    ),
}


def detect_security_tech(headers: dict, body: str = "") -> List[SecurityTech]:
    """
    Detect security technologies from HTTP response headers and body.
    
    Args:
        headers: HTTP response headers (case-insensitive)
        body: Response body text
    
    Returns:
        List of detected SecurityTech objects
    """
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower() if body else ""
    
    for tech_id, tech in SECURITY_TECH_DB.items():
        found = False
        
        # Check headers
        for detection_header in tech.detection_headers:
            header_key = detection_header.split(":")[0].strip()
            if header_key in headers_lower:
                if ":" in detection_header:
                    # Check value too
                    expected_val = detection_header.split(":", 1)[1].strip()
                    if expected_val in headers_lower.get(header_key, ""):
                        found = True
                else:
                    found = True
        
        # Check patterns in body
        if not found:
            for pattern in tech.detection_patterns:
                if pattern.lower() in body_lower or pattern.lower() in str(headers_lower):
                    found = True
                    break
        
        if found:
            detected.append(tech)
    
    return detected


def get_bypass_suggestions(tech_name: str) -> List[Dict[str, str]]:
    """Get bypass methods for a specific security technology."""
    tech = SECURITY_TECH_DB.get(tech_name.lower())
    if tech:
        return tech.bypass_methods
    return []


def get_origin_discovery_methods(tech_name: str) -> List[str]:
    """Get origin IP discovery methods for a security technology."""
    tech = SECURITY_TECH_DB.get(tech_name.lower())
    if tech:
        return tech.origin_discovery
    return []


def format_bypass_report(detected_techs: List[SecurityTech]) -> str:
    """Format a bypass report for detected security technologies."""
    if not detected_techs:
        return "No security technologies detected."
    
    report = "🛡️ **Security Technologies Detected:**\n\n"
    
    for tech in detected_techs:
        report += f"### {tech.name} ({tech.category})\n"
        report += f"{tech.description}\n\n"
        
        report += "**Bypass Methods:**\n"
        for method in tech.bypass_methods[:3]:  # Top 3
            report += f"- **{method['method']}**: {method['description']}\n"
            if method.get('command'):
                report += f"  `{method['command']}`\n"
        
        if tech.origin_discovery:
            report += "\n**Origin IP Discovery:**\n"
            for od in tech.origin_discovery[:3]:
                report += f"- {od}\n"
        
        report += "\n"
    
    return report
