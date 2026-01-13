"""
Cloud Service Metadata
======================

Metadata for cloud service providers (CDN, hosting, etc.) to categorize IPs.
Stored in ChromaDB for semantic search and easy extension.

Supports:
- Cloudflare, DigitalOcean, Google Cloud, AWS, Azure, Linode, etc.
- IP ranges, ASN ranges, detection patterns
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class CloudService:
    """Metadata for a cloud service provider."""
    name: str
    category: str  # "cdn", "hosting", "waf", "dns"
    description: str
    ip_prefixes: List[str]  # IP prefixes (e.g., "104.", "172.64")
    asn_ranges: List[str]  # ASN ranges (e.g., "AS13335", "AS14061-AS14065")
    detection_headers: List[str]  # HTTP headers for detection
    detection_patterns: List[str]  # Patterns in response


# Cloud service metadata database
CLOUD_SERVICES: Dict[str, CloudService] = {
    "cloudflare": CloudService(
        name="Cloudflare",
        category="cdn_waf",
        description="Popular CDN and WAF provider",
        ip_prefixes=["104.", "172.64", "172.65", "172.66", "172.67", "173.245"],
        asn_ranges=["AS13335"],
        detection_headers=["cf-ray", "cf-cache-status", "cf-request-id", "server: cloudflare"],
        detection_patterns=["cloudflare", "cf-ray:", "__cfduid"]
    ),
    "digitalocean": CloudService(
        name="DigitalOcean",
        category="hosting",
        description="Cloud hosting provider",
        ip_prefixes=["159.89.", "167.99.", "138.68.", "157.230.", "188.166.", "165.227.", "46.101.", "159.203."],
        asn_ranges=["AS14061"],
        detection_headers=[],
        detection_patterns=["digitalocean"]
    ),
    "google_cloud": CloudService(
        name="Google Cloud Platform",
        category="hosting",
        description="Google Cloud hosting",
        ip_prefixes=["35.", "34.", "104.", "130.", "146.", "162.", "172.", "173.", "192.", "8.34.", "8.35."],
        asn_ranges=["AS15169", "AS36040", "AS36384", "AS36385"],
        detection_headers=["server: gws", "x-goog-"],
        detection_patterns=["google", "gws"]
    ),
    "aws": CloudService(
        name="Amazon Web Services",
        category="hosting",
        description="AWS cloud hosting",
        ip_prefixes=["3.", "13.", "18.", "23.", "34.", "35.", "44.", "50.", "52.", "54.", "99.", "107.", "108.", "174.", "176.", "177.", "184.", "204.", "205.", "207.", "208.", "209.", "216."],
        asn_ranges=["AS16509", "AS14618", "AS55960"],
        detection_headers=["server: aws", "x-amz-"],
        detection_patterns=["amazonaws", "aws"]
    ),
    "azure": CloudService(
        name="Microsoft Azure",
        category="hosting",
        description="Azure cloud hosting",
        ip_prefixes=["13.", "20.", "23.", "40.", "51.", "52.", "65.", "70.", "102.", "104.", "168.", "191.", "193.", "207.", "209."],
        asn_ranges=["AS8075", "AS8068", "AS8069"],
        detection_headers=["server: azure", "x-azure-"],
        detection_patterns=["azure", "microsoft"]
    ),
    "linode": CloudService(
        name="Linode",
        category="hosting",
        description="Linode cloud hosting",
        ip_prefixes=["45.79.", "45.33.", "139.162.", "172.104.", "192.53.", "198.74.", "50.116."],
        asn_ranges=["AS63949"],
        detection_headers=[],
        detection_patterns=["linode"]
    ),
    "vultr": CloudService(
        name="Vultr",
        category="hosting",
        description="Vultr cloud hosting",
        ip_prefixes=["45.76.", "45.77.", "104.238.", "108.61.", "149.28.", "167.88.", "185.230.", "207.246."],
        asn_ranges=["AS20473"],
        detection_headers=[],
        detection_patterns=["vultr"]
    ),
    "heroku": CloudService(
        name="Heroku",
        category="hosting",
        description="Heroku PaaS platform",
        ip_prefixes=["54.", "50.", "52.", "54.", "107.", "174.", "184."],
        asn_ranges=["AS11748"],
        detection_headers=["server: heroku", "x-heroku-"],
        detection_patterns=["heroku"]
    ),
    "fastly": CloudService(
        name="Fastly",
        category="cdn",
        description="Fastly CDN",
        ip_prefixes=["151.101.", "199.27.", "199.232."],
        asn_ranges=["AS54113"],
        detection_headers=["fastly-request-id", "fastly-ff"],
        detection_patterns=["fastly"]
    ),
    "cloudfront": CloudService(
        name="AWS CloudFront",
        category="cdn",
        description="AWS CloudFront CDN",
        ip_prefixes=["13.", "18.", "52.", "54.", "99.", "204.", "205.", "216."],
        asn_ranges=["AS16509"],
        detection_headers=["server: cloudfront", "x-amz-cf-"],
        detection_patterns=["cloudfront"]
    ),
    "akamai": CloudService(
        name="Akamai",
        category="cdn",
        description="Akamai CDN",
        ip_prefixes=["23.", "104.", "184.", "2."],
        asn_ranges=["AS16625", "AS21342"],
        detection_headers=["server: akamai", "x-akamai-"],
        detection_patterns=["akamai"]
    ),
}


def get_cloud_service_for_ip(ip: str, asn: Optional[int] = None) -> Optional[str]:
    """
    Identify cloud service from IP address and optional ASN.
    
    Returns:
        Service name (e.g., "cloudflare") or None if not identified
    """
    for service_name, service in CLOUD_SERVICES.items():
        # Check IP prefixes
        for prefix in service.ip_prefixes:
            if ip.startswith(prefix):
                return service_name
        
        # Check ASN ranges
        if asn:
            for asn_range in service.asn_ranges:
                if asn_range.startswith("AS"):
                    try:
                        asn_num = int(asn_range[2:])
                        if asn == asn_num:
                            return service_name
                    except ValueError:
                        pass
    
    return None


def categorize_ip(ip: str, asn: Optional[int] = None) -> Dict[str, Any]:
    """
    Categorize an IP address.
    
    Returns:
        Dict with category info: {service, category, is_cdn, is_hosting, is_origin}
    """
    service_name = get_cloud_service_for_ip(ip, asn)
    
    if service_name:
        service = CLOUD_SERVICES[service_name]
        return {
            "service": service_name,
            "category": service.category,
            "is_cdn": service.category in ["cdn", "cdn_waf"],
            "is_hosting": service.category == "hosting",
            "is_origin": False,  # CDN/hosting IPs are not origin
            "name": service.name
        }
    else:
        # Unknown IP - likely origin server
        return {
            "service": None,
            "category": "unknown",
            "is_cdn": False,
            "is_hosting": False,
            "is_origin": True,  # Unknown IPs are potential origin servers
            "name": "Unknown"
        }
