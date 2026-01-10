"""
SNODE Native OSINT Module
==========================

Built-in OSINT functions for IP lookup, DNS, WHOIS, etc.
Based on clatscope approach, integrated directly into SNODE.
"""
import socket
import requests
from typing import Dict, Any, Optional, List


# ============================================================
# IP LOOKUP (using ipinfo.io like clatscope)
# ============================================================

def get_ip_details(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get IP details from ipinfo.io (same as clatscope).
    Free tier: 50k requests/month.
    
    Returns:
        {ip, city, region, country, org, isp, asn, timezone, loc}
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Parse org field to extract ASN and ISP
        org = data.get("org", "")
        asn = None
        isp = org
        if org and org.startswith("AS"):
            parts = org.split(" ", 1)
            if parts[0].startswith("AS") and parts[0][2:].isdigit():
                asn = int(parts[0][2:])
                isp = parts[1] if len(parts) > 1 else org
        
        return {
            "ip": data.get("ip", ip),
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "country": data.get("country", "Unknown"),
            "postal": data.get("postal", ""),
            "org": org,
            "isp": isp,
            "asn": asn,
            "timezone": data.get("timezone", ""),
            "loc": data.get("loc", ""),
            "hostname": data.get("hostname", "")
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def lookup_ip(ip: str) -> Dict[str, Any]:
    """Alias for get_ip_details."""
    return get_ip_details(ip) or {"ip": ip, "error": "Lookup failed"}


# ============================================================
# DNS LOOKUP
# ============================================================

def dns_lookup(domain: str) -> Dict[str, Any]:
    """
    Perform DNS lookup for a domain.
    
    Returns:
        {a_records, aaaa_records, mx_records, ns_records, txt_records}
    """
    try:
        import dns.resolver
    except ImportError:
        return {"domain": domain, "error": "dnspython not installed"}
    
    result = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname_records": []
    }
    
    record_types = {
        "A": "a_records",
        "AAAA": "aaaa_records",
        "MX": "mx_records",
        "NS": "ns_records",
        "TXT": "txt_records",
        "CNAME": "cname_records"
    }
    
    for rtype, key in record_types.items():
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                if rtype == "MX":
                    result[key].append({"priority": rdata.preference, "host": str(rdata.exchange)})
                else:
                    result[key].append(str(rdata))
        except Exception:
            pass
    
    return result


def resolve_domain(domain: str) -> List[str]:
    """Resolve domain to IP addresses."""
    try:
        return list(set(socket.gethostbyname_ex(domain)[2]))
    except Exception:
        return []


# ============================================================
# WHOIS LOOKUP
# ============================================================

def whois_lookup(domain: str) -> Dict[str, Any]:
    """
    Perform WHOIS lookup for a domain.
    
    Returns:
        {domain, registrar, creation_date, expiration_date, name_servers, ...}
    """
    try:
        import whois
        w = whois.whois(domain)
        
        return {
            "domain": domain,
            "registrar": w.registrar or "Unknown",
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "updated_date": str(w.updated_date) if w.updated_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
            "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
            "org": w.org or "Unknown",
            "country": w.country or "Unknown"
        }
    except ImportError:
        return {"domain": domain, "error": "python-whois not installed"}
    except Exception as e:
        return {"domain": domain, "error": str(e)}


# ============================================================
# REVERSE DNS
# ============================================================

def reverse_dns(ip: str) -> Dict[str, Any]:
    """Perform reverse DNS lookup for an IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {"ip": ip, "hostname": hostname}
    except Exception:
        return {"ip": ip, "hostname": None}


# ============================================================
# COMBINED RECON
# ============================================================

def full_recon(target: str) -> Dict[str, Any]:
    """
    Perform full OSINT recon on a target (domain or IP).
    
    Returns combined results from all lookup functions.
    """
    result = {"target": target}
    
    # Determine if target is IP or domain
    try:
        socket.inet_aton(target)
        is_ip = True
    except socket.error:
        is_ip = False
    
    if is_ip:
        # IP-based recon
        result["ip_info"] = lookup_ip(target)
        result["reverse_dns"] = reverse_dns(target)
    else:
        # Domain-based recon
        result["whois"] = whois_lookup(target)
        result["dns"] = dns_lookup(target)
        
        # Resolve and lookup IPs
        ips = resolve_domain(target)
        result["resolved_ips"] = ips
        
        if ips:
            result["ip_info"] = lookup_ip(ips[0])
    
    return result


# ============================================================
# QUICK ACCESSORS
# ============================================================

def get_isp(ip: str) -> str:
    """Get just the ISP for an IP."""
    info = lookup_ip(ip)
    return info.get("isp", "Unknown")


def get_asn(ip: str) -> Optional[int]:
    """Get just the ASN for an IP."""
    info = lookup_ip(ip)
    return info.get("asn")


def get_location(ip: str) -> str:
    """Get location string for an IP."""
    info = lookup_ip(ip)
    parts = [info.get("city", ""), info.get("region", ""), info.get("country", "")]
    return ", ".join(p for p in parts if p and p != "Unknown")
