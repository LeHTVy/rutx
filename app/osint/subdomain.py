"""
SNODE OSINT - Subdomain Enumeration
====================================

Native subdomain discovery without external dependencies.
Uses crt.sh API for certificate transparency logs.
"""
import requests
from typing import List, Set, Optional
import json


def enumerate_subdomains_crtsh(domain: str, timeout: int = 60) -> List[str]:
    """
    Enumerate subdomains using crt.sh (Certificate Transparency logs).
    
    This is the same method used by clatscope.
    Free, no API key needed.
    
    Args:
        domain: Target domain (e.g., "example.com")
        timeout: Request timeout in seconds
        
    Returns:
        List of discovered subdomains
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []
        
        try:
            data = resp.json()
        except json.JSONDecodeError:
            return []
        
        found_subs: Set[str] = set()
        
        for entry in data:
            # Extract from name_value (can have multiple per entry)
            if 'name_value' in entry:
                for subd in entry['name_value'].split('\n'):
                    subd_strip = subd.strip()
                    if subd_strip and subd_strip != domain:
                        # Remove wildcard prefix
                        if subd_strip.startswith('*.'):
                            subd_strip = subd_strip[2:]
                        found_subs.add(subd_strip)
            
            # Also check common_name
            elif 'common_name' in entry:
                c = entry['common_name'].strip()
                if c and c != domain:
                    if c.startswith('*.'):
                        c = c[2:]
                    found_subs.add(c)
        
        return sorted(list(found_subs))
        
    except Exception:
        return []


def enumerate_subdomains_hackertarget(domain: str, timeout: int = 30) -> List[str]:
    """
    Enumerate subdomains using HackerTarget API.
    
    Free tier: 100 requests/day.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []
        
        # Response format: "subdomain,ip\nsubdomain2,ip2\n..."
        subdomains = []
        for line in resp.text.strip().split('\n'):
            if ',' in line:
                sub = line.split(',')[0].strip()
                if sub and sub != domain:
                    subdomains.append(sub)
        
        return sorted(list(set(subdomains)))
        
    except Exception:
        return []


def enumerate_subdomains(domain: str) -> List[str]:
    """
    Enumerate subdomains using multiple sources.
    
    Combines:
    - crt.sh (Certificate Transparency)
    - HackerTarget (DNS database)
    
    Returns deduplicated, sorted list.
    """
    all_subs: Set[str] = set()
    
    # Try crt.sh first (usually has most results)
    crt_subs = enumerate_subdomains_crtsh(domain)
    all_subs.update(crt_subs)
    
    # Add from HackerTarget
    ht_subs = enumerate_subdomains_hackertarget(domain)
    all_subs.update(ht_subs)
    
    return sorted(list(all_subs))


def check_subdomain_alive(subdomain: str, timeout: int = 5) -> Optional[str]:
    """
    Check if a subdomain is alive (responds to HTTP/HTTPS).
    
    Returns the working URL or None if not accessible.
    """
    for scheme in ['https', 'http']:
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.head(url, timeout=timeout, allow_redirects=True)
            if resp.status_code < 500:
                return url
        except Exception:
            continue
    return None


def filter_alive_subdomains(subdomains: List[str], timeout: int = 5) -> List[dict]:
    """
    Filter subdomains to only those that are alive.
    
    Returns list of dicts: [{"subdomain": "...", "url": "...", "status": 200}]
    """
    alive = []
    for sub in subdomains:
        url = check_subdomain_alive(sub, timeout)
        if url:
            # Get status code
            try:
                resp = requests.head(url, timeout=timeout, allow_redirects=True)
                status = resp.status_code
            except Exception:
                status = None
            
            alive.append({
                "subdomain": sub,
                "url": url,
                "status": status
            })
    return alive
