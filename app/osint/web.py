"""
SNODE OSINT - Web Functions
============================

SSL certificate checking, robots.txt, sitemap, wayback, contact scraping.
Based on clatscope web-related functions.
"""
import ssl
import socket
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional


def check_ssl_cert(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Get SSL certificate information for a domain.
    
    Same functionality as clatscope's check_ssl_cert.
    
    Returns:
        {
            "domain": domain,
            "issued_to": common name,
            "issued_by": issuer,
            "valid_from": datetime,
            "valid_until": datetime,
            "days_remaining": int,
            "san": [subject alternative names],
            "error": None or error message
        }
    """
    result = {
        "domain": domain,
        "issued_to": None,
        "issued_by": None,
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "san": [],
        "error": None
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        
        # Parse subject
        subject = dict(x[0] for x in cert.get('subject', []))
        result["issued_to"] = subject.get('commonName', 'N/A')
        
        # Parse issuer
        issuer = dict(x[0] for x in cert.get('issuer', []))
        result["issued_by"] = issuer.get('commonName', 'N/A')
        
        # Parse dates
        not_before = cert.get('notBefore', '')
        not_after = cert.get('notAfter', '')
        
        if not_before:
            result["valid_from"] = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        if not_after:
            result["valid_until"] = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            result["days_remaining"] = (result["valid_until"] - datetime.now()).days
        
        # Get Subject Alternative Names
        san = cert.get('subjectAltName', [])
        result["san"] = [name for type_, name in san if type_ == 'DNS']
        
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {str(e)}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except socket.gaierror:
        result["error"] = "Could not resolve hostname"
    except Exception as e:
        result["error"] = str(e)
    
    return result


def check_robots_txt(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Fetch and parse robots.txt for a domain.
    
    Returns:
        {
            "domain": domain,
            "exists": bool,
            "content": raw content,
            "disallow": [disallowed paths],
            "allow": [allowed paths],
            "sitemaps": [sitemap URLs]
        }
    """
    result = {
        "domain": domain,
        "exists": False,
        "content": None,
        "disallow": [],
        "allow": [],
        "sitemaps": []
    }
    
    for scheme in ['https', 'http']:
        url = f"{scheme}://{domain}/robots.txt"
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                result["exists"] = True
                result["content"] = resp.text
                
                # Parse directives
                for line in resp.text.split('\n'):
                    line = line.strip().lower()
                    if line.startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            result["disallow"].append(path)
                    elif line.startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            result["allow"].append(path)
                    elif line.startswith('sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        # Handle "sitemap: http://..." format
                        if sitemap.startswith('//'):
                            sitemap = 'https:' + sitemap
                        result["sitemaps"].append(sitemap)
                
                return result
        except Exception:
            continue
    
    return result


def check_sitemap(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Fetch sitemap.xml and extract URLs.
    
    Returns:
        {
            "domain": domain,
            "exists": bool,
            "urls": [list of URLs from sitemap],
            "count": number of URLs
        }
    """
    result = {
        "domain": domain,
        "exists": False,
        "urls": [],
        "count": 0
    }
    
    import re
    
    for scheme in ['https', 'http']:
        url = f"{scheme}://{domain}/sitemap.xml"
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200 and '<urlset' in resp.text.lower():
                result["exists"] = True
                
                # Extract URLs
                urls = re.findall(r'<loc>([^<]+)</loc>', resp.text)
                result["urls"] = urls[:100]  # Limit to 100
                result["count"] = len(urls)
                return result
        except Exception:
            continue
    
    return result


def wayback_lookup(domain: str, limit: int = 10) -> Dict[str, Any]:
    """
    Check Wayback Machine for archived snapshots.
    
    Returns:
        {
            "domain": domain,
            "available": bool,
            "oldest_snapshot": URL or None,
            "newest_snapshot": URL or None,
            "snapshots": [{timestamp, url}, ...]
        }
    """
    result = {
        "domain": domain,
        "available": False,
        "oldest_snapshot": None,
        "newest_snapshot": None,
        "snapshots": []
    }
    
    # Check availability
    try:
        url = f"https://archive.org/wayback/available?url={domain}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            snapshot = data.get("archived_snapshots", {}).get("closest")
            if snapshot:
                result["available"] = True
                result["newest_snapshot"] = snapshot.get("url")
    except Exception:
        pass
    
    # Get CDX (snapshot history)
    try:
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit={limit}"
        resp = requests.get(cdx_url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:  # First row is header
                result["available"] = True
                for row in data[1:]:
                    if len(row) >= 2:
                        timestamp = row[1]
                        original_url = row[2] if len(row) > 2 else domain
                        wayback_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
                        result["snapshots"].append({
                            "timestamp": timestamp,
                            "url": wayback_url
                        })
                
                if result["snapshots"]:
                    result["oldest_snapshot"] = result["snapshots"][-1]["url"]
                    result["newest_snapshot"] = result["snapshots"][0]["url"]
    except Exception:
        pass
    
    return result


def scrape_contacts(url: str, timeout: int = 15) -> Dict[str, Any]:
    """
    Scrape contact information from a webpage.
    
    Extracts emails, phone numbers, and social links.
    
    Returns:
        {
            "url": url,
            "emails": [...],
            "phones": [...],
            "social_links": {...}
        }
    """
    import re
    
    result = {
        "url": url,
        "emails": [],
        "phones": [],
        "social_links": {}
    }
    
    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        if resp.status_code != 200:
            return result
        
        text = resp.text
        
        # Extract emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        result["emails"] = list(set(emails))
        
        # Extract phone numbers (various formats)
        phones = re.findall(r'[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}', text)
        # Filter out too short/long
        result["phones"] = list(set([p for p in phones if 7 <= len(re.sub(r'\D', '', p)) <= 15]))
        
        # Extract social links
        social_patterns = {
            "twitter": r'(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)',
            "facebook": r'facebook\.com/([a-zA-Z0-9._]+)',
            "linkedin": r'linkedin\.com/(?:in|company)/([a-zA-Z0-9_-]+)',
            "instagram": r'instagram\.com/([a-zA-Z0-9_.]+)',
            "github": r'github\.com/([a-zA-Z0-9_-]+)'
        }
        
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                result["social_links"][platform] = list(set(matches))
        
    except Exception:
        pass
    
    return result


def basic_port_scan(target: str, ports: List[int] = None, timeout: float = 1) -> Dict[str, Any]:
    """
    Simple port scan using socket connections.
    
    Default ports: common web/service ports.
    
    Returns:
        {
            "target": target,
            "open_ports": [port numbers],
            "closed_ports": [port numbers],
            "scan_time": seconds
        }
    """
    import time
    
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
    
    result = {
        "target": target,
        "open_ports": [],
        "closed_ports": [],
        "scan_time": 0
    }
    
    start = time.time()
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            code = sock.connect_ex((target, port))
            sock.close()
            
            if code == 0:
                result["open_ports"].append(port)
            else:
                result["closed_ports"].append(port)
        except Exception:
            result["closed_ports"].append(port)
    
    result["scan_time"] = round(time.time() - start, 2)
    return result
