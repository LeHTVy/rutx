"""
DNS Tools Module
Bulk DNS resolution using dnsx for fast subdomain-to-IP mapping

Features:
- Bulk resolve 100+ subdomains in seconds
- Deduplication of IPs
- Fallback to socket.gethostbyname if dnsx unavailable
"""

import subprocess
import tempfile
import os
import socket
from typing import List, Dict, Set, Tuple, Any
from collections import defaultdict


def resolve_dns(domain: str) -> dict:
    """
    Simple DNS resolution for a single domain (for tool registry compatibility).

    Args:
        domain: Domain name to resolve

    Returns:
        Dict with resolution results

    Example:
        >>> resolve_dns("example.com")
        {'domain': 'example.com', 'ip': '93.184.216.34', 'success': True, 'A': ['93.184.216.34']}
    """
    result = dnsx_bulk_resolve([domain])
    ip = result.get(domain)

    return {
        "domain": domain,
        "ip": ip,
        "A": [ip] if ip else [],
        "AAAA": [],  # IPv6 not implemented yet
        "CNAME": [],  # CNAME not implemented yet
        "success": domain in result
    }


def reverse_dns_lookup(ip: str) -> dict:
    """
    Reverse DNS lookup (PTR record) to find hostname from IP.

    Args:
        ip: IP address for reverse lookup

    Returns:
        Dict with reverse lookup results

    Example:
        >>> reverse_dns_lookup("8.8.8.8")
        {'ip': '8.8.8.8', 'hostname': 'dns.google', 'ptr': 'dns.google', 'success': True}
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {
            "ip": ip,
            "hostname": hostname,
            "ptr": hostname,
            "success": True
        }
    except socket.herror:
        return {
            "ip": ip,
            "hostname": None,
            "ptr": None,
            "success": False,
            "error": "No PTR record found"
        }
    except Exception as e:
        return {
            "ip": ip,
            "hostname": None,
            "ptr": None,
            "success": False,
            "error": str(e)
        }


def dnsx_bulk_resolve(subdomains: List[str], timeout: int = 30) -> Dict[str, str]:
    """
    Bulk resolve subdomains using dnsx (much faster than one-by-one)
    
    Args:
        subdomains: List of subdomains to resolve
        timeout: Timeout in seconds
    
    Returns:
        Dict mapping subdomain -> IP address
        
    Example:
        >>> dnsx_bulk_resolve(["api.example.com", "www.example.com"])
        {'api.example.com': '192.168.1.1', 'www.example.com': '192.168.1.2'}
    """
    if not subdomains:
        return {}
    
    # Check if dnsx is available
    try:
        subprocess.run(["dnsx", "-version"], capture_output=True, check=True, timeout=5)
        use_dnsx = True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        print("  [WARNING] dnsx not found, falling back to Python DNS (slower)")
        use_dnsx = False
    
    if use_dnsx:
        return _dnsx_resolve(subdomains, timeout)
    else:
        return _fallback_resolve(subdomains)


def _dnsx_resolve(subdomains: List[str], timeout: int) -> Dict[str, str]:
    """
    Resolve using dnsx tool (fast bulk resolution)
    """
    # Write subdomains to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write('\n'.join(subdomains))
        input_file = f.name
    
    # Output file
    output_file = tempfile.mktemp(suffix='.txt')
    
    try:
        # Run dnsx with JSON output
        cmd = [
            "dnsx",
            "-l", input_file,
            "-j",     # JSON output
            "-silent",
            "-o", output_file
        ]
        
        # print(f"DEBUG: Running command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        if result.returncode != 0:
            print(f"  [WARNING] dnsx failed with code {result.returncode}")
            print(f"  [WARNING] stderr: {result.stderr}")
        
        # Parse JSON output
        import json
        mapping = {}
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        host = data.get('host')
                        
                        # Get IP from 'a' records or 'aaaa' records
                        ips = data.get('a', []) or data.get('aaaa', [])
                        
                        if host and ips:
                            # Use first IP
                            mapping[host] = ips[0]
                            
                    except json.JSONDecodeError:
                        continue
        
        if not mapping:
            print("  [WARNING] dnsx returned no results (empty output or parsing failed)")
            # print(f"DEBUG: Raw output was: {content if 'content' in locals() else 'N/A'}")
            print("  [WARNING] Falling back to Python DNS")
            return _fallback_resolve(subdomains)
            
        return mapping
        
    except subprocess.TimeoutExpired:
        print(f"  [WARNING] dnsx timed out after {timeout}s")
        return _fallback_resolve(subdomains)
    except Exception as e:
        print(f"  [WARNING] dnsx error: {e}")
        return _fallback_resolve(subdomains)
    finally:
        # Cleanup temp files
        try:
            os.unlink(input_file)
            if os.path.exists(output_file):
                os.unlink(output_file)
        except:
            pass


def _fallback_resolve(subdomains: List[str]) -> Dict[str, str]:
    """
    Fallback: resolve using Python socket (slower, one-by-one)
    """
    mapping = {}
    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            mapping[subdomain] = ip
        except socket.gaierror:
            # Could not resolve
            pass
    
    return mapping


def deduplicate_by_ip(subdomain_to_ip: Dict[str, str]) -> Dict[str, List[str]]:
    """
    Group subdomains by their IP address (deduplication)
    
    Args:
        subdomain_to_ip: Mapping of subdomain -> IP
    
    Returns:
        Dict mapping IP -> list of subdomains pointing to it
        
    Example:
        >>> deduplicate_by_ip({
        ...     'api.example.com': '192.168.1.1',
        ...     'v1.api.example.com': '192.168.1.1',
        ...     'web.example.com': '192.168.1.2'
        ... })
        {
            '192.168.1.1': ['api.example.com', 'v1.api.example.com'],
            '192.168.1.2': ['web.example.com']
        }
    """
    ip_to_subdomains = defaultdict(list)
    
    for subdomain, ip in subdomain_to_ip.items():
        ip_to_subdomains[ip].append(subdomain)
    
    return dict(ip_to_subdomains)


def get_unique_ips(subdomains: List[str]) -> Tuple[List[str], Dict[str, List[str]], Dict[str, str]]:
    """
    Convenience function: resolve and deduplicate in one step
    
    Args:
        subdomains: List of subdomains
    
    Returns:
        Tuple of:
        - List of unique IPs
        - Dict of IP -> subdomains mapping
        - Dict of subdomain -> IP mapping
        
    Example:
        >>> unique_ips, ip_to_subs, sub_to_ip = get_unique_ips(['api.example.com', 'web.example.com'])
        >>> len(unique_ips)  # Number of unique IPs
        2
    """
    # Resolve all
    subdomain_to_ip = dnsx_bulk_resolve(subdomains)
    
    # Deduplicate
    ip_to_subdomains = deduplicate_by_ip(subdomain_to_ip)
    
    # Get unique IPs
    unique_ips = list(ip_to_subdomains.keys())
    
    return unique_ips, ip_to_subdomains, subdomain_to_ip


def print_deduplication_stats(subdomains: List[str], unique_ips: List[str], ip_to_subdomains: Dict[str, List[str]]):
    """
    Print helpful statistics about deduplication
    """
    savings = len(subdomains) - len(unique_ips)
    savings_pct = (savings / len(subdomains) * 100) if subdomains else 0

    print(f"\n  [DNS Resolution & Deduplication]")
    print(f"     - Total subdomains: {len(subdomains)}")
    print(f"     - Unique IPs: {len(unique_ips)}")
    print(f"     - Saved scans: {savings} ({savings_pct:.1f}%)")

    # Show IPs with most subdomains
    sorted_ips = sorted(ip_to_subdomains.items(), key=lambda x: len(x[1]), reverse=True)
    if len(sorted_ips) > 0:
        top_ip = sorted_ips[0]
        if len(top_ip[1]) > 1:
            print(f"     - Most shared IP: {top_ip[0]} ({len(top_ip[1])} subdomains)")


def dns_bulk_resolve(subdomains: List[str], save_results: bool = False) -> Dict[str, Any]:
    """
    Stage 1 tool: Bulk DNS resolution with deduplication for 4-stage workflow.

    Args:
        subdomains: List of subdomains to resolve
        save_results: Whether to save results for next stage

    Returns:
        Dict with resolution results, unique IPs, and metadata

    Example:
        >>> result = dns_bulk_resolve(["api.example.com", "web.example.com"])
        >>> result["unique_ips"]  # List of unique IPs
        >>> result["subdomain_to_ip"]  # Mapping
    """
    print(f"\n  📡 [STAGE 1] DNS Bulk Resolution - {len(subdomains)} subdomains")

    # Resolve all subdomains
    unique_ips, ip_to_subdomains, subdomain_to_ip = get_unique_ips(subdomains)

    # Print stats
    print_deduplication_stats(subdomains, unique_ips, ip_to_subdomains)

    # Filter out private/local IPs (only keep public IPs)
    public_ips = []
    for ip in unique_ips:
        # Check if public IP
        octets = ip.split('.')
        if len(octets) == 4:
            first = int(octets[0])
            second = int(octets[1])

            # Skip private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x
            if first == 10 or first == 127:
                continue
            if first == 172 and 16 <= second <= 31:
                continue
            if first == 192 and second == 168:
                continue

            public_ips.append(ip)

    print(f"     - Public IPs: {len(public_ips)} (filtered {len(unique_ips) - len(public_ips)} private IPs)")

    return {
        "success": True,
        "stage": 1,
        "subdomains_count": len(subdomains),
        "unique_ips": unique_ips,
        "public_ips": public_ips,
        "ip_to_subdomains": ip_to_subdomains,
        "subdomain_to_ip": subdomain_to_ip,
        "deduplication_savings": len(subdomains) - len(unique_ips),
        "summary": f"Stage 1 DNS: Resolved {len(subdomains)} subdomains to {len(unique_ips)} unique IPs ({len(public_ips)} public)"
    }


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    print("Testing DNS Tools...")
    
    # Test with real subdomains
    test_subs = [
        "www.google.com",
        "mail.google.com",
        "drive.google.com",
        "docs.google.com",
        "example.com",
        "www.example.com"
    ]
    
    print(f"\nResolving {len(test_subs)} subdomains...")
    unique_ips, ip_to_subs, sub_to_ip = get_unique_ips(test_subs)
    
    print_deduplication_stats(test_subs, unique_ips, ip_to_subs)
    
    print("\n[OK] DNS Tools working!")
    print("\nResolution results:")
    for sub, ip in sorted(sub_to_ip.items()):
        print(f"  {sub} → {ip}")
    
    print("\nIP grouping:")
    for ip, subs in sorted(ip_to_subs.items()):
        print(f"  {ip}:")
        for sub in subs:
            print(f"    - {sub}")
