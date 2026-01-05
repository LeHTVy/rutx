"""
Input/Output Validation for Sandbox Executors
"""
import re
from typing import Tuple, Optional


def validate_target(target: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a scan target (IP, hostname, or domain).
    
    Returns:
        (is_valid, error_message)
    """
    if not target or not isinstance(target, str):
        return False, "Target cannot be empty"
    
    target = target.strip()
    
    # Check for dangerous characters
    dangerous = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>']
    for char in dangerous:
        if char in target:
            return False, f"Invalid character in target: {char}"
    
    # IP address pattern
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # CIDR pattern
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    # Hostname/domain pattern
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    
    if re.match(ip_pattern, target):
        # Validate IP octets
        octets = target.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False, f"Invalid IP octet: {octet}"
        return True, None
    
    if re.match(cidr_pattern, target):
        return True, None
    
    if re.match(domain_pattern, target):
        return True, None
    
    return False, f"Invalid target format: {target}"


def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a domain name.
    
    Returns:
        (is_valid, error_message)
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain cannot be empty"
    
    domain = domain.strip().lower()
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://')[1]
    
    # Remove path if present
    if '/' in domain:
        domain = domain.split('/')[0]
    
    # Domain pattern
    pattern = r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$'
    
    if re.match(pattern, domain):
        return True, None
    
    return False, f"Invalid domain format: {domain}"


def validate_ports(ports: str) -> Tuple[bool, Optional[str]]:
    """
    Validate port specification.
    
    Returns:
        (is_valid, error_message)
    """
    if not ports:
        return True, None  # Empty is OK (use defaults)
    
    # Common formats: "80", "80,443", "1-1000", "top-100"
    ports = ports.strip()
    
    # top-N format
    if ports.startswith("top-"):
        try:
            n = int(ports.split("-")[1])
            if 1 <= n <= 65535:
                return True, None
        except ValueError:
            pass
        return False, f"Invalid top-N format: {ports}"
    
    # Individual ports or ranges
    for part in ports.split(','):
        part = part.strip()
        if '-' in part:
            # Range
            try:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    return False, f"Port out of range: {part}"
                if start > end:
                    return False, f"Invalid port range: {part}"
            except ValueError:
                return False, f"Invalid port range: {part}"
        else:
            # Single port
            try:
                port = int(part)
                if not 1 <= port <= 65535:
                    return False, f"Port out of range: {port}"
            except ValueError:
                return False, f"Invalid port: {part}"
    
    return True, None
