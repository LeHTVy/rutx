"""
SNODE OSINT - Email Functions
==============================

Email validation, MX lookup, and breach checking.
Based on clatscope email_lookup functionality.
"""
import re
import socket
from typing import Dict, Any, List, Optional


def validate_email_format(email: str) -> bool:
    """
    Validate email format using regex.
    
    Returns True if format is valid.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def get_email_domain(email: str) -> Optional[str]:
    """Extract domain from email address."""
    if '@' in email:
        return email.split('@')[1]
    return None


def lookup_mx_records(domain: str) -> List[Dict[str, Any]]:
    """
    Lookup MX records for a domain.
    
    Returns list of MX records with priority.
    """
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX')
        records = []
        for rdata in answers:
            records.append({
                "priority": rdata.preference,
                "host": str(rdata.exchange).rstrip('.')
            })
        return sorted(records, key=lambda x: x["priority"])
    except Exception:
        return []


def email_lookup(email: str) -> Dict[str, Any]:
    """
    Perform comprehensive email lookup.
    
    Validates format, checks MX records, and determines likely validity.
    Same functionality as clatscope's email_lookup.
    
    Returns:
        {
            "email": email,
            "valid_format": bool,
            "domain": domain,
            "mx_records": [...],
            "likely_valid": bool,
            "smtp_host": primary MX or None
        }
    """
    result = {
        "email": email,
        "valid_format": False,
        "domain": None,
        "mx_records": [],
        "likely_valid": False,
        "smtp_host": None
    }
    
    # Check format
    if not validate_email_format(email):
        return result
    
    result["valid_format"] = True
    result["domain"] = get_email_domain(email)
    
    if not result["domain"]:
        return result
    
    # Lookup MX records
    mx_records = lookup_mx_records(result["domain"])
    result["mx_records"] = mx_records
    
    if mx_records:
        result["likely_valid"] = True
        result["smtp_host"] = mx_records[0]["host"]
    
    return result


def verify_email_smtp(email: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Attempt SMTP verification of email (checks if mailbox exists).
    
    WARNING: This may be blocked by many mail servers.
    Don't abuse - use sparingly.
    
    Returns:
        {
            "email": email,
            "smtp_verified": bool,
            "response": server response or error
        }
    """
    result = {
        "email": email,
        "smtp_verified": False,
        "response": None
    }
    
    domain = get_email_domain(email)
    if not domain:
        result["response"] = "Invalid email format"
        return result
    
    mx_records = lookup_mx_records(domain)
    if not mx_records:
        result["response"] = "No MX records found"
        return result
    
    smtp_host = mx_records[0]["host"]
    
    try:
        import smtplib
        with smtplib.SMTP(smtp_host, 25, timeout=timeout) as smtp:
            smtp.helo("localhost")
            smtp.mail("test@localhost")
            code, message = smtp.rcpt(email)
            
            if code == 250:
                result["smtp_verified"] = True
                result["response"] = "Mailbox exists"
            else:
                result["response"] = message.decode() if isinstance(message, bytes) else str(message)
                
    except Exception as e:
        result["response"] = str(e)
    
    return result


def check_disposable_email(email: str) -> bool:
    """
    Check if email is from a disposable/temporary email provider.
    
    Uses a list of common disposable email domains.
    """
    disposable_domains = {
        "tempmail.com", "throwaway.email", "guerrillamail.com",
        "10minutemail.com", "mailinator.com", "temp-mail.org",
        "fakeinbox.com", "trashmail.com", "maildrop.cc",
        "yopmail.com", "sharklasers.com", "dispostable.com",
        "getnada.com", "tmpmail.net", "tempail.com"
    }
    
    domain = get_email_domain(email)
    if domain:
        return domain.lower() in disposable_domains
    return False


def extract_emails_from_text(text: str) -> List[str]:
    """
    Extract all email addresses from text.
    
    Returns deduplicated list of emails.
    """
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(pattern, text)
    return list(set(emails))


def haveibeenpwned_check(email: str, api_key: str = None) -> Dict[str, Any]:
    """
    Check if email appears in known data breaches.
    
    NOTE: Requires HIBP API key for full results.
    Without API key, only returns partial info.
    
    Args:
        email: Email to check
        api_key: HaveIBeenPwned API key (optional)
        
    Returns:
        {
            "email": email,
            "pwned": bool,
            "breaches": [...] or error message
        }
    """
    import requests
    
    result = {
        "email": email,
        "pwned": False,
        "breaches": []
    }
    
    headers = {
        "User-Agent": "SNODE-OSINT"
    }
    
    if api_key:
        headers["hibp-api-key"] = api_key
    
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            result["pwned"] = True
            result["breaches"] = resp.json()
        elif resp.status_code == 404:
            result["pwned"] = False
        elif resp.status_code == 401:
            result["breaches"] = "API key required for this lookup"
        else:
            result["breaches"] = f"Error: HTTP {resp.status_code}"
            
    except Exception as e:
        result["breaches"] = str(e)
    
    return result
