"""
ClatScope OSINT Integration for SNODE

Wrapper module that provides clean access to ClatScope's OSINT functions.
"""
import sys
import os
from pathlib import Path

# Add clatscope to path
CLATSCOPE_DIR = Path(__file__).parent.parent.parent / "clatscope"
sys.path.insert(0, str(CLATSCOPE_DIR))

# Disable pystyle console output (interactive mode)
os.environ['PYSTYLE_NO_ANIMATION'] = '1'

class ClatScopeOSINT:
    """OSINT wrapper for ClatScope functions."""
    
    def __init__(self, config: dict = None):
        """
        Initialize ClatScope OSINT.
        
        Args:
            config: Dict with API keys:
                - hibp_api_key: Have I Been Pwned API key
                - hunter_api_key: Hunter.io API key
                - virustotal_api_key: VirusTotal API key
        """
        self.config = config or {}
        self._clatscope = None
        self._load_clatscope()
    
    def _load_clatscope(self):
        """Load ClatScope functions."""
        try:
            # Import individual functions from ClatScope
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "clatscope",
                CLATSCOPE_DIR / "ClatScope Info Tool (1.21).py"
            )
            self._clatscope = importlib.util.module_from_spec(spec)
            
            # Don't execute main, just load functions
            # We'll call functions directly
        except Exception as e:
            print(f"⚠️ ClatScope load error: {e}")
    
    # ========== Core OSINT Functions ==========
    
    def ip_lookup(self, ip: str) -> dict:
        """Get IP geolocation, ISP, and details."""
        try:
            import requests
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "ip": ip,
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "region": data.get("regionName"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone"),
                }
            return {"error": "Lookup failed"}
        except Exception as e:
            return {"error": str(e)}
    
    def dns_lookup(self, domain: str) -> dict:
        """Get DNS records (A, CNAME, MX, NS)."""
        try:
            import dns.resolver
            results = {"domain": domain, "records": {}}
            
            for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    results["records"][record_type] = [str(r) for r in answers]
                except:
                    pass
            
            return results
        except Exception as e:
            return {"error": str(e)}
    
    def whois_lookup(self, domain: str) -> dict:
        """Get WHOIS registration info."""
        try:
            import whois
            w = whois.whois(domain)
            return {
                "domain": domain,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "org": w.org,
                "country": w.country,
            }
        except Exception as e:
            return {"error": str(e)}
    
    def subdomain_enum(self, domain: str) -> dict:
        """Find subdomains using certificate transparency."""
        try:
            import requests
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        if sub and not sub.startswith("*"):
                            subdomains.add(sub.strip())
                return {
                    "domain": domain,
                    "subdomains": sorted(list(subdomains)),
                    "count": len(subdomains)
                }
            return {"error": "crt.sh lookup failed"}
        except Exception as e:
            return {"error": str(e)}
    
    def ssl_cert(self, domain: str) -> dict:
        """Get SSL certificate details."""
        try:
            import ssl
            import socket
            from datetime import datetime
            
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "domain": domain,
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serial": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": cert.get("subjectAltName"),
                    }
        except Exception as e:
            return {"error": str(e)}
    
    def web_metadata(self, url: str) -> dict:
        """Extract web page metadata."""
        try:
            import requests
            from bs4 import BeautifulSoup
            
            if not url.startswith("http"):
                url = f"https://{url}"
            
            response = requests.get(url, timeout=15, headers={
                "User-Agent": "Mozilla/5.0 (OSINT Scanner)"
            })
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extract meta tags
            meta = {}
            for tag in soup.find_all("meta"):
                name = tag.get("name") or tag.get("property")
                if name:
                    meta[name] = tag.get("content")
            
            return {
                "url": url,
                "title": soup.title.string if soup.title else None,
                "meta": meta,
                "status_code": response.status_code,
                "server": response.headers.get("Server"),
                "content_type": response.headers.get("Content-Type"),
            }
        except Exception as e:
            return {"error": str(e)}
    
    def robots_sitemap(self, domain: str) -> dict:
        """Get robots.txt and sitemap.xml."""
        try:
            import requests
            
            results = {"domain": domain}
            
            # Check robots.txt
            try:
                r = requests.get(f"https://{domain}/robots.txt", timeout=10)
                if r.status_code == 200:
                    results["robots_txt"] = r.text[:2000]
            except:
                pass
            
            # Check sitemap.xml
            try:
                r = requests.get(f"https://{domain}/sitemap.xml", timeout=10)
                if r.status_code == 200:
                    results["sitemap"] = "Found" if "</urlset>" in r.text else "Partial"
                    results["sitemap_size"] = len(r.text)
            except:
                pass
            
            return results
        except Exception as e:
            return {"error": str(e)}
    
    def phone_lookup(self, phone: str) -> dict:
        """Parse and lookup phone number."""
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone
            
            parsed = phonenumbers.parse(phone)
            
            return {
                "phone": phone,
                "valid": phonenumbers.is_valid_number(parsed),
                "country": geocoder.description_for_number(parsed, "en"),
                "carrier": carrier.name_for_number(parsed, "en"),
                "timezone": list(timezone.time_zones_for_number(parsed)),
                "type": str(phonenumbers.number_type(parsed)),
                "formatted": phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                ),
            }
        except Exception as e:
            return {"error": str(e)}
    
    def email_validate(self, email: str) -> dict:
        """Validate email address."""
        try:
            from email_validator import validate_email, EmailNotValidError
            
            valid = validate_email(email)
            return {
                "email": email,
                "valid": True,
                "normalized": valid.normalized,
                "local_part": valid.local_part,
                "domain": valid.domain,
            }
        except EmailNotValidError as e:
            return {"email": email, "valid": False, "error": str(e)}
        except Exception as e:
            return {"error": str(e)}
    
    def reverse_dns(self, ip: str) -> dict:
        """Reverse DNS lookup."""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return {"ip": ip, "hostname": hostname}
        except Exception as e:
            return {"ip": ip, "hostname": None, "error": str(e)}
    
    def find_origin(self, domain: str) -> dict:
        """
        Find real origin IP behind CDN/WAF.
        Combines multiple techniques: DNS, MX, SSL SANs, historical hints.
        """
        import socket
        import requests
        
        results = {
            "domain": domain,
            "potential_origins": [],
            "techniques_used": [],
            "cdn_detected": None
        }
        
        # 1. Direct DNS resolution (might be CDN IP)
        try:
            cdn_ip = socket.gethostbyname(domain)
            results["current_ip"] = cdn_ip
            
            # Check if it's a known CDN IP range
            ip_info = self.ip_lookup(cdn_ip)
            org = (ip_info.get("org") or "").lower()
            isp = (ip_info.get("isp") or "").lower()
            
            if any(cdn in org or cdn in isp for cdn in ["cloudflare", "akamai", "fastly", "incapsula", "sucuri"]):
                results["cdn_detected"] = ip_info.get("org")
        except:
            pass
        
        # 2. Check MX records (often not behind CDN)
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, "MX")
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip(".")
                try:
                    mx_ip = socket.gethostbyname(mx_host)
                    # Check if MX IP is different from CDN
                    if mx_ip != results.get("current_ip"):
                        results["potential_origins"].append({
                            "ip": mx_ip,
                            "source": "MX record",
                            "hostname": mx_host
                        })
                        results["techniques_used"].append("MX record analysis")
                except:
                    pass
        except:
            pass
        
        # 3. Check SSL certificate SANs for other domains/IPs
        try:
            ssl_info = self.ssl_cert(domain)
            if ssl_info.get("san"):
                for san_type, san_value in ssl_info["san"]:
                    if san_type == "IP Address":
                        results["potential_origins"].append({
                            "ip": san_value,
                            "source": "SSL SAN IP"
                        })
                        results["techniques_used"].append("SSL SAN analysis")
        except:
            pass
        
        # 4. Check common subdomains that bypass CDN
        bypass_subdomains = ["direct", "origin", "backend", "server", "mail", "ftp", "cpanel", "whm", "webmail"]
        for sub in bypass_subdomains:
            try:
                test_domain = f"{sub}.{domain}"
                sub_ip = socket.gethostbyname(test_domain)
                if sub_ip != results.get("current_ip"):
                    results["potential_origins"].append({
                        "ip": sub_ip,
                        "source": f"Subdomain: {test_domain}"
                    })
                    results["techniques_used"].append("Subdomain enumeration")
                    break  # Found one, likely the origin
            except:
                continue
        
        # 5. Check SecurityTrails-style historical DNS (via public API if available)
        try:
            # Use viewdns.info as free alternative
            response = requests.get(
                f"https://viewdns.info/iphistory/?domain={domain}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10
            )
            if response.status_code == 200 and "IP History" in response.text:
                results["techniques_used"].append("DNS history check (manual review needed)")
                results["dns_history_url"] = f"https://viewdns.info/iphistory/?domain={domain}"
        except:
            pass
        
        # Deduplicate potential origins
        seen_ips = set()
        unique_origins = []
        for origin in results["potential_origins"]:
            if origin["ip"] not in seen_ips:
                seen_ips.add(origin["ip"])
                unique_origins.append(origin)
        results["potential_origins"] = unique_origins
        
        return results
    
    def email_breach(self, email: str, api_key: str = None) -> dict:
        """Check Have I Been Pwned for breaches."""
        api_key = api_key or self.config.get("hibp_api_key")
        if not api_key:
            return {"error": "HIBP API key required"}
        
        try:
            import requests
            
            headers = {
                "hibp-api-key": api_key,
                "User-Agent": "SNODE-OSINT"
            }
            
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                return {
                    "email": email,
                    "breached": True,
                    "breach_count": len(breaches),
                    "breaches": [b.get("Name") for b in breaches[:10]]
                }
            elif response.status_code == 404:
                return {"email": email, "breached": False}
            else:
                return {"error": f"HIBP returned {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}


# Singleton instance
_osint_instance = None

def get_osint(config: dict = None) -> ClatScopeOSINT:
    """Get or create OSINT instance."""
    global _osint_instance
    if _osint_instance is None:
        _osint_instance = ClatScopeOSINT(config)
    return _osint_instance
