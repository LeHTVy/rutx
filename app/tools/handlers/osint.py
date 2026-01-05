"""
OSINT Tool Handlers
===================

Handles: shodan, dnsrecon, fierce, theHarvester
"""
from typing import Dict, Any
from app.tools.handlers import register_handler
import subprocess


@register_handler("shodan")
def handle_shodan(action_input: Dict[str, Any], state: Any) -> str:
    """Search Shodan for hosts/services."""
    query = action_input.get("query", "")
    host = action_input.get("host", action_input.get("ip", ""))
    
    if not query and not host:
        return """Error: query or host required. Examples:
  shodan with {"query": "apache country:us"}
  shodan with {"host": "8.8.8.8"}
  shodan with {"query": "port:22 ssh"}
  
Note: Requires SHODAN_API_KEY environment variable or shodan init <key>"""
    
    try:
        if host:
            print(f"  🔍 Shodan lookup: {host}...")
            result = subprocess.run(
                ["shodan", "host", host],
                capture_output=True,
                text=True,
                timeout=30
            )
        else:
            print(f"  🔍 Shodan search: {query}...")
            result = subprocess.run(
                ["shodan", "search", "--limit", "10", query],
                capture_output=True,
                text=True,
                timeout=30
            )
        
        if result.returncode != 0 and "API" in result.stderr:
            return "⚠️ Shodan API key required. Run: shodan init YOUR_API_KEY"
        
        return f"═══ SHODAN ═══\n{result.stdout}\n{result.stderr}"
        
    except FileNotFoundError:
        return "⚠️ shodan not installed. Install: pip install shodan"
    except Exception as e:
        return f"Shodan error: {e}"


@register_handler("dnsrecon")
def handle_dnsrecon(action_input: Dict[str, Any], state: Any) -> str:
    """DNS reconnaissance."""
    domain = action_input.get("domain", "")
    
    if not domain:
        return "Error: domain required. Example: dnsrecon with {\"domain\": \"example.com\"}"
    
    print(f"  🌐 DNSRecon on {domain}...")
    
    try:
        result = subprocess.run(
            ["dnsrecon", "-d", domain],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        return f"═══ DNSRECON: {domain} ═══\n{result.stdout[:4000]}"
        
    except FileNotFoundError:
        return "⚠️ dnsrecon not installed. Install: sudo apt install dnsrecon OR pip install dnsrecon"
    except subprocess.TimeoutExpired:
        return "dnsrecon timed out"
    except Exception as e:
        return f"dnsrecon error: {e}"


@register_handler("fierce")
def handle_fierce(action_input: Dict[str, Any], state: Any) -> str:
    """Fierce DNS brute-force."""
    domain = action_input.get("domain", "")
    
    if not domain:
        return "Error: domain required. Example: fierce with {\"domain\": \"example.com\"}"
    
    print(f"  🔥 Fierce on {domain}...")
    
    try:
        result = subprocess.run(
            ["fierce", "--domain", domain],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        return f"═══ FIERCE: {domain} ═══\n{result.stdout[:4000]}"
        
    except FileNotFoundError:
        return "⚠️ fierce not installed. Install: pip install fierce"
    except subprocess.TimeoutExpired:
        return "fierce timed out"
    except Exception as e:
        return f"fierce error: {e}"


@register_handler("theharvester")
def handle_theharvester(action_input: Dict[str, Any], state: Any) -> str:
    """theHarvester email/domain OSINT."""
    domain = action_input.get("domain", "")
    source = action_input.get("source", "all")
    
    if not domain:
        return """Error: domain required. Examples:
  theharvester with {"domain": "example.com"}
  theharvester with {"domain": "example.com", "source": "google"}
  
Sources: all, google, bing, linkedin, twitter, duckduckgo"""
    
    print(f"  🌾 theHarvester on {domain} (source: {source})...")
    
    try:
        result = subprocess.run(
            ["theHarvester", "-d", domain, "-b", source],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        return f"═══ THEHARVESTER: {domain} ═══\n{result.stdout[:4000]}"
        
    except FileNotFoundError:
        return "⚠️ theHarvester not installed. Install: sudo apt install theharvester OR pip install theHarvester"
    except subprocess.TimeoutExpired:
        return "theHarvester timed out"
    except Exception as e:
        return f"theHarvester error: {e}"
