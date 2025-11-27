"""
Tool Effectiveness Scoring System
Guides intelligent tool selection based on target type

Inspired by HexStrike's IntelligentDecisionEngine
Adapted for Wireless framework's modular architecture
"""

# ============================================================================
# TOOL EFFECTIVENESS RATINGS (0.0 - 1.0)
# ============================================================================
# Higher score = more effective for that target type
# 0.9-1.0: Excellent (primary tool for this task)
# 0.8-0.9: Very Good (should be considered)
# 0.7-0.8: Good (useful but not primary)
# 0.6-0.7: Moderate (use if specialized features needed)
# <0.6: Limited (rarely use for this target type)

TOOL_EFFECTIVENESS = {
    # ========================================================================
    # WEB APPLICATION TARGETS
    # ========================================================================
    "web_application": {
        # Currently Implemented Tools
        "nmap": 0.80,                      # Good for initial recon
        "nmap_quick_scan": 0.75,           # Fast recon
        "nmap_service_detection": 0.85,    # Service identification
        "nmap_comprehensive_scan": 0.88,   # Full web app scan
        "nmap_vuln_scan": 0.82,            # Vulnerability detection
        "amass_enum": 0.85,                # Subdomain enumeration
        "bbot_subdomain_enum": 0.88,       # Advanced subdomain enum
        "bbot_web_scan": 0.90,             # Web-focused scanning
        "shodan_search": 0.80,             # Threat intelligence
        "masscan_batch_scan": 0.70,        # Batch port scanning (less specific)
        
        # Tools to Add (for reference when implementing)
        "nuclei": 0.95,                    # HIGHEST - Template-based vuln scanning
        "gobuster": 0.90,                  # EXCELLENT - Directory brute-forcing
        "ffuf": 0.90,                      # EXCELLENT - Fast web fuzzing
        "nikto": 0.85,                     # VERY GOOD - Classic web scanner
        "sqlmap": 0.90,                    # EXCELLENT - SQL injection
        "wpscan": 0.95,                    # HIGHEST - WordPress (when detected)
        "feroxbuster": 0.85,               # VERY GOOD - Recursive content discovery
        "dirsearch": 0.87,                 # VERY GOOD - Path scanner
        "katana": 0.88,                    # VERY GOOD - Web crawler
        "httpx": 0.85,                     # VERY GOOD - HTTP toolkit
        "dalfox": 0.93,                    # HIGHEST - XSS detection
    },
    
    # ========================================================================
    # NETWORK HOST TARGETS
    # ========================================================================
    "network_host": {
        # Currently Implemented Tools
        "nmap": 0.95,                      # HIGHEST - Primary network scanner
        "nmap_quick_scan": 0.85,           # Fast initial scan
        "nmap_service_detection": 0.95,    # Service/version detection
        "nmap_comprehensive_scan": 0.97,   # Full network scan
        "nmap_aggressive_scan": 0.95,      # OS/service detection
        "nmap_stealth_scan": 0.90,         # SYN stealth scan
        "nmap_all_ports": 0.92,            # All 65535 ports
        "masscan_batch_scan": 0.92,        # EXCELLENT - Fast batch scanning
        "masscan_quick_scan": 0.88,        # Fast scanning
        "shodan_lookup": 0.85,             # Threat intelligence for IPs
        "amass_enum": 0.70,                # Moderate (better for domains)
        "bbot_subdomain_enum": 0.65,       # Limited (domain-focused)
        
        # Tools to Add
        "rustscan": 0.90,                  # Ultra-fast port scanner
        "autorecon": 0.95,                 # Comprehensive automated recon
        "enum4linux": 0.80,                # SMB enumeration
        "enum4linux-ng": 0.88,             # Enhanced SMB enumeration
        "smbmap": 0.85,                    # SMB share enumeration
        "rpcclient": 0.82,                 # Windows RPC enumeration
        "nbtscan": 0.75,                   # NetBIOS scanning
        "arp-scan": 0.85,                  # Local network discovery
        "responder": 0.88,                 # Credential harvesting
        "hydra": 0.80,                     # Network login cracking
    },
    
    # ========================================================================
    # API ENDPOINT TARGETS
    # ========================================================================
    "api_endpoint": {
        # Currently Implemented Tools
        "nmap_service_detection": 0.75,    # Basic service detection
        "bbot_web_scan": 0.80,             # Web/API scanning
        "shodan_search": 0.70,             # Limited for APIs
        
        # Tools to Add (HIGH PRIORITY for API testing)
        "nuclei": 0.90,                    # Template-based vuln scanning
        "arjun": 0.95,                     # HIGHEST - API parameter discovery
        "x8": 0.92,                        # EXCELLENT - Hidden parameters
        "paramspider": 0.88,               # Parameter mining
        "httpx": 0.90,                     # API probing
        "ffuf": 0.85,                      # API fuzzing
        "katana": 0.85,                    # API endpoint discovery
        "jaeles": 0.88,                    # API testing workflow
    },
    
    # ========================================================================
    # SUBDOMAIN ENUMERATION (Special Category)
    # ========================================================================
    "subdomain_enum": {
        # Currently Implemented Tools
        "amass_enum": 0.90,                # EXCELLENT - OWASP standard
        "amass_intel": 0.85,               # Intel gathering
        "bbot_subdomain_enum": 0.90,       # EXCELLENT - Recursive scanning
        "bbot_quick_scan": 0.82,           # Quick reconnaissance
        "shodan_search": 0.75,             # Supplementary OSINT
        
        # Tools to Add
        "subfinder": 0.88,                 # Fast passive enumeration
        "assetfinder": 0.82,               # Subdomain discovery
        "github-search": 0.75,             # GitHub leaked credentials
        "waybackurls": 0.80,               # Historical URLs
    },
    
    # ========================================================================
    # OSINT / THREAT INTELLIGENCE
    # ========================================================================
    "osint": {
        # Currently Implemented Tools
        "shodan_lookup": 0.95,             # HIGHEST - Primary OSINT for IPs
        "shodan_search": 0.90,             # Query-based intelligence
        "shodan_host": 0.95,               # Host intelligence
        "amass_intel": 0.85,               # Intelligence gathering
        "bbot_subdomain_enum": 0.80,       # Passive recon
        
        # Tools to Add
        "waybackurls": 0.80,               # Historical data
        "gau": 0.82,                       # Get All URLs
        "github-search": 0.75,             # GitHub reconnaissance
        "trufflehog": 0.80,                # Secret scanning
        "gitleaks": 0.82,                  # Git secret scanner
    },
    
    # ========================================================================
    # VULNERABILITY SCANNING
    # ========================================================================
    "vulnerability_scan": {
        # Currently Implemented Tools
        "nmap_vuln_scan": 0.90,            # EXCELLENT - NSE vuln scripts
        "nmap_comprehensive_scan": 0.88,   # Full scanning with vulns
        "shodan_host": 0.85,               # Known CVEs from Shodan
        
        # Tools to Add (HIGH PRIORITY)
        "nuclei": 0.95,                    # HIGHEST - 5000+ templates
        "nikto": 0.85,                     # Classic web vuln scanner
        "jaeles": 0.92,                    # Workflow-based scanning
        "sqlmap": 0.90,                    # SQL injection
        "dalfox": 0.93,                    # XSS detection
        "wpscan": 0.95,                    # WordPress vulns (when applicable)
    },
}

# ============================================================================
# TARGET TYPE DETECTION KEYWORDS
# ============================================================================
# Used to automatically detect target type from user input

TARGET_TYPE_KEYWORDS = {
    "web_application": [
        "website", "web app", "web application", "http", "https", 
        "portal", "dashboard", "admin panel", "web", "site",
        "wordpress", "joomla", "drupal", "cms"
    ],
    "network_host": [
        "server", "host", "machine", "ip address", "network", 
        "router", "firewall", "gateway", "device", "system",
        "windows", "linux", "dc01", "prod"
    ],
    "api_endpoint": [
        "api", "rest api", "graphql", "endpoint", "api endpoint",
        "web service", "microservice", "rest", "soap", "json api"
    ],
    "subdomain_enum": [
        "subdomain", "subdomains", "enumerate subdomains", "find subdomains",
        "subdomain enumeration", "dns enumeration", "discover subdomains"
    ],
    "osint": [
        "osint", "intelligence", "reconnaissance", "recon", "threat intel",
        "passive scan", "information gathering", "footprint"
    ],
    "vulnerability_scan": [
        "vulnerability", "vulnerabilities", "vuln", "cve", "exploit",
        "security issues", "weaknesses", "find vulnerabilities"
    ]
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_tool_effectiveness(tool_name: str, target_type: str) -> float:
    """
    Get effectiveness score for a tool on a specific target type
    
    Args:
        tool_name: Name of the tool (e.g., "nmap", "nuclei")
        target_type: Target category (e.g., "web_application", "network_host")
    
    Returns:
        Effectiveness score (0.0-1.0) or 0.5 if not found
    """
    if target_type not in TOOL_EFFECTIVENESS:
        return 0.5  # Default moderate effectiveness
    
    return TOOL_EFFECTIVENESS[target_type].get(tool_name, 0.5)


def get_best_tools(target_type: str, min_score: float = 0.8, limit: int = 5):
    """
    Get top-rated tools for a target type
    
    Args:
        target_type: Target category
        min_score: Minimum effectiveness score (default: 0.8)
        limit: Maximum number of tools to return
    
    Returns:
        List of (tool_name, score) tuples, sorted by score (descending)
    """
    if target_type not in TOOL_EFFECTIVENESS:
        return []
    
    tools = TOOL_EFFECTIVENESS[target_type]
    
    # Filter by minimum score and sort
    top_tools = [
        (tool, score) 
        for tool, score in tools.items() 
        if score >= min_score
    ]
    
    # Sort by score (descending)
    top_tools.sort(key=lambda x: x[1], reverse=True)
    
    return top_tools[:limit]


def detect_target_type(user_input: str) -> str:
    """
    Auto-detect target type from user input
    
    Args:
        user_input: User's request text
    
    Returns:
        Detected target type or "web_application" as default
    """
    user_input_lower = user_input.lower()
    
    # Check each target type's keywords
    for target_type, keywords in TARGET_TYPE_KEYWORDS.items():
        for keyword in keywords:
            if keyword in user_input_lower:
                return target_type
    
    # Check if input is an IP address → network_host
    import re
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', user_input.strip()):
        return "network_host"
    
    # Check if input has domain pattern → web_application  
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}', user_input.strip()):
        return "web_application"
    
    # Default to web_application
    return "web_application"


def get_effectiveness_summary(target_type: str) -> str:
    """
    Get formatted summary of tool effectiveness for prompts
    
    Args:
        target_type: Target category
    
    Returns:
        Formatted string for inclusion in LLM prompts
    """
    if target_type not in TOOL_EFFECTIVENESS:
        return "No effectiveness data available for this target type."
    
    tools = TOOL_EFFECTIVENESS[target_type]
    
    # Group by effectiveness category
    excellent = [(t, s) for t, s in tools.items() if s >= 0.9]
    very_good = [(t, s) for t, s in tools.items() if 0.8 <= s < 0.9]
    good = [(t, s) for t, s in tools.items() if 0.7 <= s < 0.8]
    
    # Sort each group by score
    excellent.sort(key=lambda x: x[1], reverse=True)
    very_good.sort(key=lambda x: x[1], reverse=True)
    good.sort(key=lambda x: x[1], reverse=True)
    
    summary = f"Tool Effectiveness for '{target_type}':\n\n"
    
    if excellent:
        summary += "EXCELLENT (0.9-1.0) - Primary tools:\n"
        for tool, score in excellent:
            summary += f"  • {tool}: {score:.2f}\n"
        summary += "\n"
    
    if very_good:
        summary += "VERY GOOD (0.8-0.9) - Should consider:\n"
        for tool, score in very_good:
            summary += f"  • {tool}: {score:.2f}\n"
        summary += "\n"
    
    if good:
        summary += "GOOD (0.7-0.8) - Useful:\n"
        for tool, score in good:
            summary += f"  • {tool}: {score:.2f}\n"
    
    return summary.strip()


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

if __name__ == "__main__":
    # Example 1: Get effectiveness for specific tool/target
    score = get_tool_effectiveness("nuclei", "web_application")
    print(f"Nuclei effectiveness for web apps: {score}")
    
    # Example 2: Get best tools for target type
    best_tools = get_best_tools("api_endpoint", min_score=0.85, limit=3)
    print(f"\nTop 3 tools for APIs:")
    for tool, score in best_tools:
        print(f"  {tool}: {score}")
    
    # Example 3: Auto-detect target type
    user_input = "scan api.example.com for vulnerabilities"
    target_type = detect_target_type(user_input)
    print(f"\nDetected target type: {target_type}")
    
    # Example 4: Get effectiveness summary for prompts
    summary = get_effectiveness_summary("web_application")
    print(f"\n{summary}")
