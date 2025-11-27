"""
Attack Pattern Templates
Pre-defined tool workflows for common penetration testing scenarios

Inspired by HexStrike's attack pattern system
Each pattern defines a sequence of tools with priorities and parameters
"""

from typing import Dict, List, Any

# ============================================================================
# ATTACK PATTERN DEFINITIONS
# ============================================================================
# Priority: Lower number = run first (1 = highest priority)
# Each pattern is a list of steps with recommended tools and parameters

ATTACK_PATTERNS = {
    # ========================================================================
    # WEB APPLICATION TESTING
    # ========================================================================
    "web_reconnaissance": {
        "description": "Comprehensive web application reconnaissance workflow",
        "target_type": "web_application",
        "estimated_time": "15-30 minutes",
        "steps": [
            {
                "step": 1,
                "tool": "nmap_service_detection",
                "priority": 1,
                "description": "Identify web services and versions",
                "params": {"target": "{target}"},
                "why": "Foundation - need to know what services are exposed",
                "success_probability": 0.95
            },
            {
                "step": 2,
                "tool": "bbot_web_scan",
                "priority": 2,
                "description": "Advanced web reconnaissance",
                "params": {"target": "{target}"},
                "why": "Comprehensive web app scanning and endpoint discovery",
                "success_probability": 0.90
            },
            {
                "step": 3,
                "tool": "shodan_search",
                "priority": 3,
                "description": "Gather threat intelligence",
                "params": {"query": "{target}"},
                "why": "Check for known vulnerabilities and exposures",
                "success_probability": 0.80
            },
            # Future steps (when tools are added):
            # {"step": 4, "tool": "nuclei", "priority": 4, "params": {"severity": "critical,high", "tags": "tech"}},
            # {"step": 5, "tool": "gobuster", "priority": 5, "params": {"mode": "dir"}},
        ]
    },
    
    "web_vulnerability_scan": {
        "description": "Find vulnerabilities in web applications",
        "target_type": "web_application",
        "estimated_time": "20-45 minutes",
        "steps": [
            {
                "step": 1,
                "tool": "nmap_service_detection",
                "priority": 1,
                "description": "Identify services first",
                "params": {"target": "{target}"},
                "why": "Need to know what we're scanning before vulnerability testing",
                "success_probability": 0.95
            },
            {
                "step": 2,
                "tool": "nmap_vuln_scan",
                "priority": 2,
                "description": "Check for known CVEs",
                "params": {"target": "{target}"},
                "why": "NSE vuln scripts can find common vulnerabilities",
                "success_probability": 0.85
            },
            {
                "step": 3,
                "tool": "shodan_host",
                "priority": 3,
                "description": "Get vulnerability intelligence",
                "params": {"ip": "{target_ip}"},
                "why": "Shodan often has CVE data for public IPs",
                "success_probability": 0.75
            },
            # Future: nuclei, nikto, sqlmap when added
        ]
    },
    
    # ========================================================================
    # NETWORK SCANNING
    # ========================================================================
    "network_discovery": {
        "description": "Discover hosts and services on a network",
        "target_type": "network_host",
        "estimated_time": "10-20 minutes",
        "steps": [
            {
                "step": 1,
                "tool": "nmap_quick_scan",
                "priority": 1,
                "description": "Fast initial port scan",
                "params": {"target": "{target}"},
                "why": "Quick overview of open ports",
                "success_probability": 0.95
            },
            {
                "step": 2,
                "tool": "nmap_service_detection",
                "priority": 2,
                "description": "Detailed service identification",
                "params": {"target": "{target}"},
                "why": "Identify exact versions for vulnerability research",
                "success_probability": 0.90
            },
            {
                "step": 3,
                "tool": "shodan_lookup",
                "priority": 3,
                "description": "Threat intelligence lookup",
                "params": {"ip": "{target}"},
                "why": "Check if IP is associated with malicious activity",
                "success_probability": 0.85
            },
        ]
    },
    
    "comprehensive_network_scan": {
        "description": "Full network security assessment",
        "target_type": "network_host",
        "estimated_time": "30-60 minutes",
        "steps": [
            {
                "step": 1,
                "tool": "nmap_service_detection",
                "priority": 1,
                "description": "Service and version detection",
                "params": {"target": "{target}"},
                "why": "Foundation for vulnerability assessment",
                "success_probability": 0.95
            },
            {
                "step": 2,
                "tool": "nmap_aggressive_scan",
                "priority": 2,
                "description": "OS detection and aggressive service probing",
                "params": {"target": "{target}"},
                "why": "Get comprehensive host information",
                "success_probability": 0.90
            },
            {
                "step": 3,
                "tool": "nmap_vuln_scan",
                "priority": 3,
                "description": "Vulnerability detection",
                "params": {"target": "{target}"},
                "why": "Check for known vulnerabilities",
                "success_probability": 0.85
            },
            {
                "step": 4,
                "tool": "nmap_comprehensive_scan",
                "priority": 4,
                "description": "All ports + OS + vulns",
                "params": {"target": "{target}"},
                "why": "Complete picture of the target",
                "success_probability": 0.88
            },
        ]
    },
    
    "batch_network_scan": {
        "description": "Fast scanning of multiple targets",
        "target_type": "network_host",
        "estimated_time": "5-15 minutes (depends on target count)",
        "steps": [
            {
                "step": 1,
                "tool": "masscan_batch_scan",
                "priority": 1,
                "description": "Ultra-fast batch port scanning",
                "params": {"targets": "{targets}"},
                "why": "Masscan can scan thousands of hosts quickly",
                "success_probability": 0.92
            },
            {
                "step": 2,
                "tool": "nmap_service_detection",
                "priority": 2,
                "description": "Follow-up service detection on interesting hosts",
                "params": {"target": "{interesting_targets}"},
                "why": "Get detailed info on hosts with open ports",
                "success_probability": 0.88
            },
        ]
    },
    
    # ========================================================================
    # SUBDOMAIN ENUMERATION
    # ========================================================================
    "subdomain_enumeration": {
        "description": "Comprehensive subdomain discovery",
        "target_type": "subdomain_enum",
        "estimated_time": "15-30 minutes",
        "steps": [
            {
                "step": 1,
                "tool": "amass_enum",
                "priority": 1,
                "description": "OWASP Amass subdomain enumeration",
                "params": {"domain": "{domain}", "passive": False},
                "why": "Industry-standard subdomain enumeration",
                "success_probability": 0.90
            },
            {
                "step": 2,
                "tool": "bbot_subdomain_enum",
                "priority": 2,
                "description": "Recursive subdomain scanning",
                "params": {"target": "{domain}", "passive": False},
                "why": "BBOT finds subdomains Amass might miss",
                "success_probability": 0.90
            },
            # Future: subfinder, assetfinder when added
        ]
    },
    
    "fast_subdomain_enum": {
        "description": "Quick subdomain discovery (passive only)",
        "target_type": "subdomain_enum",
        "estimated_time": "5-10 minutes",
        "steps": [
            {
                "step": 1,
                "tool": "amass_enum",
                "priority": 1,
                "description": "Passive Amass enumeration",
                "params": {"domain": "{domain}", "passive": True},
                "why": "Fast passive discovery, no active scanning",
                "success_probability": 0.85
            },
            {
                "step": 2,
                "tool": "bbot_quick_scan",
                "priority": 2,
                "description": "Quick BBOT reconnaissance",
                "params": {"target": "{domain}"},
                "why": "Fast supplementary scanning",
                "success_probability": 0.82
            },
        ]
    },
    
    # ========================================================================
    # API TESTING
    # ========================================================================
    "api_reconnaissance": {
        "description": "Discover and analyze API endpoints",
        "target_type": "api_endpoint",
        "estimated_time": "10-20 minutes",
        "steps": [
            {
                "step": 1,
                "tool": "nmap_service_detection",
                "priority": 1,
                "description": "Identify API services",
                "params": {"target": "{target}"},
                "why": "Find which ports the API is running on",
                "success_probability": 0.85
            },
            {
                "step": 2,
                "tool": "bbot_web_scan",
                "priority": 2,
                "description": "API endpoint discovery",
                "params": {"target": "{target}"},
                "why": "Find API routes and endpoints",
                "success_probability": 0.88
            },
            # Future: httpx, arjun, x8 when added
        ]
    },
    
    # ========================================================================
    # BUG BOUNTY WORKFLOWS
    # ========================================================================
    "bug_bounty_recon": {
        "description": "Bug bounty reconnaissance workflow",
        "target_type": "subdomain_enum",
        "estimated_time": "20-40 minutes",
        "steps": [
            {
                "step": 1,
                "tool": "amass_enum",
                "priority": 1,
                "description": "Comprehensive subdomain enumeration",
                "params": {"domain": "{domain}", "passive": False},
                "why": "Find all subdomains - more attack surface",
                "success_probability": 0.90
            },
            {
                "step": 2,
                "tool": "bbot_subdomain_enum",
                "priority": 2,
                "description": "Recursive subdomain discovery",
                "params": {"target": "{domain}", "passive": False},
                "why": "Find subdomains Amass missed",
                "success_probability": 0.90
            },
            {
                "step": 3,
                "tool": "masscan_batch_scan",
                "priority": 3,
                "description": "Fast port scan all discovered subdomains",
                "params": {"targets": "{discovered_subdomains}"},
                "why": "Identify which subdomains have services",
                "success_probability": 0.88
            },
            {
                "step": 4,
                "tool": "nmap_service_detection",
                "priority": 4,
                "description": "Service detection on interesting targets",
                "params": {"target": "{high_value_targets}"},
                "why": "Deep dive into CRITICAL/HIGH-VALUE targets",
                "success_probability": 0.92
            },
            # Future: httpx, katana, gau, paramspider, nuclei when added
        ]
    },
    
    # ========================================================================
    # OSINT / PASSIVE RECONNAISSANCE
    # ========================================================================
    "passive_recon": {
        "description": "OSINT and passive information gathering",
        "target_type": "osint",
        "estimated_time": "10-15 minutes",
        "steps": [
            {
                "step": 1,
                "tool": "shodan_search",
                "priority": 1,
                "description": "Search Shodan for target",
                "params": {"query": "{target}"},
                "why": "Public vulnerability and exposure data",
                "success_probability": 0.90
            },
            {
                "step": 2,
                "tool": "amass_intel",
                "priority": 2,
                "description": "Passive intelligence gathering",
                "params": {"domain": "{domain}"},
                "why": "WHOIS, ASN, and relationship data",
                "success_probability": 0.85
            },
            {
                "step": 3,
                "tool": "bbot_subdomain_enum",
                "priority": 3,
                "description": "Passive subdomain enumeration",
                "params": {"target": "{domain}", "passive": True},
                "why": "No active scanning, safe for OSINT",
                "success_probability": 0.82
            },
        ]
    },
}

# ============================================================================
# PATTERN METADATA
# ============================================================================

PATTERN_CATEGORIES = {
    "web": ["web_reconnaissance", "web_vulnerability_scan"],
    "network": ["network_discovery", "comprehensive_network_scan", "batch_network_scan"],
    "subdomain": ["subdomain_enumeration", "fast_subdomain_enum"],
    "api": ["api_reconnaissance"],
    "bug_bounty": ["bug_bounty_recon"],
    "osint": ["passive_recon"],
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_pattern(pattern_name: str) -> Dict[str, Any]:
    """
    Get attack pattern by name
    
    Args:
        pattern_name: Name of the pattern
    
    Returns:
        Pattern dictionary or None if not found
    """
    return ATTACK_PATTERNS.get(pattern_name)


def list_patterns(category: str = None) -> List[str]:
    """
    List available attack patterns
    
    Args:
        category: Optional category filter (e.g., "web", "network")
    
    Returns:
        List of pattern names
    """
    if category:
        return PATTERN_CATEGORIES.get(category, [])
    return list(ATTACK_PATTERNS.keys())


def get_pattern_summary(pattern_name: str) -> str:
    """
    Get formatted summary of an attack pattern for prompts
    
    Args:
        pattern_name: Name of the pattern
    
    Returns:
        Formatted string describing the pattern
    """
    pattern = ATTACK_PATTERNS.get(pattern_name)
    if not pattern:
        return f"Pattern '{pattern_name}' not found."
    
    summary = f"**{pattern_name.upper()}**\n"
    summary += f"Description: {pattern['description']}\n"
    summary += f"Target Type: {pattern['target_type']}\n"
    summary += f"Estimated Time: {pattern['estimated_time']}\n\n"
    summary += "Steps:\n"
    
    for step in pattern['steps']:
        summary += f"  {step['step']}. {step['tool']} - {step['description']}\n"
        summary += f"     Why: {step['why']}\n"
        summary += f"     Success: {step['success_probability']*100:.0f}%\n"
    
    return summary


def suggest_pattern(user_input: str, target_type: str = None) -> str:
    """
    Suggest attack pattern based on user input
    
    Args:
        user_input: User's request text
        target_type: Optional pre-detected target type
    
    Returns:
        Suggested pattern name or None
    """
    user_input_lower = user_input.lower()
    
    # Keyword-based pattern detection
    pattern_keywords = {
        "web_reconnaissance": ["web scan", "web recon", "scan website", "scan web"],
        "web_vulnerability_scan": ["find vulnerabilities", "vuln scan", "security issues", "web vuln"],
        "network_discovery": ["scan network", "network scan", "host discovery", "find hosts"],
        "comprehensive_network_scan": ["comprehensive", "full scan", "complete scan", "thorough"],
        "batch_network_scan": ["batch", "multiple targets", "many hosts", "scan list"],
        "subdomain_enumeration": ["subdomain", "enumerate subdomain", "find subdomain"],
        "fast_subdomain_enum": ["quick subdomain", "fast subdomain", "rapid subdomain"],
        "api_reconnaissance": ["api scan", "api recon", "scan api", "test api"],
        "bug_bounty_recon": ["bug bounty", "bounty", "reconnaissance"],
        "passive_recon": ["passive", "osint", "no scan", "information gathering"],
    }
    
    for pattern_name, keywords in pattern_keywords.items():
        for keyword in keywords:
            if keyword in user_input_lower:
                return pattern_name
    
    # Fallback based on target type
    if target_type:
        type_defaults = {
            "web_application": "web_reconnaissance",
            "network_host": "network_discovery",
            "api_endpoint": "api_reconnaissance",
            "subdomain_enum": "subdomain_enumeration",
            "osint": "passive_recon",
        }
        return type_defaults.get(target_type)
    
    return None


def get_all_patterns_summary() -> str:
    """
    Get summary of all attack patterns for LLM prompts
    
    Returns:
        Formatted string listing all patterns
    """
    summary = "AVAILABLE ATTACK PATTERNS:\n\n"
    
    for category, patterns in PATTERN_CATEGORIES.items():
        summary += f"{category.upper()} PATTERNS:\n"
        for pattern_name in patterns:
            pattern = ATTACK_PATTERNS[pattern_name]
            summary += f"  • {pattern_name}: {pattern['description']}\n"
            summary += f"    Time: {pattern['estimated_time']}, Steps: {len(pattern['steps'])}\n"
        summary += "\n"
    
    return summary


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

if __name__ == "__main__":
    # Example 1: Get specific pattern
    pattern = get_pattern("web_reconnaissance")
    print(f"Pattern: {pattern['description']}")
    print(f"Steps: {len(pattern['steps'])}")
    
    # Example 2: List patterns by category
    web_patterns = list_patterns("web")
    print(f"\nWeb patterns: {web_patterns}")
    
    # Example 3: Get pattern summary for prompts
    summary = get_pattern_summary("bug_bounty_recon")
    print(f"\n{summary}")
    
    # Example 4: Suggest pattern based on user input
    user_input = "I want to scan a website for vulnerabilities"
    suggested = suggest_pattern(user_input)
    print(f"\nSuggested pattern: {suggested}")
    
    # Example 5: Get all patterns summary
    all_summary = get_all_patterns_summary()
    print(f"\n{all_summary}")
