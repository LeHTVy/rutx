"""
OSINT Intelligence Gathering System
Makes LLM understand target context like a human pentester

Workflow:
1. Pre-scan OSINT (Google, Shodan, LinkedIn, GitHub, etc.)
2. LLM analyzes OSINT to identify "crown jewels"
3. Prioritize targets based on business intelligence
4. Comprehensive scans on high-value assets
"""

from typing import Dict, List, Any, Set
import re

# ============================================================================
# OSINT DATA SOURCES
# ============================================================================

OSINT_INDICATORS = {
    # Keywords that indicate high-value/core products
    "core_product_keywords": [
        "flagship", "core product", "main product", "primary solution",
        "leading", "award-winning", "patented", "proprietary",
        "revenue-generating", "enterprise", "mission-critical"
    ],
    
    # Technology stack indicators
    "tech_stack_keywords": {
        "authentication": ["auth", "sso", "login", "oauth", "saml", "identity"],
        "payment": ["payment", "billing", "checkout", "stripe", "paypal", "transaction"],
        "database": ["db", "database", "mysql", "postgres", "mongo", "redis", "data"],
        "api": ["api", "rest", "graphql", "endpoint", "service", "microservice"],
        "admin": ["admin", "management", "console", "dashboard", "control"],
        "analytics": ["analytics", "metrics", "tracking", "telemetry", "stats"],
    },
    
    # Business intelligence keywords
    "business_keywords": {
        "high_value": ["customer", "client", "enterprise", "premium", "pro", "business"],
        "revenue": ["payment", "subscription", "billing", "checkout", "commerce"],
        "critical": ["critical", "essential", "vital", "important", "key"],
        "security": ["secure", "encrypted", "protected", "certified", "compliant"],
    }
}

# ============================================================================
# OSINT INTELLIGENCE ANALYZER
# ============================================================================

class OSINTIntelligenceAnalyzer:
    """
    Analyzes OSINT data to identify crown jewels and prioritize targets
    
    Mimics human pentester's intelligence gathering process
    """
    
    def __init__(self):
        self.crown_jewels = set()
        self.high_value_targets = set()
        self.tech_context = {}
        self.business_context = {}
    
    def analyze_target_intelligence(
        self,
        domain: str,
        subdomains: List[str],
        shodan_data: Dict = None,
        web_content: Dict = None
    ) -> Dict[str, Any]:
        """
        Analyze all OSINT sources to identify crown jewels
        
        Args:
            domain: Main domain (e.g., "snode.com")
            subdomains: List of discovered subdomains
            shodan_data: Shodan intelligence (optional)
            web_content: Scraped web content from main domain (optional)
        
        Returns:
            Intelligence report with prioritized targets
        """
        intelligence = {
            "crown_jewels": [],      # Absolutely critical (top 5%)
            "high_value": [],        # Very important (top 20%)
            "medium_value": [],      # Worth attention (top 50%)
            "low_value": [],         # Standard targets
            "tech_stack": {},
            "business_context": "",
            "recommended_scan_strategy": {}
        }
        
        # Step 1: Extract business context from web content
        if web_content:
            business_info = self._extract_business_context(web_content)
            intelligence["business_context"] = business_info
        
        # Step 2: Analyze subdomain names for intelligence
        for subdomain in subdomains:
            priority = self._calculate_subdomain_priority(
                subdomain,
                domain,
                shodan_data,
                web_content
            )
            
            if priority["score"] >= 9:  # Crown jewel
                intelligence["crown_jewels"].append({
                    "subdomain": subdomain,
                    "score": priority["score"],
                    "reasons": priority["reasons"],
                    "risk_level": "CRITICAL"
                })
            elif priority["score"] >= 7:  # High value
                intelligence["high_value"].append({
                    "subdomain": subdomain,
                    "score": priority["score"],
                    "reasons": priority["reasons"],
                    "risk_level": "HIGH"
                })
            elif priority["score"] >= 5:  # Medium value
                intelligence["medium_value"].append({
                    "subdomain": subdomain,
                    "score": priority["score"],
                    "reasons": priority["reasons"],
                    "risk_level": "MEDIUM"
                })
            else:  # Low value
                intelligence["low_value"].append({
                    "subdomain": subdomain,
                    "score": priority["score"],
                    "reasons": priority["reasons"],
                    "risk_level": "LOW"
                })
        
        # Step 3: Generate scan strategy
        intelligence["recommended_scan_strategy"] = self._generate_scan_strategy(intelligence)
        
        return intelligence
    
    def _extract_business_context(self, web_content: Dict) -> str:
        """
        Extract business intelligence from web content
        
        Looks for:
        - Company description
        - Core products mentioned
        - Technology stack
        - Key features
        """
        context_parts = []
        
        # Example: Parse homepage, about page, products page
        homepage = web_content.get("homepage", "")
        about = web_content.get("about", "")
        
        # Look for core product mentions
        for keyword in OSINT_INDICATORS["core_product_keywords"]:
            if keyword in homepage.lower() or keyword in about.lower():
                # Extract sentence containing keyword
                sentences = re.split(r'[.!?]', homepage + " " + about)
                for sentence in sentences:
                    if keyword in sentence.lower():
                        context_parts.append(sentence.strip())
                        break
        
        return " ".join(context_parts[:5])  # Top 5 relevant sentences
    
    def _calculate_subdomain_priority(
        self,
        subdomain: str,
        domain: str,
        shodan_data: Dict = None,
        web_content: Dict = None
    ) -> Dict[str, Any]:
        """
        Calculate priority score for a subdomain (0-10)
        
        Factors:
        - Subdomain name (admin, api, payment = high)
        - Mentioned in web content as core product
        - Shodan intelligence (critical ports, CVEs)
        - Technology stack indicators
        """
        score = 0
        reasons = []
        
        subdomain_name = subdomain.split('.')[0].lower()
        
        # Factor 1: Subdomain name analysis (0-4 points)
        name_score, name_reasons = self._score_subdomain_name(subdomain_name)
        score += name_score
        reasons.extend(name_reasons)
        
        # Factor 2: Business context mention (0-3 points)
        if web_content:
            mention_score, mention_reasons = self._score_business_mention(
                subdomain_name,
                web_content
            )
            score += mention_score
            reasons.extend(mention_reasons)
        
        # Factor 3: Shodan intelligence (0-3 points)
        if shodan_data:
            shodan_score, shodan_reasons = self._score_shodan_data(subdomain, shodan_data)
            score += shodan_score
            reasons.extend(shodan_reasons)
        
        return {
            "score": min(score, 10),  # Cap at 10
            "reasons": reasons
        }
    
    def _score_subdomain_name(self, name: str) -> tuple:
        """Score based on subdomain name"""
        score = 0
        reasons = []
        
        # CRITICAL keywords (4 points)
        critical = ["api", "admin", "payment", "auth", "sso", "oauth"]
        if any(kw in name for kw in critical):
            score += 4
            reasons.append(f"Critical subdomain name: {name}")
        
        # HIGH VALUE keywords (3 points)  
        elif any(kw in name for kw in ["dashboard", "portal", "console", "manage"]):
            score += 3
            reasons.append(f"High-value subdomain: {name}")
        
        # MEDIUM keywords (2 points)
        elif any(kw in name for kw in ["dev", "staging", "test", "internal"]):
            score += 2
            reasons.append(f"Development/internal subdomain: {name}")
        
        # STANDARD keywords (1 point)
        elif any(kw in name for kw in ["mail", "www", "blog", "docs"]):
            score += 1
            reasons.append(f"Standard subdomain: {name}")
        
        return score, reasons
    
    def _score_business_mention(self, subdomain_name: str, web_content: Dict) -> tuple:
        """Score based on business context mentions"""
        score = 0
        reasons = []
        
        homepage = web_content.get("homepage", "").lower()
        
        # Check if subdomain name is mentioned prominently
        for keyword in OSINT_INDICATORS["core_product_keywords"]:
            if keyword in homepage and subdomain_name in homepage:
                # Check if they appear near each other (within 50 chars)
                if abs(homepage.find(keyword) - homepage.find(subdomain_name)) < 50:
                    score += 3
                    reasons.append(f"Core product mention: '{subdomain_name}' appears with '{keyword}'")
                    break
        
        # Check if mentioned multiple times (indicates importance)
        mention_count = homepage.count(subdomain_name)
        if mention_count >= 5:
            score += 2
            reasons.append(f"Frequently mentioned ({mention_count} times)")
        elif mention_count >= 2:
            score += 1
            reasons.append(f"Mentioned {mention_count} times")
        
        return score, reasons
    
    def _score_shodan_data(self, subdomain: str, shodan_data: Dict) -> tuple:
        """Score based on Shodan intelligence"""
        score = 0
        reasons = []
        
        # Get Shodan data for this subdomain
        host_data = shodan_data.get(subdomain, {})
        
        # Critical ports exposed (3 points)
        critical_ports = [3389, 445, 3306, 5432, 1433, 27017]  # RDP, SMB, databases
        exposed_critical = [p for p in critical_ports if p in host_data.get("ports", [])]
        if exposed_critical:
            score += 3
            reasons.append(f"Critical ports exposed: {exposed_critical}")
        
        # Known CVEs (2 points)
        if host_data.get("CVEs"):
            score += 2
            reasons.append(f"Known CVEs: {len(host_data.get('CVEs', []))}")
        
        # Multiple services (1 point - complex target)
        if len(host_data.get("ports", [])) >= 5:
            score += 1
            reasons.append(f"Multiple services: {len(host_data.get('ports', []))} ports")
        
        return score, reasons
    
    def _generate_scan_strategy(self, intelligence: Dict) -> Dict[str, Any]:
        """
        Generate intelligent scan strategy based on intelligence
        
        Returns recommended scanning approach for each priority level
        """
        return {
            "crown_jewels": {
                "scan_type": "COMPREHENSIVE",
                "tools": [
                    "nmap_comprehensive_scan",  # All 65535 ports
                    "nmap_vuln_scan",           # Vulnerability scripts
                    "nmap_aggressive_scan",      # OS detection
                    "shodan_lookup",            # Threat intelligence
                    "nuclei",                   # When added: web vuln scanning
                ],
                "priority": 1,
                "estimated_time": "30-60 minutes per target",
                "rationale": "Critical assets require thorough analysis"
            },
            "high_value": {
                "scan_type": "DETAILED",
                "tools": [
                    "nmap_service_detection",   # Top 1000 ports + versions
                    "nmap_vuln_scan",           # Vulnerability check
                    "shodan_lookup",            # Threat intel
                ],
                "priority": 2,
                "estimated_time": "15-30 minutes per target",
                "rationale": "Important targets need detailed scanning"
            },
            "medium_value": {
                "scan_type": "STANDARD",
                "tools": [
                    "nmap_service_detection",   # Top 1000 ports
                ],
                "priority": 3,
                "estimated_time": "10-15 minutes per target",
                "rationale": "Standard reconnaissance"
            },
            "low_value": {
                "scan_type": "QUICK",
                "tools": [
                    "masscan_batch_scan",       # Fast batch scanning
                    "nmap_quick_scan",          # Top 100 ports
                ],
                "priority": 4,
                "estimated_time": "5-10 minutes total (batch)",
                "rationale": "Quick overview sufficient for low-priority targets"
            }
        }


# ============================================================================
# LLM PROMPT FOR OSINT ANALYSIS
# ============================================================================

OSINT_ANALYSIS_PROMPT = """You are a professional penetration tester analyzing OSINT intelligence.

TARGET: {domain}

BUSINESS CONTEXT (from company website):
{business_context}

DISCOVERED SUBDOMAINS ({subdomain_count}):
{subdomains}

SHODAN INTELLIGENCE:
{shodan_summary}

YOUR TASK:
Analyze the above intelligence like a human pentester would. Identify:

1. **CROWN JEWELS** - The 3-5 most critical assets
   - Core products/services mentioned on website
   - Subdomains that match business-critical functions
   - High-value targets (auth, payment, admin, API)

2. **ATTACK SURFACE** - What's most vulnerable
   - Exposed critical services (databases, RDP, SMB)
   - Known CVEs from Shodan
   - Development/staging environments

3. **SCAN PRIORITIES** - How to allocate time
   - Which targets deserve comprehensive scans
   - Which can be quick-scanned
   - Why each is prioritized that way

OUTPUT FORMAT:
## CROWN JEWELS (Top 3-5 Critical Targets)
[List with business justification for each]

## HIGH-VALUE TARGETS
[List with technical justification]

## RECOMMENDED SCAN STRATEGY
[Specific scanning approach for each priority level]

THINK LIKE A PENTESTER: Don't just look at subdomain names. Consider:
- What does the company actually sell/do?
- Which subdomains align with core business?
- What would cause maximum impact if compromised?
"""


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    analyzer = OSINTIntelligenceAnalyzer()
    
    # Example: snode.com reconnaissance
    subdomains = [
        "guardian.snode.com",
        "guardian-master-01.snode.com",
        "api.snode.com",
        "admin.snode.com",
        "dev.snode.com",
        "www.snode.com",
        "mail.snode.com"
    ]
    
    # Simulated web content
    web_content = {
        "homepage": """
        SNODE is the leading provider of Guardian security solutions. 
        Our flagship Guardian platform protects enterprise networks worldwide.
        Guardian is used by Fortune 500 companies for mission-critical security.
        """,
        "about": """
        Guardian technology is our core product, featuring patented 
        threat detection and automated response capabilities.
        """
    }
    
    # Analyze intelligence
    intelligence = analyzer.analyze_target_intelligence(
        domain="snode.com",
        subdomains=subdomains,
        web_content=web_content
    )
    
    # Display results
    print("\n🎯 INTELLIGENCE ANALYSIS RESULTS\n")
    
    print("CROWN JEWELS:")
    for target in intelligence["crown_jewels"]:
        print(f"  • {target['subdomain']} (Score: {target['score']}/10)")
        for reason in target['reasons']:
            print(f"    - {reason}")
    
    print("\nHIGH VALUE:")
    for target in intelligence["high_value"]:
        print(f"  • {target['subdomain']} (Score: {target['score']}/10)")
    
    print("\nRECOMMENDED SCAN STRATEGY:")
    strategy = intelligence["recommended_scan_strategy"]
    for priority, details in strategy.items():
        print(f"\n{priority.upper()}:")
        print(f"  Scan Type: {details['scan_type']}")
        print(f"  Tools: {', '.join(details['tools'])}")
        print(f"  Time: {details['estimated_time']}")
