"""
LLM Response Validator

Validates Phase 3 (Intelligence Analysis) LLM outputs to detect:
- Requests for scan results (when already provided)
- Hallucinated data (invented CVEs, services, ports)
- Generic/vague recommendations
- Missing evidence citations
- Quality issues
"""

from typing import Dict, List, Tuple, Optional
import re
import json


class ResponseValidator:
    """Validates LLM responses for quality and accuracy"""

    # Phrases indicating LLM is asking for data
    ASKING_PHRASES = [
        "please provide",
        "need the scan",
        "share the results",
        "send me the",
        "waiting for the scan",
        "provide me with",
        "show me the",
        "i need to see",
        "could you provide",
        "can you share"
    ]

    # Generic advice phrases (indicates low-quality response)
    GENERIC_PHRASES = [
        "further investigation",
        "additional testing",
        "it's important to",
        "you should consider",
        "best practices include",
        "recommended to perform",
        "advisable to conduct",
        "suggest performing"
    ]

    @classmethod
    def validate_phase3_output(cls, response: str, programmatic_report: str) -> Tuple[bool, List[str], Dict]:
        """
        Comprehensive validation of Phase 3 LLM output.

        Args:
            response: LLM's analysis response
            programmatic_report: Original programmatic report data

        Returns:
            Tuple of (is_valid, issues_list, quality_score_dict)
        """
        issues = []
        warnings = []

        # Check 1: Is LLM asking for scan results?
        if cls._is_asking_for_data(response):
            issues.append("[X] CRITICAL: LLM asked for scan results instead of analyzing provided data")

        # Check 2: Are findings cited from programmatic report?
        if not cls._has_evidence_citations(response):
            warnings.append("[!] No evidence citations found - findings may not be grounded in scan data")

        # Check 3: Check for invented CVEs
        invented_cves = cls._check_invented_cves(response, programmatic_report)
        if invented_cves:
            issues.append(f"[X] CRITICAL: Invented CVEs not in report: {', '.join(invented_cves)}")

        # Check 4: Check for invented services
        invented_services = cls._check_invented_services(response, programmatic_report)
        if invented_services:
            issues.append(f"[X] Invented services not in report: {', '.join(invented_services[:5])}")

        # Check 5: Check for invented ports
        invented_ports = cls._check_invented_ports(response, programmatic_report)
        if invented_ports:
            issues.append(f"[X] Invented ports not in report: {', '.join(map(str, invented_ports[:10]))}")

        # Check 6: Is response too generic?
        generic_count = cls._count_generic_phrases(response)
        if generic_count > 3:
            warnings.append(f"[!] Response is too generic ({generic_count} vague recommendations)")

        # Check 7: Does response have structured format?
        if not cls._has_structured_format(response):
            warnings.append("[!] Response does not follow required structured format")

        # Calculate quality score
        quality_score = cls._calculate_quality_score(response, programmatic_report, issues, warnings)

        # Combine issues and warnings
        all_issues = issues + warnings

        is_valid = len(issues) == 0  # Valid if no critical issues

        return is_valid, all_issues, quality_score

    @classmethod
    def _is_asking_for_data(cls, response: str) -> bool:
        """Check if LLM is asking for scan results"""
        response_lower = response.lower()
        return any(phrase in response_lower for phrase in cls.ASKING_PHRASES)

    @classmethod
    def _has_evidence_citations(cls, response: str) -> bool:
        """Check if response contains evidence citations"""
        # Look for "Evidence:", "evidence":", or quoted text
        has_evidence_field = "evidence" in response.lower() and (":" in response or "\":" in response)
        has_quotes = response.count('"') >= 4  # At least 2 quoted sections
        
        # Also accept specific subdomain/domain mentions as evidence (for subdomain scans)
        has_domain_evidence = bool(re.search(r'\b[\w-]+\.[\w-]+\.[a-z]{2,}\b', response))
        
        return has_evidence_field or has_quotes or has_domain_evidence

    @classmethod
    def _check_invented_cves(cls, response: str, programmatic_report: str) -> List[str]:
        """Check for CVEs in response that aren't in programmatic report"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'

        cves_in_response = set(re.findall(cve_pattern, response))
        cves_in_report = set(re.findall(cve_pattern, programmatic_report))

        invented = list(cves_in_response - cves_in_report)
        return invented

    @classmethod
    def _check_invented_services(cls, response: str, programmatic_report: str) -> List[str]:
        """Check for services mentioned in response but not in report"""
        # Common service names
        services = [
            "SSH", "OpenSSH", "HTTP", "HTTPS", "Apache", "nginx", "IIS",
            "MySQL", "PostgreSQL", "MongoDB", "Redis", "Elasticsearch",
            "FTP", "SFTP", "SMTP", "POP3", "IMAP",
            "SMB", "RDP", "VNC", "Telnet", "DNS"
        ]

        response_lower = response.lower()
        report_lower = programmatic_report.lower()

        invented = []
        for service in services:
            service_lower = service.lower()
            # Service mentioned in response but not in report
            if service_lower in response_lower and service_lower not in report_lower:
                invented.append(service)

        return invented

    @classmethod
    def _check_invented_ports(cls, response: str, programmatic_report: str) -> List[int]:
        """Check for ports mentioned in response but not in report"""
        port_pattern = r'[Pp]ort\s+(\d{1,5})'

        ports_in_response = set(int(m) for m in re.findall(port_pattern, response) if int(m) <= 65535)
        ports_in_report = set(int(m) for m in re.findall(port_pattern, programmatic_report) if int(m) <= 65535)

        invented = list(ports_in_response - ports_in_report)
        return invented

    @classmethod
    def _count_generic_phrases(cls, response: str) -> int:
        """Count generic/vague phrases in response"""
        response_lower = response.lower()
        count = sum(1 for phrase in cls.GENERIC_PHRASES if phrase in response_lower)
        return count

    @classmethod
    def _has_structured_format(cls, response: str) -> bool:
        """Check if response follows structured format"""
        required_sections = [
            "executive summary",
            "findings",
            "recommendations"
        ]

        response_lower = response.lower()
        has_sections = sum(1 for section in required_sections if section in response_lower)

        return has_sections >= 2  # At least 2 of 3 sections present

    @classmethod
    def _calculate_quality_score(cls, response: str, programmatic_report: str,
                                   issues: List[str], warnings: List[str]) -> Dict:
        """
        Calculate quality score for response.

        Score breakdown (100 points total):
        - Evidence citations: 30 points
        - Specificity: 25 points
        - Accuracy: 25 points
        - Actionability: 20 points
        """
        score = {
            "total": 0,
            "max": 100,
            "breakdown": {},
            "grade": "F"
        }

        # 1. Evidence citations (30 points)
        evidence_count = response.count("Evidence:") + response.count("evidence\":")
        # Also count subdomain mentions as evidence for subdomain scans
        subdomain_mentions = len(re.findall(r'\b[\w-]+\.[\w-]+\.[a-z]{2,}\b', response))
        if subdomain_mentions > 0 and evidence_count == 0:
            evidence_count = min(3, subdomain_mentions // 2)  # Give partial credit for subdomain mentions
        score["breakdown"]["evidence_citations"] = min(30, evidence_count * 10)

        # 2. Specificity (25 points)
        has_ips = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', response))
        has_ports = bool(re.search(r'[Pp]ort \d+', response))
        has_services = bool(re.search(r'(SSH|HTTP|MySQL|nginx|Apache|FTP|SMB|RDP)', response))
        has_versions = bool(re.search(r'\d+\.\d+', response))  # Version numbers
        has_subdomains = bool(re.search(r'\b[\w-]+\.[\w-]+\.[a-z]{2,}\b', response))  # Subdomain mentions

        specificity = (has_ips * 8) + (has_ports * 7) + (has_services * 5) + (has_versions * 5) + (has_subdomains * 10)
        score["breakdown"]["specificity"] = min(25, specificity)

        # 3. Accuracy (25 points) - deduct for issues
        accuracy = 25
        accuracy -= len([i for i in issues if "CRITICAL" in i]) * 10  # -10 per critical issue
        accuracy -= len([i for i in issues if "[X]" in i and "CRITICAL" not in i]) * 5  # -5 per error
        accuracy = max(0, accuracy)
        score["breakdown"]["accuracy"] = accuracy

        # 4. Actionability (20 points)
        has_timeline = any(t in response for t in ["0-24h", "1-7d", "1-30d", "immediate", "short-term", "long-term"])
        has_specific_actions = (
            response.lower().count("upgrade") +
            response.lower().count("restrict") +
            response.lower().count("update") +
            response.lower().count("patch") +
            response.lower().count("configure")
        )

        actionability = (has_timeline * 10) + min(10, has_specific_actions * 2)
        score["breakdown"]["actionability"] = actionability

        # Calculate total
        score["total"] = sum(score["breakdown"].values())

        # Assign grade
        if score["total"] >= 85:
            score["grade"] = "A"
        elif score["total"] >= 70:
            score["grade"] = "B"
        elif score["total"] >= 50:
            score["grade"] = "C"
        elif score["total"] >= 30:
            score["grade"] = "D"
        else:
            score["grade"] = "F"

        # Add confidence level
        if score["total"] >= 80 and len(issues) == 0:
            score["confidence"] = "HIGH"
        elif score["total"] >= 60 and len([i for i in issues if "CRITICAL" in i]) == 0:
            score["confidence"] = "MEDIUM"
        else:
            score["confidence"] = "LOW"

        return score

    @classmethod
    def format_validation_report(cls, is_valid: bool, issues: List[str], quality_score: Dict) -> str:
        """Format validation results as readable report"""
        report = "\n" + "="*60 + "\n"
        report += "RESPONSE VALIDATION REPORT\n"
        report += "="*60 + "\n\n"

        # Overall status
        status = "[VALID]" if is_valid else "[INVALID]"
        report += f"Overall Status: {status}\n"
        report += f"Quality Grade: {quality_score['grade']} ({quality_score['total']}/{quality_score['max']} points)\n"
        report += f"Confidence: {quality_score['confidence']}\n\n"

        # Score breakdown
        report += "Score Breakdown:\n"
        for category, points in quality_score["breakdown"].items():
            category_name = category.replace("_", " ").title()
            report += f"  - {category_name}: {points} points\n"

        # Issues
        if issues:
            report += "\n"
            report += f"Issues Found ({len(issues)}):\n"
            for issue in issues:
                report += f"  {issue}\n"
        else:
            report += "\n[OK] No issues found!\n"

        report += "\n" + "="*60 + "\n"

        return report


def validate_response(response: str, programmatic_report: str, verbose: bool = True) -> Tuple[bool, Dict]:
    """
    Convenience function to validate LLM response.

    Args:
        response: LLM's Phase 3 analysis response
        programmatic_report: Original programmatic report
        verbose: If True, print validation report

    Returns:
        Tuple of (is_valid, quality_score_dict)
    """
    is_valid, issues, quality_score = ResponseValidator.validate_phase3_output(
        response, programmatic_report
    )

    if verbose:
        report = ResponseValidator.format_validation_report(is_valid, issues, quality_score)
        print(report)

    return is_valid, quality_score


# Testing
if __name__ == "__main__":
    print("Testing Response Validator...\n")

    # Test case 1: Good response
    good_response = """
## EXECUTIVE SUMMARY
- Overall Risk Level: HIGH
- Targets Scanned: 192.168.1.100
- Key Findings:
  - Critical: 0 findings
  - High: 2 findings

## FINDINGS

### High Severity

**Title**: Outdated MySQL 5.5.62 Exposed
**Affected Target**: 192.168.1.100
**Affected Port**: 3306
**Service**: MySQL 5.5.62
**Evidence**: "Port 3306: MySQL 5.5.62" (from programmatic report)
**CVE IDs**: None detected
**Recommendation**: Upgrade to MySQL 8.0+ within 0-24h
    """

    report = "Port 3306: MySQL 5.5.62\nPort 22: OpenSSH 7.4"

    print("Test 1: Good Response")
    validate_response(good_response, report)

    # Test case 2: Bad response (asking for data)
    bad_response = "I need you to provide the scan results so I can analyze them."

    print("\nTest 2: Bad Response (Asking for Data)")
    validate_response(bad_response, report)

    # Test case 3: Hallucinated CVE
    hallucinated_response = """
## FINDINGS
**Title**: Critical RCE Vulnerability
**Evidence**: "Port 3306: MySQL 5.5.62"
**CVE IDs**: CVE-2023-99999
**Recommendation**: Patch immediately
    """

    print("\nTest 3: Hallucinated CVE")
    validate_response(hallucinated_response, report)
