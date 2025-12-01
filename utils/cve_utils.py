import re
from typing import List, Dict, Set

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}')

def extract_cves_from_text(text: str) -> Set[str]:
    """Extract all CVE IDs from text"""
    return set(CVE_PATTERN.findall(text.upper()))

def extract_cves_from_scan_results(scan_results: List[Dict]) -> Dict[str, List[str]]:
    """
    Extract CVEs from all scan results

    Returns:
        {
            "shodan": ["CVE-2021-44228", ...],
            "nmap": ["CVE-2022-26134", ...],
            "total_unique": ["CVE-2021-44228", ...]
        }
    """
    cves = {
        "shodan": [],
        "nmap": [],
        "nuclei": [],
        "total_unique": set()
    }

    for result in scan_results:
        tool_name = result.get("tool", "").lower()

        # Shodan CVEs
        if "shodan" in tool_name:
            shodan_cves = result.get("result", {}).get("data", {}).get("vulns", [])
            cves["shodan"].extend(shodan_cves)
            cves["total_unique"].update(shodan_cves)

        # Nmap CVEs (from script output)
        elif "nmap" in tool_name:
            output = result.get("result", {}).get("output", "")
            nmap_cves = extract_cves_from_text(output)
            cves["nmap"].extend(nmap_cves)
            cves["total_unique"].update(nmap_cves)

    cves["total_unique"] = sorted(list(cves["total_unique"]))
    return cves

def summarize_cve_severity(cves: List[str]) -> Dict:
    """
    Quick severity estimate based on CVE year
    (Placeholder until we have full enrichment)

    Returns:
        {
            "total": 5,
            "recent": 3,  # Last 2 years
            "critical_likely": 2  # Based on heuristics
        }
    """
    from datetime import datetime
    current_year = datetime.now().year

    recent = [c for c in cves if int(c.split('-')[1]) >= current_year - 2]

    return {
        "total": len(cves),
        "recent": len(recent),
        "recent_pct": round(len(recent) / len(cves) * 100) if cves else 0
    }
