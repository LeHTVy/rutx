"""
Vuln Hunter Agent - Vulnerability Research Specialist
=====================================================

Handles CVE research, vulnerability scanning, and prioritization.
"""
from typing import Dict, Any, List, Optional
import logging
import re

from .base import BaseSpecializedAgent, AgentResult, ToolResult

logger = logging.getLogger(__name__)


class VulnHunterAgent(BaseSpecializedAgent):
    """
    Vulnerability hunting and research agent.
    
    Specializes in:
    - CVE research and correlation
    - Vulnerability scanning
    - Severity prioritization
    - Exploit availability research
    """
    
    ROLE_NAME = "vuln_hunter_agent"
    
    def execute(self, task: str, context: Dict = None) -> AgentResult:
        """Execute vulnerability hunting task"""
        context = context or {}
        context['user_input'] = task
        
        target = context.get('target', '')
        services = context.get('services', [])
        context['services'] = services
        
        findings = {
            "target": target,
            "cves": [],
            "vulnerabilities": [],
            "exploits_available": []
        }
        tool_results = []
        
        # Vulnerability scanning with nuclei
        if self.can_use_tool('nuclei'):
            result = self.execute_tool('nuclei', 'vuln_scan', {
                'target': target,
                'severity': 'critical,high,medium'
            })
            tool_results.append(result)
            if result.success:
                vulns = self._parse_nuclei_vulns(result.output)
                findings['vulnerabilities'] = vulns
                findings['cves'] = self._extract_cves(result.output)
        
        # Service-based vuln scan with nmap
        if services and self.can_use_tool('nmap'):
            result = self.execute_tool('nmap', 'vuln_scan', {
                'target': target,
                'scripts': 'vuln'
            })
            tool_results.append(result)
            if result.success:
                additional_cves = self._extract_cves(result.output)
                findings['cves'].extend(additional_cves)
        
        # Search for exploits
        if findings['cves'] and self.can_use_tool('searchsploit'):
            for cve in findings['cves'][:5]:  # Limit to 5
                result = self.execute_tool('searchsploit', 'search', {
                    'query': cve
                })
                tool_results.append(result)
                if result.success and result.output.strip():
                    findings['exploits_available'].append({
                        'cve': cve,
                        'exploits': result.output
                    })
        
        # Generate analysis
        user_prompt = self.get_user_prompt(context)
        analysis = self._generate_llm_response(user_prompt)
        
        return AgentResult(
            agent_name=self.name,
            success=len(tool_results) > 0,
            output=analysis,
            findings=findings,
            tool_results=tool_results,
            next_action="exploit" if findings.get('exploits_available') else None,
            suggested_agents=["exploit_expert_agent"]
        )
    
    def _parse_nuclei_vulns(self, output: str) -> List[Dict]:
        """Parse nuclei vulnerability findings"""
        vulns = []
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            severity = "info"
            if '[critical]' in line.lower():
                severity = "critical"
            elif '[high]' in line.lower():
                severity = "high"
            elif '[medium]' in line.lower():
                severity = "medium"
            elif '[low]' in line.lower():
                severity = "low"
            
            vulns.append({
                "raw": line,
                "severity": severity
            })
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulns.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        return vulns
    
    def _extract_cves(self, output: str) -> List[str]:
        """Extract CVE IDs from output"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = list(set(re.findall(cve_pattern, output, re.IGNORECASE)))
        return [cve.upper() for cve in cves]
    
    def suggest_next_agent(self, findings: Dict) -> Optional[str]:
        """Suggest next agent based on vulnerability findings"""
        if findings.get('exploits_available'):
            return "exploit_expert_agent"
        return None
