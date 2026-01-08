"""
Network Analyst Agent - Network Security Specialist
===================================================

Handles port scanning, service detection, and network analysis.
"""
from typing import Dict, Any, List, Optional
import logging
import re

from .base import BaseSpecializedAgent, AgentResult, ToolResult

logger = logging.getLogger(__name__)


class NetworkAnalystAgent(BaseSpecializedAgent):
    """
    Network analysis and scanning agent.
    
    Specializes in:
    - Port scanning
    - Service detection
    - OS fingerprinting
    - Network topology mapping
    """
    
    ROLE_NAME = "network_analyst_agent"
    
    def execute(self, task: str, context: Dict = None) -> AgentResult:
        """Execute network analysis task"""
        context = context or {}
        context['user_input'] = task
        
        target = context.get('target', '')
        scan_type = self._determine_scan_type(task)
        context['scan_type'] = scan_type
        
        findings = {
            "target": target,
            "open_ports": [],
            "services": [],
            "os_detection": None,
            "hosts_up": []
        }
        tool_results = []
        
        # Select scanner based on task
        if 'fast' in task.lower() or 'quick' in task.lower():
            # Fast scan with rustscan or masscan
            if self.can_use_tool('rustscan'):
                result = self.execute_tool('rustscan', 'quick_scan', {
                    'target': target
                })
                tool_results.append(result)
                if result.success:
                    findings['open_ports'] = self._parse_ports(result.output)
            elif self.can_use_tool('masscan'):
                result = self.execute_tool('masscan', 'port_scan', {
                    'target': target,
                    'ports': '1-65535',
                    'rate': '1000'
                })
                tool_results.append(result)
                if result.success:
                    findings['open_ports'] = self._parse_ports(result.output)
        
        # Detailed scan with nmap
        if self.can_use_tool('nmap'):
            # Service version detection
            if 'service' in task.lower() or 'version' in task.lower() or not tool_results:
                result = self.execute_tool('nmap', 'service_scan', {
                    'target': target
                })
                tool_results.append(result)
                if result.success:
                    parsed = self._parse_nmap_output(result.output)
                    findings['open_ports'] = parsed.get('ports', [])
                    findings['services'] = parsed.get('services', [])
            
            # OS detection
            if 'os' in task.lower() or 'operating' in task.lower():
                result = self.execute_tool('nmap', 'os_detect', {
                    'target': target
                })
                tool_results.append(result)
                if result.success:
                    findings['os_detection'] = self._parse_os_detection(result.output)
        
        # Generate analysis
        user_prompt = self.get_user_prompt(context)
        analysis = self._generate_llm_response(user_prompt)
        
        return AgentResult(
            agent_name=self.name,
            success=len(tool_results) > 0,
            output=analysis,
            findings=findings,
            tool_results=tool_results,
            next_action="vuln_scan" if findings.get('services') else None,
            suggested_agents=["vuln_hunter_agent", "web_pentest_agent"]
        )
    
    def _determine_scan_type(self, task: str) -> str:
        """Determine scan type from task"""
        task_lower = task.lower()
        if 'stealth' in task_lower or 'syn' in task_lower:
            return "stealth"
        if 'full' in task_lower or 'comprehensive' in task_lower:
            return "comprehensive"
        if 'quick' in task_lower or 'fast' in task_lower:
            return "quick"
        return "default"
    
    def _parse_ports(self, output: str) -> List[Dict]:
        """Parse port list from scanner output"""
        ports = []
        port_pattern = r'(\d+)/(tcp|udp)\s+(\w+)'
        for match in re.finditer(port_pattern, output):
            ports.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3)
            })
        return ports
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse nmap output for ports and services"""
        result = {"ports": [], "services": []}
        
        # Parse port/service lines
        pattern = r'(\d+)/(tcp|udp)\s+(\w+)\s+(.+)'
        for match in re.finditer(pattern, output):
            port_info = {
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4).strip()
            }
            result['ports'].append(port_info)
            result['services'].append({
                "port": port_info['port'],
                "name": port_info['service']
            })
        
        return result
    
    def _parse_os_detection(self, output: str) -> Optional[Dict]:
        """Parse OS detection results"""
        os_info = None
        # Look for OS detection lines
        os_match = re.search(r'OS details?:\s*(.+)', output, re.IGNORECASE)
        if os_match:
            os_info = {"detected": os_match.group(1).strip()}
        return os_info
    
    def suggest_next_agent(self, findings: Dict) -> Optional[str]:
        """Suggest next agent based on network findings"""
        if findings.get('services'):
            # Check for web services
            for svc in findings['services']:
                if any(kw in svc.get('name', '').lower() for kw in ['http', 'web', 'nginx', 'apache']):
                    return "web_pentest_agent"
        return "vuln_hunter_agent"
