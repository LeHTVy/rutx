"""
Recon Agent - Reconnaissance Specialist
=======================================

Handles subdomain enumeration, OSINT, and attack surface mapping.
"""
from typing import Dict, Any, List, Optional
import logging
import re

from .base import BaseSpecializedAgent, AgentResult, ToolResult

logger = logging.getLogger(__name__)


class ReconAgent(BaseSpecializedAgent):
    """
    Reconnaissance agent for information gathering.
    
    Specializes in:
    - Subdomain enumeration
    - Technology detection
    - Attack surface mapping
    - OSINT collection
    """
    
    ROLE_NAME = "recon_agent"
    
    def execute(self, task: str, context: Dict = None) -> AgentResult:
        """Execute recon task"""
        context = context or {}
        context['user_input'] = task
        
        # Extract target from task
        target = self._extract_target(task, context)
        context['target'] = target
        
        findings = {
            "target": target,
            "subdomains": [],
            "technologies": [],
            "endpoints": [],
            "ips": []
        }
        tool_results = []
        
        # Determine which tools to use based on task
        if any(kw in task.lower() for kw in ['subdomain', 'sub', 'domain']):
            # Subdomain enumeration
            if self.can_use_tool('subfinder'):
                result = self.execute_tool('subfinder', 'enumerate', {
                    'domain': target
                })
                tool_results.append(result)
                if result.success:
                    findings['subdomains'] = self._parse_subdomains(result.output)
        
        if any(kw in task.lower() for kw in ['tech', 'stack', 'httpx']):
            # Technology detection
            if self.can_use_tool('httpx'):
                targets = findings.get('subdomains', [target])
                result = self.execute_tool('httpx', 'probe', {
                    'targets': targets[:50]  # Limit to 50
                })
                tool_results.append(result)
                if result.success:
                    findings['technologies'] = self._parse_technologies(result.output)
        
        # Generate analysis with LLM
        user_prompt = self.get_user_prompt(context)
        analysis = self._generate_llm_response(user_prompt)
        
        return AgentResult(
            agent_name=self.name,
            success=len(tool_results) > 0,
            output=analysis,
            findings=findings,
            tool_results=tool_results,
            next_action="scan_ports" if findings.get('subdomains') else None,
            suggested_agents=["network_analyst_agent", "web_pentest_agent"]
        )
    
    def _extract_target(self, task: str, context: Dict) -> str:
        """Extract target domain/IP from task"""
        # Check context first
        if context.get('target'):
            return context['target']
        
        # Try to find domain pattern
        domain_pattern = r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}'
        match = re.search(domain_pattern, task)
        if match:
            return match.group(0).replace('http://', '').replace('https://', '')
        
        # Try IP pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, task)
        if match:
            return match.group(0)
        
        return ""
    
    def _parse_subdomains(self, output: str) -> List[str]:
        """Parse subdomain list from tool output"""
        subdomains = []
        for line in output.split('\n'):
            line = line.strip()
            if line and '.' in line and not line.startswith('#'):
                subdomains.append(line)
        return subdomains
    
    def _parse_technologies(self, output: str) -> List[Dict]:
        """Parse technology detection results"""
        techs = []
        # Simple parsing - can be enhanced
        for line in output.split('\n'):
            if line.strip():
                techs.append({"raw": line.strip()})
        return techs
    
    def suggest_next_agent(self, findings: Dict) -> Optional[str]:
        """Suggest next agent based on recon findings"""
        if findings.get('subdomains'):
            return "network_analyst_agent"
        if findings.get('endpoints'):
            return "web_pentest_agent"
        return None
