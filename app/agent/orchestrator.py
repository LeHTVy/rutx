"""
Agent Orchestrator - Routes tasks to specialized agents
=======================================================

Central coordinator that decides which specialized agent(s) 
should handle a given task based on LLM analysis.
"""
from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass, field
import logging
import re

from app.agent.specialized import (
    BaseSpecializedAgent,
    ReconAgent,
    WebPentestAgent,
    VulnHunterAgent,
    NetworkAnalystAgent,
    ExploitExpertAgent
)
from app.agent.roles import get_role_manager

logger = logging.getLogger(__name__)


@dataclass
class RoutingDecision:
    """Result of agent routing decision"""
    primary_agent: str
    confidence: float
    reason: str
    secondary_agents: List[str] = field(default_factory=list)
    is_multi_agent: bool = False


@dataclass
class WorkflowResult:
    """Result from multi-agent workflow"""
    success: bool
    agents_used: List[str]
    combined_findings: Dict[str, Any]
    outputs: List[str]
    final_summary: str


class AgentOrchestrator:
    """
    Routes tasks to appropriate specialized agents.
    
    Capabilities:
    - LLM-based routing to select best agent
    - Multi-agent workflows for complex tasks
    - Context passing between agents
    - Automatic agent chaining based on suggestions
    """
    
    # Agent registry
    AGENT_CLASSES: Dict[str, Type[BaseSpecializedAgent]] = {
        "recon_agent": ReconAgent,
        "web_pentest_agent": WebPentestAgent,
        "vuln_hunter_agent": VulnHunterAgent,
        "network_analyst_agent": NetworkAnalystAgent,
        "exploit_expert_agent": ExploitExpertAgent,
    }
    
    # Keywords for quick routing (backup when no LLM)
    ROUTING_KEYWORDS = {
        "recon_agent": ["subdomain", "recon", "osint", "enumerate", "discover", "amass", "subfinder"],
        "web_pentest_agent": ["web", "http", "fuzz", "directory", "ffuf", "nikto", "owasp"],
        "vuln_hunter_agent": ["vuln", "cve", "vulnerability", "exploit", "nuclei"],
        "network_analyst_agent": ["port", "scan", "nmap", "service", "network", "ip", "masscan"],
        "exploit_expert_agent": ["exploit", "payload", "metasploit", "sqlmap", "attack"],
    }
    
    def __init__(self, llm_client=None, config: Dict = None):
        self.llm = llm_client
        self.config = config or {}
        self.role_manager = get_role_manager()
        self._agents: Dict[str, BaseSpecializedAgent] = {}
    
    def _get_agent(self, agent_name: str) -> Optional[BaseSpecializedAgent]:
        """Get or create agent instance"""
        if agent_name not in self._agents:
            agent_class = self.AGENT_CLASSES.get(agent_name)
            if agent_class:
                self._agents[agent_name] = agent_class(
                    llm_client=self.llm,
                    config=self.config
                )
        return self._agents.get(agent_name)
    
    def list_agents(self) -> List[Dict]:
        """List available agents with info"""
        agents = []
        for name in self.AGENT_CLASSES.keys():
            info = self.role_manager.get_role_info(name)
            if info:
                agents.append(info)
            else:
                agents.append({
                    "name": name,
                    "description": "No description available",
                    "enabled": True
                })
        return agents
    
    def route(self, query: str, context: Dict = None) -> RoutingDecision:
        """
        Decide which agent should handle the query.
        
        Uses LLM if available, falls back to keyword matching.
        """
        context = context or {}
        
        # Try LLM-based routing first
        if self.llm:
            return self._route_with_llm(query, context)
        
        # Fallback to keyword-based routing
        return self._route_with_keywords(query)
    
    def _route_with_llm(self, query: str, context: Dict) -> RoutingDecision:
        """Use LLM to decide routing"""
        available_agents = "\n".join([
            f"- {name}: {info.get('description', 'N/A')}"
            for name, info in [
                (n, self.role_manager.get_role_info(n) or {})
                for n in self.AGENT_CLASSES.keys()
            ]
        ])
        
        prompt = f"""Given the user query and available specialized agents, select the best agent to handle this task.

Available Agents:
{available_agents}

User Query: {query}

Context: {context}

Respond with ONLY a JSON object in this exact format:
{{"agent": "agent_name_here", "confidence": 0.0-1.0, "reason": "brief explanation"}}
"""
        
        try:
            response = self.llm.generate(prompt, system="You are a routing assistant. Respond only with valid JSON.")
            
            # Parse JSON from response
            json_match = re.search(r'\{[^}]+\}', response)
            if json_match:
                import json
                data = json.loads(json_match.group())
                return RoutingDecision(
                    primary_agent=data.get('agent', 'recon_agent'),
                    confidence=float(data.get('confidence', 0.5)),
                    reason=data.get('reason', '')
                )
        except Exception as e:
            logger.warning(f"LLM routing failed: {e}, falling back to keywords")
        
        return self._route_with_keywords(query)
    
    def _route_with_keywords(self, query: str) -> RoutingDecision:
        """Keyword-based routing fallback"""
        query_lower = query.lower()
        
        scores = {}
        for agent_name, keywords in self.ROUTING_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in query_lower)
            if score > 0:
                scores[agent_name] = score
        
        if scores:
            best_agent = max(scores.keys(), key=lambda x: scores[x])
            max_score = scores[best_agent]
            confidence = min(max_score / 3.0, 1.0)  # Normalize
            return RoutingDecision(
                primary_agent=best_agent,
                confidence=confidence,
                reason=f"Matched {max_score} keywords"
            )
        
        # Default to recon
        return RoutingDecision(
            primary_agent="recon_agent",
            confidence=0.3,
            reason="No clear match, defaulting to reconnaissance"
        )
    
    def execute(self, query: str, context: Dict = None, agent_name: str = None) -> Any:
        """
        Execute task with appropriate agent.
        
        Args:
            query: User query/task
            context: Additional context
            agent_name: Force specific agent (optional)
        """
        context = context or {}
        
        # Route or use specified agent
        if agent_name:
            decision = RoutingDecision(
                primary_agent=agent_name,
                confidence=1.0,
                reason="User specified"
            )
        else:
            decision = self.route(query, context)
        
        logger.info(f"Routing to {decision.primary_agent} (confidence: {decision.confidence})")
        
        # Get and execute agent
        agent = self._get_agent(decision.primary_agent)
        if not agent:
            return {
                "error": f"Agent not found: {decision.primary_agent}",
                "available": list(self.AGENT_CLASSES.keys())
            }
        
        return agent.execute(query, context)
    
    def execute_workflow(
        self, 
        query: str, 
        context: Dict = None,
        max_agents: int = 3,
        auto_chain: bool = True
    ) -> WorkflowResult:
        """
        Execute multi-agent workflow.
        
        Agents can suggest next agents, creating an automatic chain.
        """
        context = context or {}
        agents_used = []
        outputs = []
        combined_findings = {}
        
        current_query = query
        current_context = context.copy()
        
        for i in range(max_agents):
            # Route to next agent
            decision = self.route(current_query, current_context)
            agent_name = decision.primary_agent
            
            if agent_name in agents_used:
                # Avoid loops
                break
            
            logger.info(f"Workflow step {i+1}: {agent_name}")
            agents_used.append(agent_name)
            
            # Execute agent
            result = self.execute(current_query, current_context, agent_name)
            
            if hasattr(result, 'output'):
                outputs.append(f"**{agent_name}:**\n{result.output}")
            
            if hasattr(result, 'findings'):
                combined_findings.update(result.findings)
                current_context.update(result.findings)
            
            # Check for suggested next agent
            if auto_chain and hasattr(result, 'suggested_agents') and result.suggested_agents:
                # Use first suggestion that hasn't been used
                next_agent = None
                for suggested in result.suggested_agents:
                    if suggested not in agents_used:
                        next_agent = suggested
                        break
                
                if not next_agent:
                    break
                
                # Continue with suggested agent
                current_query = f"Continue analysis based on previous findings"
            else:
                break
        
        return WorkflowResult(
            success=len(agents_used) > 0,
            agents_used=agents_used,
            combined_findings=combined_findings,
            outputs=outputs,
            final_summary="\n\n".join(outputs)
        )


# Singleton instance
_orchestrator: Optional[AgentOrchestrator] = None


def get_orchestrator(llm_client=None, config: Dict = None) -> AgentOrchestrator:
    """Get singleton AgentOrchestrator instance"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator(llm_client, config)
    return _orchestrator
