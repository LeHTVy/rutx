"""
Analyzer - LLM Decision Layer for Plan-Execute-Analyze Loop
============================================================

After tool execution, the Analyzer decides:
- DONE: Goal achieved, return final response
- CONTINUE: Need more tools, loop back to Planner
- USER_INPUT: Need clarification from user

This creates a proper agentic loop where LLM recommends,
executor runs, and analyzer decides next step.
"""
from dataclasses import dataclass
from typing import Dict, Any, Optional
from enum import Enum

from app.llm import get_llm_config
from app.agent.graph import OllamaClient


class DecisionType(Enum):
    """Possible analyzer decisions."""
    DONE = "done"           # Goal achieved, return response
    CONTINUE = "continue"   # Need more tools
    USER_INPUT = "user_input"  # Need user clarification


@dataclass
class AnalyzerDecision:
    """Result of analyzer decision."""
    action: DecisionType
    response: str        # Final answer or question for user
    next_goal: str = ""  # If CONTINUE, what to pursue next
    confidence: float = 0.8
    
    @property
    def is_done(self) -> bool:
        return self.action == DecisionType.DONE
    
    @property
    def should_continue(self) -> bool:
        return self.action == DecisionType.CONTINUE
    
    @property
    def needs_user_input(self) -> bool:
        return self.action == DecisionType.USER_INPUT


# Prompt for analyzer to decide next step
ANALYZE_PROMPT = '''You are analyzing penetration test results to decide next steps.

ORIGINAL GOAL: {goal}

TOOLS EXECUTED:
{tools_summary}

RESULTS:
{results_summary}

CONTEXT:
{context_summary}

Based on the results, decide ONE of:

1. DONE - Goal is achieved, provide final summary
2. CONTINUE - More tools needed, specify what to do next  
3. USER_INPUT - Need clarification from user

OUTPUT JSON ONLY:
{{
    "decision": "DONE" | "CONTINUE" | "USER_INPUT",
    "response": "your response or question",
    "next_goal": "if CONTINUE, what to do next"
}}

CRITICAL DECISION RULES:
- RESPECT THE EXACT GOAL. If user asked for "subdomains" only → DONE after subdomains found
- CONTINUE only if user explicitly asked for "full pentest", "comprehensive scan", or "everything"
- If user asked for one specific thing and we did it → DONE
- If user query is vague (no target specified) → USER_INPUT
- If tools failed → DONE with error explanation

EXAMPLES:
- Goal: "find subdomains" + Result: "Found 23 subdomains" → DONE (user got what they asked)
- Goal: "full pentest on X" + Result: "Found subdomains" → CONTINUE to port scan
- Goal: "scan ports" + Result: "No ports open" → DONE (task complete, even if negative)
'''

# Simpler prompt for retry
ANALYZE_SIMPLE_PROMPT = '''Results: {results}

Decide: DONE (goal achieved) or CONTINUE (need more recon)?

JSON only:
{{"decision": "DONE", "response": "summary here", "next_goal": ""}}'''


class Analyzer:
    """
    Analyzes execution results and decides next action.
    
    Part of the Plan-Execute-Analyze loop.
    """
    
    def __init__(self, model: str = None):
        config = get_llm_config()
        self.model = model or config.get_model()
        self.llm = OllamaClient(model=self.model)
    
    def decide(
        self,
        goal: str,
        results: Dict[str, Any],
        context: Dict[str, Any]
    ) -> AnalyzerDecision:
        """
        Analyze results and decide next step.
        
        Args:
            goal: Original user goal
            results: Tool execution results
            context: Current context (subdomains, ports, etc.)
            
        Returns:
            AnalyzerDecision with action and response
        """
        # Build summaries for prompt
        tools_summary = self._summarize_tools(results)
        results_summary = self._summarize_results(results)
        context_summary = self._summarize_context(context)
        
        prompt = ANALYZE_PROMPT.format(
            goal=goal,
            tools_summary=tools_summary,
            results_summary=results_summary,
            context_summary=context_summary
        )
        
        # Try to get decision from LLM
        for attempt in range(2):
            try:
                if attempt == 0:
                    response = self.llm.generate(prompt, timeout=30)
                else:
                    # Simpler prompt on retry
                    response = self.llm.generate(
                        ANALYZE_SIMPLE_PROMPT.format(results=results_summary[:500]),
                        timeout=20
                    )
                
                decision = self._parse_decision(response)
                if decision:
                    return decision
                    
            except Exception:
                pass
        
        # Fallback: Use heuristics
        return self._heuristic_decision(goal, results, context)
    
    def _parse_decision(self, response: str) -> Optional[AnalyzerDecision]:
        """Parse LLM response into decision."""
        import json
        import re
        
        if not response:
            return None
        
        # Try to extract JSON
        try:
            # Find JSON in response
            json_match = re.search(r'\{[^}]+\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                
                decision_str = data.get("decision", "").upper()
                if decision_str == "DONE":
                    action = DecisionType.DONE
                elif decision_str == "CONTINUE":
                    action = DecisionType.CONTINUE
                elif decision_str == "USER_INPUT":
                    action = DecisionType.USER_INPUT
                else:
                    return None
                
                return AnalyzerDecision(
                    action=action,
                    response=data.get("response", ""),
                    next_goal=data.get("next_goal", "")
                )
        except (json.JSONDecodeError, KeyError):
            pass
        
        return None
    
    def _heuristic_decision(
        self,
        goal: str,
        results: Dict[str, Any],
        context: Dict[str, Any]
    ) -> AnalyzerDecision:
        """
        Fallback heuristic when LLM fails.
        
        SMART LOGIC:
        1. If goal mentions specific tool and we ran it → DONE
        2. If full pentest and not all steps done → CONTINUE
        3. Otherwise → DONE with results
        """
        goal_lower = goal.lower()
        executed_tools = list(results.keys())
        
        # Check what we have
        has_subdomains = context.get("has_subdomains", False)
        has_ports = context.get("has_ports", False)
        has_vulns = context.get("vuln_scan_done", False)
        
        # === RULE 1: Goal-specific completion ===
        # If user asked for subdomains and we got them → DONE
        if ("subdomain" in goal_lower and "subdomain_enum" in executed_tools) or has_subdomains:
            if "scan" not in goal_lower and "port" not in goal_lower and "vuln" not in goal_lower:
                # Just wanted subdomains, we're done
                return self._make_done_response(results)
        
        # If user asked for port scan and we did it → DONE
        if ("scan" in goal_lower or "port" in goal_lower) and (
            "port_scan" in executed_tools or "quick_scan" in executed_tools or has_ports
        ):
            if "vuln" not in goal_lower and "pentest" not in goal_lower:
                return self._make_done_response(results)
        
        # If user asked for vuln scan and we did it → DONE
        if "vuln" in goal_lower and ("vuln_scan" in executed_tools or has_vulns):
            return self._make_done_response(results)
        
        # === RULE 2: Full pentest flow ===
        is_full_pentest = any(word in goal_lower for word in [
            "pentest", "full scan", "comprehensive", "everything", "assess", "full recon"
        ])
        
        if is_full_pentest:
            if not has_subdomains:
                return AnalyzerDecision(
                    action=DecisionType.CONTINUE,
                    response="Starting with subdomain enumeration",
                    next_goal="enumerate subdomains"
                )
            elif not has_ports:
                return AnalyzerDecision(
                    action=DecisionType.CONTINUE,
                    response="Subdomains found, scanning ports",
                    next_goal="scan ports on discovered subdomains"
                )
            elif not has_vulns:
                return AnalyzerDecision(
                    action=DecisionType.CONTINUE,
                    response="Ports scanned, checking vulnerabilities",
                    next_goal="run vulnerability scan"
                )
            else:
                # All steps done
                return self._make_done_response(results)
        
        # === RULE 3: Default - if we have results, we're done ===
        if executed_tools:
            return self._make_done_response(results)
        
        return AnalyzerDecision(
            action=DecisionType.DONE,
            response="Analysis complete"
        )
    
    def _make_done_response(self, results: Dict[str, Any]) -> AnalyzerDecision:
        """Create DONE decision with formatted results."""
        try:
            from app.cli.display import format_tool_result
            
            response_parts = []
            for tool, result in results.items():
                if hasattr(result, 'output') and result.output:
                    formatted = format_tool_result(tool, result.output, result.success)
                    response_parts.append(formatted)
                elif hasattr(result, 'success'):
                    response_parts.append(f"{tool}: {'Success' if result.success else 'Failed'}")
            
            response = "\n\n".join(response_parts) if response_parts else "Task completed"
        except ImportError:
            # Fallback if display.py not available
            response_parts = []
            for tool, result in results.items():
                if hasattr(result, 'output') and result.output:
                    response_parts.append(result.output[:500])
            response = "\n\n".join(response_parts) if response_parts else "Task completed"
        
        return AnalyzerDecision(
            action=DecisionType.DONE,
            response=response
        )
    
    def _summarize_tools(self, results: Dict[str, Any]) -> str:
        """Summarize which tools were executed."""
        tools = list(results.keys())
        if not tools:
            return "No tools executed"
        return ", ".join(tools)
    
    def _summarize_results(self, results: Dict[str, Any]) -> str:
        """Summarize tool outputs."""
        summaries = []
        for tool, result in results.items():
            if hasattr(result, 'output'):
                output = result.output[:300] if len(result.output) > 300 else result.output
                success = "✓" if result.success else "✗"
                summaries.append(f"{success} {tool}: {output}")
            else:
                summaries.append(f"? {tool}: {str(result)[:100]}")
        
        return "\n".join(summaries) if summaries else "No results"
    
    def _summarize_context(self, context: Dict[str, Any]) -> str:
        """Summarize current context."""
        facts = []
        
        if context.get("has_subdomains"):
            count = context.get("subdomain_count", "some")
            facts.append(f"Subdomains: {count} found")
        
        if context.get("has_ports"):
            facts.append("Ports: scanned")
        
        if context.get("vuln_scan_done"):
            facts.append("Vulnerabilities: scanned")
        
        if context.get("last_domain"):
            facts.append(f"Target: {context['last_domain']}")
        
        return ", ".join(facts) if facts else "No prior data"
