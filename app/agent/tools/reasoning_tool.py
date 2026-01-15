"""
Reasoning Tool - Clean Refactored Version

Comprehensive analysis of security testing results using reasoning model.
Main purpose: Provide final assessment after all tasks are completed, analyzing all findings comprehensively.

Focus: Clean code structure with helper functions.
"""
from typing import Dict, Any
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient
from app.agent.analyzer import get_checklist_manager
from app.ui import get_logger

logger = get_logger()


def _build_results_summary(context: Dict[str, Any]) -> str:
    """Build summary of all execution results."""
    summary_parts = []
    
    # Get execution results
    execution_results = context.get("execution_results", {})
    if execution_results:
        summary_parts.append("## Execution Results:")
        for tool, result in execution_results.items():
            if result.get("success"):
                output = result.get("output", "")[:500]
                summary_parts.append(f"- {tool}: Success\n  Output: {output[:200]}...")
            else:
                error = result.get("error", "Unknown error")
                summary_parts.append(f"- {tool}: Failed\n  Error: {error}")
    
    # Get findings
    findings = context.get("findings", [])
    if findings:
        summary_parts.append(f"\n## Findings: {len(findings)} items discovered")
        for finding in findings[:10]:
            summary_parts.append(f"- {finding.get('type', 'Unknown')}: {finding.get('description', '')[:100]}")
    
    # Get vulnerabilities
    vulnerabilities = context.get("vulnerabilities", [])
    if vulnerabilities:
        summary_parts.append(f"\n## Vulnerabilities: {len(vulnerabilities)} found")
        for vuln in vulnerabilities[:10]:
            severity = vuln.get("severity", "unknown")
            summary_parts.append(f"- [{severity.upper()}] {vuln.get('name', 'Unknown')}: {vuln.get('description', '')[:100]}")
    
    # Get tools run
    tools_run = context.get("tools_run", [])
    if tools_run:
        summary_parts.append(f"\n## Tools Executed: {', '.join(tools_run)}")
    
    return "\n".join(summary_parts) if summary_parts else "No results available."


def _build_checklist_progress(context: Dict[str, Any]) -> str:
    """Build checklist progress summary."""
    checklist = context.get("checklist", [])
    if not checklist:
        return "No checklist available."
    
    checklist_manager = get_checklist_manager()
    session_id = context.get("session_id", "default")
    progress = checklist_manager.get_progress(session_id)
    
    progress_str = f"""
## Checklist Progress:
- Total Tasks: {progress['total']}
- Completed: {progress['completed']}
- Failed: {progress['failed']}
- Pending: {progress['pending']}
- In Progress: {progress['in_progress']}
- Completion: {progress['percentage']}%

## Tasks:
"""
    status_icons = {
        "completed": "✅",
        "failed": "❌",
        "in_progress": "🔄",
        "pending": "⏳"
    }
    
    for task_data in checklist:
        task_id = task_data.get("id", "unknown")
        description = task_data.get("description", "")
        status = task_data.get("status", "pending")
        phase = task_data.get("phase", 0)
        
        status_icon = status_icons.get(status, "⏳")
        progress_str += f"{status_icon} [{task_id}] Phase {phase}: {description}\n"
    
    return progress_str


def _build_context_summary(context: Dict[str, Any]) -> str:
    """Build context summary."""
    summary_parts = []
    
    if context.get("target_domain") or context.get("last_domain"):
        target = context.get("target_domain") or context.get("last_domain")
        summary_parts.append(f"Target: {target}")
    
    if context.get("subdomain_count"):
        summary_parts.append(f"Subdomains discovered: {context.get('subdomain_count')}")
    
    if context.get("detected_tech"):
        summary_parts.append(f"Technologies detected: {', '.join(context.get('detected_tech', [])[:10])}")
    
    if context.get("open_ports"):
        ports = context.get("open_ports", [])
        summary_parts.append(f"Open ports: {', '.join(map(str, ports[:20]))}")
    
    if context.get("has_vulnerabilities"):
        summary_parts.append("Vulnerabilities detected: Yes")
    
    return "\n".join(summary_parts) if summary_parts else "No additional context."


class ReasoningTool(AgentTool):
    """
    Tool for comprehensive reasoning and analysis of results.
    
    Main purpose:
    - Analyze all findings comprehensively after checklist completion
    - Provide final assessment using reasoning model
    - Summarize execution results, findings, vulnerabilities, and checklist progress
    - Generate comprehensive security assessment report
    """
    
    def execute(self, context: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """
        Analyze comprehensive results and provide final assessment.
        
        Args:
            context: Current context dictionary with all results
            
        Returns:
            Dictionary with comprehensive analysis and recommendations
        """
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        
        # Use reasoning model for comprehensive analysis
        from app.llm.config import get_reasoning_model
        reasoning_model = get_reasoning_model()
        llm = OllamaClient(model="reasoning") if reasoning_model else OllamaClient()
        
        # Build summaries
        results_summary = _build_results_summary(context)
        checklist_progress = _build_checklist_progress(context)
        context_summary = _build_context_summary(context)
        
        # Load prompt
        from app.agent.prompt_loader import format_prompt
        prompt = format_prompt(
            "reasoning",
            results_summary=results_summary,
            checklist_progress=checklist_progress,
            context_summary=context_summary
        )
        
        print("  🧠 Comprehensive analysis with reasoning model...")
        
        try:
            # Generate comprehensive analysis with streaming
            response = llm.generate(prompt, timeout=120, stream=True, show_thinking=True, show_content=True)
            
            return {
                "response": response or "Analysis completed.",
                "next_action": "end",
                "response_streamed": True,
                "context": context
            }
        except Exception as e:
            logger.error(f"Reasoning analysis failed: {e}")
            return {
                "response": f"Analysis completed. Error during reasoning: {e}",
                "next_action": "end",
                "response_streamed": False,
                "context": context
            }
