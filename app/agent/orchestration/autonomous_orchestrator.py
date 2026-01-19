"""
Autonomous Orchestrator - Self-Driving Pentest Agent
=====================================================

Core autonomous loop that:
1. Receives task from user
2. Shows plan with countdown timer
3. Auto-executes unless cancelled
4. Chains agents automatically when phase complete
5. Stops only when LLM determines task complete

This is the brain that makes SNODE truly autonomous like Cursor.
"""
import asyncio
import sys
import time
import select
from typing import Dict, Any, List, Optional, Generator, AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum

from app.ui import get_logger

logger = get_logger()


class OrchestrationStatus(Enum):
    """Status of the orchestration loop."""
    PLANNING = "planning"
    COUNTDOWN = "countdown"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    PHASE_COMPLETE = "phase_complete"
    TASK_COMPLETE = "task_complete"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass
class OrchestratorEvent:
    """Event yielded by the orchestrator."""
    status: OrchestrationStatus
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    countdown: int = 0


class AutonomousOrchestrator:
    """
    Self-driving orchestrator for SNODE.
    
    Replaces the old confirmation-based flow with:
    - LLM-driven agent selection
    - Auto-execution with countdown
    - Automatic phase transitions
    - Context flow between phases
    """
    
    # Configuration
    DEFAULT_COUNTDOWN = 5  # seconds before auto-execute
    MAX_ITERATIONS = 10   # prevent infinite loops
    MAX_RUNTIME = 1800    # 30 minutes max
    
    def __init__(self):
        self._llm = None
        self._coordinator = None
        self._shared_memory = None
        self.iteration_count = 0
        self.start_time = None
        self.cancelled = False
    
    @property
    def llm(self):
        """Lazy-load LLM client."""
        if self._llm is None:
            from app.llm.client import OllamaClient
            self._llm = OllamaClient()
        return self._llm
    
    @property
    def coordinator(self):
        """Lazy-load agent coordinator."""
        if self._coordinator is None:
            from app.agent.orchestration.coordinator import get_coordinator
            self._coordinator = get_coordinator()
        return self._coordinator
    
    @property
    def shared_memory(self):
        """Get shared memory."""
        if self._shared_memory is None:
            from app.memory import get_shared_memory
            self._shared_memory = get_shared_memory()
        return self._shared_memory
    
    def run_autonomous(self, task: str, context: Dict[str, Any] = None) -> Generator[OrchestratorEvent, None, None]:
        """
        Run autonomous pentest workflow.
        
        Yields events for UI to display. Auto-proceeds after countdown.
        
        Args:
            task: User's task description
            context: Initial context (optional)
            
        Yields:
            OrchestratorEvent with status updates
        """
        self.start_time = time.time()
        self.iteration_count = 0
        self.cancelled = False
        
        # Initialize context
        if context is None:
            context = self.shared_memory.to_dict()
        
        # Extract target from task if not in context
        if not context.get("target_domain") and not context.get("last_domain"):
            target = self._extract_target(task)
            if target:
                context["target_domain"] = target
                context["last_domain"] = target
                self.shared_memory.domain = target
        
        yield OrchestratorEvent(
            status=OrchestrationStatus.PLANNING,
            message=f"🧠 Planning autonomous attack...",
            data={"task": task, "target": context.get("target_domain", "unknown")}
        )
        
        # Main autonomous loop
        while not self._is_task_complete(context) and not self.cancelled:
            # Check limits
            if self.iteration_count >= self.MAX_ITERATIONS:
                yield OrchestratorEvent(
                    status=OrchestrationStatus.TASK_COMPLETE,
                    message=f"⚠️ Reached iteration limit ({self.MAX_ITERATIONS})",
                    data=context
                )
                break
            
            elapsed = time.time() - self.start_time
            if elapsed > self.MAX_RUNTIME:
                yield OrchestratorEvent(
                    status=OrchestrationStatus.TASK_COMPLETE,
                    message=f"⚠️ Reached time limit ({self.MAX_RUNTIME}s)",
                    data=context
                )
                break
            
            self.iteration_count += 1
            
            # 1. LLM selects best agent
            agent = self._select_agent(task, context)
            
            # 2. Agent plans tools
            plan = agent.plan_with_user_priority(task, context)
            
            # Check if any tools to run
            if not plan.get("tools"):
                yield OrchestratorEvent(
                    status=OrchestrationStatus.TASK_COMPLETE,
                    message="✅ No more tools to run - task complete",
                    data=context
                )
                break
            
            # 3. Yield plan with countdown
            yield OrchestratorEvent(
                status=OrchestrationStatus.COUNTDOWN,
                message=self._format_plan(plan, context),
                data={"plan": plan, "agent": agent.AGENT_NAME},
                countdown=self.DEFAULT_COUNTDOWN
            )
            
            # Check if cancelled during countdown (handled by caller)
            if self.cancelled:
                yield OrchestratorEvent(
                    status=OrchestrationStatus.CANCELLED,
                    message="❌ Cancelled by user"
                )
                break
            
            # 4. Execute tools
            yield OrchestratorEvent(
                status=OrchestrationStatus.EXECUTING,
                message=f"🚀 Executing: {', '.join(plan['tools'])}",
                data={"tools": plan["tools"]}
            )
            
            results = self._execute_plan(agent, plan, context)
            
            # 5. Update context with results
            context = self._merge_results(context, results)
            
            # Update shared memory
            self.shared_memory.update_from_dict(context)
            
            # 6. Analyze and decide next steps
            yield OrchestratorEvent(
                status=OrchestrationStatus.ANALYZING,
                message="🧠 Analyzing results...",
                data=results
            )
            
            # Check if phase is complete
            phase_eval = self._evaluate_phase(context)
            
            if phase_eval.get("phase_complete"):
                yield OrchestratorEvent(
                    status=OrchestrationStatus.PHASE_COMPLETE,
                    message=f"✅ Phase {phase_eval['current_phase']} complete. Moving to Phase {phase_eval.get('next_phase', phase_eval['current_phase'] + 1)}",
                    data=phase_eval
                )
                
                # Update task for next phase
                task = self._generate_next_task(task, context, phase_eval)
        
        # Final completion
        if not self.cancelled:
            yield OrchestratorEvent(
                status=OrchestrationStatus.TASK_COMPLETE,
                message="🎯 Autonomous operation complete",
                data=self._generate_summary(context)
            )
    
    async def run_autonomous_async(self, task: str, context: Dict[str, Any] = None) -> AsyncGenerator[OrchestratorEvent, None]:
        """
        Async version of run_autonomous with real countdown.
        
        Yields events and waits for countdown between steps.
        """
        for event in self.run_autonomous(task, context):
            yield event
            
            # Wait during countdown
            if event.status == OrchestrationStatus.COUNTDOWN:
                for i in range(event.countdown, 0, -1):
                    if self.cancelled:
                        break
                    await asyncio.sleep(1)
    
    def cancel(self):
        """Cancel the orchestration."""
        self.cancelled = True
    
    def _extract_target(self, task: str) -> Optional[str]:
        """Extract domain/IP from task."""
        import re
        
        # Domain pattern
        domain_match = re.search(
            r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            task
        )
        if domain_match:
            return domain_match.group(0)
        
        # IP pattern
        ip_match = re.search(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            task
        )
        if ip_match:
            return ip_match.group(0)
        
        return None
    
    def _select_agent(self, task: str, context: Dict[str, Any]) -> 'BaseAgent':
        """Use LLM to select the best agent for current state."""
        return self.coordinator.route(task, context)
    
    def _execute_plan(self, agent, plan: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tools from plan."""
        results = {
            "tools_run": [],
            "outputs": {},
            "findings": []
        }
        
        tools = plan.get("tools", [])
        commands = plan.get("commands", {})
        
        # Get targets from context
        targets = self._get_execution_targets(context)
        
        for tool in tools:
            command = commands.get(tool)
            
            # Get appropriate target
            target = targets[0] if targets else context.get("target_domain", "")
            
            params = {
                "domain": target,
                "target": target,
                "url": f"https://{target}" if target else "",
                "targets": targets[:10]  # For batch operations
            }
            
            logger.info(f"Agent '{agent.AGENT_NAME}' executing {tool}...", icon="")
            
            try:
                result = agent.execute_tool(tool, command, params)
                results["tools_run"].append(tool)
                results["outputs"][tool] = result
                
                # Parse findings from output
                if result.get("success") and result.get("output"):
                    parsed = self._parse_tool_output(tool, result["output"])
                    results["findings"].extend(parsed)
                    
            except Exception as e:
                results["outputs"][tool] = {"error": str(e)}
        
        return results
    
    def _get_execution_targets(self, context: Dict[str, Any]) -> List[str]:
        """Get all targets for execution from context."""
        targets = []
        
        # Main domain
        if context.get("target_domain"):
            targets.append(context["target_domain"])
        elif context.get("last_domain"):
            targets.append(context["last_domain"])
        
        # Discovered subdomains
        if context.get("subdomains"):
            targets.extend(context["subdomains"][:50])
        
        # Discovered IPs
        if context.get("ips"):
            targets.extend(context["ips"][:20])
        
        return list(set(targets))
    
    def _merge_results(self, context: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
        """Merge execution results into context."""
        # Add tools run
        context["tools_run"] = context.get("tools_run", []) + results.get("tools_run", [])
        
        # Parse and add findings
        for finding in results.get("findings", []):
            finding_type = finding.get("type")
            data = finding.get("data")
            
            if finding_type == "subdomain":
                if "subdomains" not in context:
                    context["subdomains"] = []
                if isinstance(data, list):
                    context["subdomains"].extend(data)
                else:
                    context["subdomains"].append(data)
                context["subdomains"] = list(set(context["subdomains"]))
                context["has_subdomains"] = True
                
            elif finding_type == "ip":
                if "ips" not in context:
                    context["ips"] = []
                if isinstance(data, list):
                    context["ips"].extend(data)
                else:
                    context["ips"].append(data)
                context["ips"] = list(set(context["ips"]))
                
            elif finding_type == "port":
                if "open_ports" not in context:
                    context["open_ports"] = []
                context["open_ports"].append(data)
                context["has_ports"] = True
                
            elif finding_type == "vulnerability":
                if "vulns_found" not in context:
                    context["vulns_found"] = []
                context["vulns_found"].append(data)
        
        return context
    
    def _parse_tool_output(self, tool: str, output: str) -> List[Dict]:
        """Parse tool output into findings."""
        findings = []
        
        # Simple parsing - each line might be a finding
        lines = output.strip().split('\n')
        
        if tool in ["subfinder", "amass", "assetfinder", "bbot"]:
            # Subdomain tools
            for line in lines:
                line = line.strip()
                if line and '.' in line and not line.startswith('#'):
                    findings.append({"type": "subdomain", "data": line})
                    
        elif tool in ["nmap", "masscan", "rustscan"]:
            # Port scanners
            import re
            for line in lines:
                # Match patterns like "80/tcp open http"
                match = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', line)
                if match:
                    findings.append({
                        "type": "port",
                        "data": {
                            "port": int(match.group(1)),
                            "protocol": match.group(2),
                            "service": match.group(3)
                        }
                    })
        
        return findings
    
    def _evaluate_phase(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate if current phase is complete."""
        from app.agent.core import get_phase_manager
        
        pm = get_phase_manager()
        return pm.evaluate_phase_with_llm(context)
    
    def _generate_next_task(self, original_task: str, context: Dict[str, Any], phase_eval: Dict[str, Any]) -> str:
        """Generate task for next phase based on results."""
        target = context.get("target_domain", "target")
        next_phase = phase_eval.get("next_phase", 2)
        suggested_tools = phase_eval.get("suggested_tools", [])
        
        phase_tasks = {
            2: f"Scan ports and services on {target} and discovered subdomains",
            3: f"Find vulnerabilities on {target} services",
            4: f"Exploit vulnerabilities found on {target}",
            5: f"Perform post-exploitation on {target}",
            6: f"Generate report for {target}"
        }
        
        task = phase_tasks.get(next_phase, original_task)
        
        if suggested_tools:
            task += f" using {', '.join(suggested_tools[:3])}"
        
        return task
    
    def _is_task_complete(self, context: Dict[str, Any]) -> bool:
        """Determine if the overall task is complete."""
        import json
        import re
        
        # Quick checks
        if context.get("report_generated"):
            return True
        if context.get("shell_obtained") and context.get("privesc_done"):
            return True
        
        # Ask LLM for complex cases
        target = context.get("target_domain", "unknown")
        subdomain_count = len(context.get("subdomains", []))
        port_count = len(context.get("open_ports", []))
        vuln_count = len(context.get("vulns_found", []))
        tools_run = context.get("tools_run", [])
        
        # If very little has been done, continue
        if len(tools_run) < 3:
            return False
        
        prompt = f"""Is this pentest task complete enough to stop?

Target: {target}
Subdomains found: {subdomain_count}
Open ports: {port_count}
Vulnerabilities: {vuln_count}
Tools run: {', '.join(tools_run[-10:])}

Return JSON: {{"complete": true/false, "reason": "brief explanation"}}"""

        try:
            response = self.llm.generate(prompt, timeout=20, stream=False)
            match = re.search(r'\{[^{}]*\}', response)
            if match:
                data = json.loads(match.group())
                return data.get("complete", False)
        except Exception:
            pass
        
        return False
    
    def _generate_summary(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final summary of the operation."""
        return {
            "target": context.get("target_domain", "unknown"),
            "subdomains_found": len(context.get("subdomains", [])),
            "ips_found": len(context.get("ips", [])),
            "open_ports": len(context.get("open_ports", [])),
            "vulnerabilities": len(context.get("vulns_found", [])),
            "tools_used": list(set(context.get("tools_run", []))),
            "iterations": self.iteration_count,
            "runtime_seconds": time.time() - self.start_time if self.start_time else 0
        }
    
    def _format_plan(self, plan: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Format plan for display."""
        from app.agent.core import get_phase_manager, PHASE_NAMES
        
        pm = get_phase_manager()
        phase = pm.get_current_phase(context)
        phase_name = PHASE_NAMES.get(phase, f"Phase {phase}")
        
        agent = plan.get("agent", "unknown")
        tools = plan.get("tools", [])
        target = context.get("target_domain", "unknown")
        
        # Get target count
        targets = self._get_execution_targets(context)
        target_info = f"{target}"
        if len(targets) > 1:
            target_info += f" (+{len(targets)-1} more)"
        
        lines = [
            f"",
            f"📋 {phase_name}",
            f"   Agent: {agent}",
            f"   Tools: {', '.join(tools)}",
            f"   Targets: {target_info}",
            f""
        ]
        
        return "\n".join(lines)


# Singleton
_orchestrator: Optional[AutonomousOrchestrator] = None


def get_orchestrator() -> AutonomousOrchestrator:
    """Get or create the orchestrator singleton."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AutonomousOrchestrator()
    return _orchestrator


def reset_orchestrator():
    """Reset the orchestrator (for new engagement)."""
    global _orchestrator
    _orchestrator = AutonomousOrchestrator()
