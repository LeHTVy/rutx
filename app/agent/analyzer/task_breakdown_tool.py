"""
Task Breakdown Tool

Extracts and encapsulates logic for breaking down user requests into checklist tasks.
Uses general model to analyze user prompt and create structured task checklist.
"""
import json
import re
from typing import Dict, Any, Optional, List
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient
from app.agent.analyzer.checklist_manager import get_checklist_manager, Task, TaskStatus
from app.ui import get_logger

logger = get_logger()


class TaskBreakdownTool(AgentTool):
    """Tool for breaking down user requests into checklist tasks."""
    
    def execute(self, query: str = None, context: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """
        Break down user request into checklist tasks.
        
        Args:
            query: User query string
            context: Current context dictionary
            
        Returns:
            Dictionary with checklist and context updates
        """
        if query is None and self.state:
            query = self.state.get("query", "")
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        
        # Check if checklist already exists (don't recreate)
        existing_checklist = context.get("checklist", [])
        if existing_checklist:
            logger.info("Checklist already exists, skipping breakdown")
            return {
                "checklist": existing_checklist,
                "context": context
            }
        
        # Build context summary
        context_summary = self._build_context_summary(context)
        
        # Use general model for task breakdown
        from app.llm.config import get_general_model
        general_model = get_general_model()
        llm = OllamaClient(model="general") if general_model else OllamaClient()
        
        # Load prompt
        from app.agent.prompt_loader import format_prompt
        prompt = format_prompt(
            "task_breakdown",
            query=query,
            context_summary=context_summary if context_summary else "No prior context"
        )
        
        logger.info("Breaking down request into tasks...", icon="")
        
        try:
            # Generate breakdown
            response = llm.generate(prompt, timeout=30, stream=False)
            
            # Parse JSON response
            tasks = self._parse_breakdown_response(response)
            
            if not tasks:
                logger.warning("Failed to parse task breakdown, creating minimal checklist")
                # Fallback: create a simple task
                tasks = [{
                    "id": "task_1",
                    "description": f"Execute security testing for: {query}",
                    "phase": 1,
                    "required_tools": [],
                    "dependencies": []
                }]
            
            # Convert to Task objects
            checklist_manager = get_checklist_manager()
            session_id = context.get("session_id", "default")
            
            task_objects = []
            for task_data in tasks:
                task = Task(
                    id=task_data.get("id", f"task_{len(task_objects) + 1}"),
                    description=task_data.get("description", ""),
                    phase=task_data.get("phase", 1),
                    required_tools=task_data.get("required_tools", []),
                    dependencies=task_data.get("dependencies", [])
                )
                task_objects.append(task)
                checklist_manager.add_task(task, session_id)
            
            # Store in context
            context["checklist"] = [t.to_dict() for t in task_objects]
            context["checklist_complete"] = False
            context["current_task_id"] = None
            
            logger.info(f"Created {len(task_objects)} tasks", icon="")
            
            # Show checklist summary
            for i, task in enumerate(task_objects, 1):
                deps_str = f" (depends on: {', '.join(task.dependencies)})" if task.dependencies else ""
                logger.info(f"[{i}] Phase {task.phase}: {task.description}{deps_str}", icon="")
            
            return {
                "checklist": [t.to_dict() for t in task_objects],
                "context": context
            }
            
        except Exception as e:
            logger.error(f"Task breakdown failed: {e}")
            # Fallback: create minimal task
            fallback_task = Task(
                id="task_1",
                description=f"Execute: {query}",
                phase=1,
                required_tools=[],
                dependencies=[]
            )
            checklist_manager = get_checklist_manager()
            session_id = context.get("session_id", "default")
            checklist_manager.add_task(fallback_task, session_id)
            
            context["checklist"] = [fallback_task.to_dict()]
            context["checklist_complete"] = False
            
            return {
                "checklist": [fallback_task.to_dict()],
                "context": context
            }
    
    def _build_context_summary(self, context: Dict[str, Any]) -> str:
        """Build context summary for prompt."""
        summary_parts = []
        
        if context.get("tools_run"):
            summary_parts.append(f"Tools already run: {', '.join(context.get('tools_run', []))}")
        
        if context.get("subdomain_count"):
            summary_parts.append(f"Subdomains found: {context.get('subdomain_count')}")
        
        if context.get("has_ports"):
            summary_parts.append("Port scan completed")
        
        if context.get("detected_tech"):
            summary_parts.append(f"Technologies detected: {', '.join(context.get('detected_tech', [])[:5])}")
        
        if context.get("target_domain") or context.get("last_domain"):
            target = context.get("target_domain") or context.get("last_domain")
            summary_parts.append(f"Target: {target}")
        
        return "\n".join(summary_parts) if summary_parts else "No prior context"
    
    def _parse_breakdown_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse JSON response from LLM."""
        # Try to extract JSON from response
        json_match = re.search(r'\{[^{}]*"tasks"[^{}]*\[.*?\]\s*\}', response, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group())
                return data.get("tasks", [])
            except json.JSONDecodeError:
                pass
        
        # Try to find JSON array directly
        array_match = re.search(r'\[.*?\]', response, re.DOTALL)
        if array_match:
            try:
                tasks = json.loads(array_match.group())
                if isinstance(tasks, list):
                    return tasks
            except json.JSONDecodeError:
                pass
        
        # Try to parse entire response as JSON
        try:
            data = json.loads(response.strip())
            if isinstance(data, dict) and "tasks" in data:
                return data["tasks"]
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
        
        return []
