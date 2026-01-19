"""
Checklist Planning Service

Service to handle checklist-based planning.
"""
from typing import Any, Dict, List, Optional, Tuple

from app.agent.analyzer.checklist_manager import get_checklist_manager, Task
from app.ui import get_logger

logger = get_logger()

def _get_session_id(context: Dict[str, Any]) -> str:
    """Get session_id from context with a safe default."""
    session_id = context.get("session_id")
    return session_id if isinstance(session_id, str) and session_id else "default"


def _get_checklist_list(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Return checklist as a list of dicts, or empty list if missing/invalid.

    Guardrail: some callers may accidentally set checklist to a non-list.
    """
    checklist = context.get("checklist", [])
    if checklist is None:
        return []
    if not isinstance(checklist, list):
        logger.warning("Checklist in context is not a list; ignoring invalid value")
        return []
    # Ensure items are dict-like (Task.from_dict expects dict)
    return [x for x in checklist if isinstance(x, dict)]


def get_next_task_from_checklist(context: Dict[str, Any]) -> Optional[Task]:
    """
    Get next available task from checklist.
    
    Args:
        context: Current context dictionary
        
    Returns:
        Next task to execute, or None if all tasks done/blocked
    """
    checklist = _get_checklist_list(context)
    if not checklist:
        return None
    
    checklist_manager = get_checklist_manager()
    session_id = _get_session_id(context)
    
    # Load checklist into manager if not already loaded
    if not checklist_manager.get_checklist(session_id):
        loaded = 0
        for task_data in checklist:
            try:
                task = Task.from_dict(task_data)
            except Exception as e:
                # Guardrail: don't crash planner if a single task is malformed
                logger.warning(f"Skipping invalid checklist task: {e}")
                continue
            checklist_manager.add_task(task, session_id)
            loaded += 1
        if loaded == 0:
            return None
    
    # Get next task from checklist
    next_task = checklist_manager.get_next_task(session_id)
    return next_task


def prepare_query_with_task(query: str, context: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Prepare query and context for checklist task execution.
    
    Args:
        query: Original query
        context: Current context
        
    Returns:
        (updated_query, updated_context)
    """
    if not isinstance(query, str):
        # Guardrail: keep behavior stable; just coerce to string
        query = str(query)

    next_task = get_next_task_from_checklist(context)
    
    if not next_task:
        # All tasks done or blocked
        checklist_manager = get_checklist_manager()
        session_id = _get_session_id(context)
        progress = checklist_manager.get_progress(session_id)
        
        if progress["completed"] == progress["total"]:
            logger.info(f"All checklist tasks completed ({progress['completed']}/{progress['total']})")
            context["checklist_complete"] = True
        else:
            logger.info(f"No available tasks (Progress: {progress['completed']}/{progress['total']})")
        
        return query, context
    
    # Mark task as in progress
    checklist_manager = get_checklist_manager()
    session_id = _get_session_id(context)
    checklist_manager.mark_in_progress(next_task.id, session_id)
    context["current_task_id"] = next_task.id
    
    # Update query to focus on current task
    updated_query = f"{query} - Task: {next_task.description}"
    
    # Add task's required tools as context (hint for planner)
    if next_task.required_tools:
        context["task_required_tools"] = next_task.required_tools
        context["task_phase"] = next_task.phase
    
    logger.info(f"Working on task: {next_task.description} (Phase {next_task.phase})")
    
    return updated_query, context


def get_task_required_tools(context: Dict[str, Any]) -> Optional[List[str]]:
    """
    Get required tools from current checklist task.
    
    Args:
        context: Current context
        
    Returns:
        List of required tools, or None if no task
    """
    current_task_id = context.get("current_task_id")
    if not current_task_id:
        return None
    
    checklist_manager = get_checklist_manager()
    session_id = _get_session_id(context)
    task = checklist_manager.get_task_by_id(current_task_id, session_id)
    
    if task:
        return task.required_tools
    
    return None
