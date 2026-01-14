"""
Checklist Manager - Task breakdown and tracking
===============================================

Manages checklist tasks for complex security operations.
Breaks down user requests into actionable tasks with dependencies.
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class TaskStatus(str, Enum):
    """Task status enumeration."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Task:
    """Represents a single task in the checklist."""
    id: str
    description: str
    phase: int  # PTES phase (1-6)
    required_tools: List[str] = field(default_factory=list)  # Suggested tools
    dependencies: List[str] = field(default_factory=list)  # Task IDs that must complete first
    status: str = TaskStatus.PENDING.value
    results: Dict[str, Any] = field(default_factory=dict)  # Tool execution results
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for serialization."""
        return {
            "id": self.id,
            "description": self.description,
            "phase": self.phase,
            "required_tools": self.required_tools,
            "dependencies": self.dependencies,
            "status": self.status,
            "results": self.results,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        """Create task from dictionary."""
        task = cls(
            id=data["id"],
            description=data["description"],
            phase=data.get("phase", 1),
            required_tools=data.get("required_tools", []),
            dependencies=data.get("dependencies", []),
            status=data.get("status", TaskStatus.PENDING.value),
            results=data.get("results", {}),
            error=data.get("error")
        )
        if data.get("created_at"):
            task.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("completed_at"):
            task.completed_at = datetime.fromisoformat(data["completed_at"])
        return task


class ChecklistManager:
    """Manages checklist tasks for security operations."""
    
    def __init__(self):
        self.checklists: Dict[str, List[Task]] = {}  # session_id -> tasks
    
    def create_checklist(self, user_prompt: str, context: Dict[str, Any], session_id: str = "default") -> List[Task]:
        """
        Create a checklist from user prompt and context.
        
        This is a placeholder - actual breakdown will be done by task_breakdown_tool using LLM.
        """
        # This will be populated by task_breakdown_tool
        tasks = []
        self.checklists[session_id] = tasks
        return tasks
    
    def add_task(self, task: Task, session_id: str = "default"):
        """Add a task to checklist."""
        if session_id not in self.checklists:
            self.checklists[session_id] = []
        self.checklists[session_id].append(task)
    
    def get_checklist(self, session_id: str = "default") -> List[Task]:
        """Get checklist for session."""
        return self.checklists.get(session_id, [])
    
    def get_next_task(self, session_id: str = "default") -> Optional[Task]:
        """
        Get next available task (pending, no incomplete dependencies).
        
        Returns:
            Next task to execute, or None if all tasks are done or blocked.
        """
        checklist = self.get_checklist(session_id)
        if not checklist:
            return None
        
        # Find tasks that are pending and have all dependencies completed
        for task in checklist:
            if task.status == TaskStatus.PENDING.value:
                # Check if all dependencies are completed
                if self._dependencies_complete(task, checklist):
                    return task
        
        return None
    
    def _dependencies_complete(self, task: Task, checklist: List[Task]) -> bool:
        """Check if all dependencies of a task are completed."""
        if not task.dependencies:
            return True
        
        task_dict = {t.id: t for t in checklist}
        for dep_id in task.dependencies:
            dep_task = task_dict.get(dep_id)
            if not dep_task:
                return False  # Dependency not found
            if dep_task.status != TaskStatus.COMPLETED.value:
                return False  # Dependency not completed
        
        return True
    
    def mark_in_progress(self, task_id: str, session_id: str = "default") -> bool:
        """Mark task as in progress."""
        checklist = self.get_checklist(session_id)
        for task in checklist:
            if task.id == task_id:
                task.status = TaskStatus.IN_PROGRESS.value
                return True
        return False
    
    def mark_completed(self, task_id: str, results: Dict[str, Any], session_id: str = "default") -> bool:
        """Mark task as completed with results."""
        checklist = self.get_checklist(session_id)
        for task in checklist:
            if task.id == task_id:
                task.status = TaskStatus.COMPLETED.value
                task.results = results
                task.completed_at = datetime.now()
                return True
        return False
    
    def mark_failed(self, task_id: str, error: str, session_id: str = "default") -> bool:
        """Mark task as failed."""
        checklist = self.get_checklist(session_id)
        for task in checklist:
            if task.id == task_id:
                task.status = TaskStatus.FAILED.value
                task.error = error
                task.completed_at = datetime.now()
                return True
        return False
    
    def is_complete(self, session_id: str = "default") -> bool:
        """Check if all tasks in checklist are completed or failed."""
        checklist = self.get_checklist(session_id)
        if not checklist:
            return False
        
        for task in checklist:
            if task.status not in [TaskStatus.COMPLETED.value, TaskStatus.FAILED.value, TaskStatus.SKIPPED.value]:
                return False
        
        return True
    
    def get_progress(self, session_id: str = "default") -> Dict[str, Any]:
        """Get progress statistics for checklist."""
        checklist = self.get_checklist(session_id)
        if not checklist:
            return {
                "total": 0,
                "completed": 0,
                "failed": 0,
                "pending": 0,
                "in_progress": 0,
                "percentage": 0.0
            }
        
        total = len(checklist)
        completed = sum(1 for t in checklist if t.status == TaskStatus.COMPLETED.value)
        failed = sum(1 for t in checklist if t.status == TaskStatus.FAILED.value)
        pending = sum(1 for t in checklist if t.status == TaskStatus.PENDING.value)
        in_progress = sum(1 for t in checklist if t.status == TaskStatus.IN_PROGRESS.value)
        
        percentage = (completed / total * 100) if total > 0 else 0.0
        
        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "in_progress": in_progress,
            "percentage": round(percentage, 1)
        }
    
    def get_task_by_id(self, task_id: str, session_id: str = "default") -> Optional[Task]:
        """Get task by ID."""
        checklist = self.get_checklist(session_id)
        for task in checklist:
            if task.id == task_id:
                return task
        return None
    
    def to_dict(self, session_id: str = "default") -> List[Dict[str, Any]]:
        """Convert checklist to list of dictionaries for serialization."""
        checklist = self.get_checklist(session_id)
        return [task.to_dict() for task in checklist]
    
    def from_dict(self, data: List[Dict[str, Any]], session_id: str = "default"):
        """Load checklist from list of dictionaries."""
        tasks = [Task.from_dict(t) for t in data]
        self.checklists[session_id] = tasks


# Singleton instance
_checklist_manager: Optional[ChecklistManager] = None


def get_checklist_manager() -> ChecklistManager:
    """Get singleton checklist manager instance."""
    global _checklist_manager
    if _checklist_manager is None:
        _checklist_manager = ChecklistManager()
    return _checklist_manager
