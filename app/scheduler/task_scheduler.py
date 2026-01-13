"""
Task Scheduler for SNODE
=========================

Manages scheduled, planned, and ad-hoc tasks.
"""
import asyncio
import json
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
import uuid

from .models import (
    TaskState,
    TaskType,
    TaskSchedule,
    TaskPlan,
    BaseTask,
    ScheduledTask,
    PlannedTask,
    AdHocTask,
)


SCHEDULER_FOLDER = "tmp/scheduler"


class TaskScheduler:
    """
    Task scheduler for SNODE.
    
    Manages:
    - Scheduled tasks (cron-based)
    - Planned tasks (future datetime)
    - Ad-hoc tasks (one-time)
    """
    
    _instance: Optional["TaskScheduler"] = None
    _lock = threading.RLock()
    
    def __init__(self, tasks_file: str = None):
        self.tasks_file = tasks_file or str(Path.home() / ".snode" / "scheduler" / "tasks.json")
        self.tasks: List[Union[ScheduledTask, PlannedTask, AdHocTask]] = []
        self._running = False
        self._check_interval = 60.0  # Check every 60 seconds
        
        # Ensure directory exists
        Path(self.tasks_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing tasks
        self.load()
    
    @classmethod
    def get(cls) -> "TaskScheduler":
        """Get singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def load(self):
        """Load tasks from file."""
        try:
            if Path(self.tasks_file).exists():
                with open(self.tasks_file, 'r') as f:
                    data = json.load(f)
                    self.tasks = []
                    for task_data in data.get("tasks", []):
                        task = self._deserialize_task(task_data)
                        if task:
                            self.tasks.append(task)
        except Exception as e:
            print(f"  ⚠️ Failed to load tasks: {e}")
            self.tasks = []
    
    def save(self):
        """Save tasks to file."""
        try:
            data = {
                "tasks": [self._serialize_task(task) for task in self.tasks]
            }
            with open(self.tasks_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"  ⚠️ Failed to save tasks: {e}")
    
    def _serialize_task(self, task: Union[ScheduledTask, PlannedTask, AdHocTask]) -> dict:
        """Serialize task to dict."""
        data = task.model_dump()
        data["type"] = task.type.value
        return data
    
    def _deserialize_task(self, data: dict) -> Optional[Union[ScheduledTask, PlannedTask, AdHocTask]]:
        """Deserialize task from dict."""
        task_type = data.get("type")
        
        if task_type == TaskType.SCHEDULED.value:
            return ScheduledTask(**data)
        elif task_type == TaskType.PLANNED.value:
            return PlannedTask(**data)
        elif task_type == TaskType.AD_HOC.value:
            return AdHocTask(**data)
        else:
            return None
    
    # ==================== Task Management ====================
    
    def add_task(self, task: Union[ScheduledTask, PlannedTask, AdHocTask]) -> str:
        """Add a new task."""
        with self._lock:
            self.tasks.append(task)
            self.save()
            return task.uuid
    
    def get_task(self, task_uuid: str) -> Optional[Union[ScheduledTask, PlannedTask, AdHocTask]]:
        """Get task by UUID."""
        with self._lock:
            return next((t for t in self.tasks if t.uuid == task_uuid), None)
    
    def get_tasks(self) -> List[Union[ScheduledTask, PlannedTask, AdHocTask]]:
        """Get all tasks."""
        with self._lock:
            return self.tasks.copy()
    
    def remove_task(self, task_uuid: str) -> bool:
        """Remove a task."""
        with self._lock:
            self.tasks = [t for t in self.tasks if t.uuid != task_uuid]
            self.save()
            return True
    
    def update_task(
        self,
        task_uuid: str,
        **kwargs
    ) -> Optional[Union[ScheduledTask, PlannedTask, AdHocTask]]:
        """Update a task."""
        with self._lock:
            task = self.get_task(task_uuid)
            if task:
                for key, value in kwargs.items():
                    if hasattr(task, key):
                        setattr(task, key, value)
                task.updated_at = datetime.now(timezone.utc)
                self.save()
            return task
    
    # ==================== Task Execution ====================
    
    async def run_task(self, task_uuid: str, context: Dict[str, Any] = None):
        """Run a task."""
        task = self.get_task(task_uuid)
        if not task:
            raise ValueError(f"Task not found: {task_uuid}")
        
        if task.state == TaskState.RUNNING:
            raise ValueError(f"Task already running: {task_uuid}")
        
        # Update state
        self.update_task(task_uuid, state=TaskState.RUNNING, last_run=datetime.now(timezone.utc))
        
        try:
            # Execute task via agent
            from app.agent.graph import create_langgraph_agent
            agent = create_langgraph_agent()
            
            # Run the task
            result = agent.run(task.prompt, context or {})
            if len(result) == 4:
                response, context, _, _ = result
            else:
                response, context, _ = result
            if len(result) == 4:
                response, _, _, _ = result
            else:
                response, _, _ = result
            
            # Update state
            self.update_task(
                task_uuid,
                state=TaskState.IDLE,
                last_result=response[:500]  # Truncate result
            )
            
        except Exception as e:
            # Update state to error
            self.update_task(
                task_uuid,
                state=TaskState.ERROR,
                last_result=f"ERROR: {str(e)}"
            )
            raise
    
    # ==================== Scheduled Task Checking ====================
    
    async def check_and_run_due_tasks(self):
        """Check for due tasks and run them."""
        with self._lock:
            due_tasks = []
            
            for task in self.tasks:
                if task.state != TaskState.IDLE:
                    continue
                
                # Check if task is due
                if isinstance(task, ScheduledTask):
                    if task.check_schedule(self._check_interval):
                        due_tasks.append(task)
                elif isinstance(task, PlannedTask):
                    if task.check_plan():
                        due_tasks.append(task)
            
            # Run due tasks
            for task in due_tasks:
                try:
                    await self.run_task(task.uuid)
                except Exception as e:
                    print(f"  ⚠️ Failed to run task {task.name}: {e}")
    
    def start_background_loop(self):
        """Start background task checking loop."""
        if self._running:
            return
        
        self._running = True
        
        async def loop():
            while self._running:
                try:
                    await self.check_and_run_due_tasks()
                except Exception as e:
                    print(f"  ⚠️ Task scheduler error: {e}")
                await asyncio.sleep(self._check_interval)
        
        # Run in background
        asyncio.create_task(loop())
    
    def stop_background_loop(self):
        """Stop background task checking loop."""
        self._running = False


# Singleton
_scheduler_instance = None

def get_task_scheduler() -> TaskScheduler:
    """Get or create task scheduler instance."""
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = TaskScheduler.get()
    return _scheduler_instance
