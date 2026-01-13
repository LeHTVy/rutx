"""
Task Models for SNODE Scheduler
================================
"""
import random
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Literal, Optional
from enum import Enum
from pydantic import BaseModel, Field
import pytz


class TaskState(str, Enum):
    """Task execution state."""
    IDLE = "idle"
    RUNNING = "running"
    DISABLED = "disabled"
    ERROR = "error"


class TaskType(str, Enum):
    """Task type."""
    AD_HOC = "adhoc"
    SCHEDULED = "scheduled"
    PLANNED = "planned"


class TaskSchedule(BaseModel):
    """Cron-based schedule for recurring tasks."""
    minute: str = "*"
    hour: str = "*"
    day: str = "*"
    month: str = "*"
    weekday: str = "*"
    timezone: str = "UTC"

    def to_crontab(self) -> str:
        """Convert to crontab format."""
        return f"{self.minute} {self.hour} {self.day} {self.month} {self.weekday}"


class TaskPlan(BaseModel):
    """Plan for future tasks with datetime list."""
    todo: list[datetime] = Field(default_factory=list)
    in_progress: Optional[datetime] = None
    done: list[datetime] = Field(default_factory=list)

    @classmethod
    def create(
        cls,
        todo: list[datetime] = None,
        in_progress: Optional[datetime] = None,
        done: list[datetime] = None
    ):
        """Create with timezone normalization."""
        if todo is None:
            todo = []
        if done is None:
            done = []

        # Normalize timezones
        for idx, dt in enumerate(todo):
            if dt.tzinfo is None:
                todo[idx] = pytz.timezone("UTC").localize(dt)
        if in_progress and in_progress.tzinfo is None:
            in_progress = pytz.timezone("UTC").localize(in_progress)
        for idx, dt in enumerate(done):
            if dt.tzinfo is None:
                done[idx] = pytz.timezone("UTC").localize(dt)

        return cls(todo=todo, in_progress=in_progress, done=done)

    def add_todo(self, launch_time: datetime):
        """Add a todo datetime."""
        if launch_time.tzinfo is None:
            launch_time = pytz.timezone("UTC").localize(launch_time)
        self.todo.append(launch_time)
        self.todo = sorted(self.todo)

    def set_in_progress(self, launch_time: datetime):
        """Move a todo to in_progress."""
        if launch_time.tzinfo is None:
            launch_time = pytz.timezone("UTC").localize(launch_time)
        if launch_time not in self.todo:
            raise ValueError(f"Launch time {launch_time} not in todo list")
        self.todo.remove(launch_time)
        self.todo = sorted(self.todo)
        self.in_progress = launch_time

    def set_done(self, launch_time: datetime):
        """Move in_progress to done."""
        if launch_time.tzinfo is None:
            launch_time = pytz.timezone("UTC").localize(launch_time)
        if launch_time != self.in_progress:
            raise ValueError(f"Launch time {launch_time} is not the same as in progress time {self.in_progress}")
        self.done.append(launch_time)
        self.in_progress = None


class BaseTask(BaseModel):
    """Base task model."""
    uuid: str = Field(default_factory=lambda: str(random.randint(1000000000000000000, 9999999999999999999)))
    name: str
    state: TaskState = TaskState.IDLE
    type: TaskType
    system_prompt: str = ""
    prompt: str
    attachments: list[str] = Field(default_factory=list)
    context_id: Optional[str] = None
    last_run: Optional[datetime] = None
    last_result: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        use_enum_values = True


class AdHocTask(BaseTask):
    """One-time task."""
    type: Literal[TaskType.AD_HOC] = TaskType.AD_HOC
    token: str = Field(default_factory=lambda: str(random.randint(1000000000000000000, 9999999999999999999)))

    @classmethod
    def create(
        cls,
        name: str,
        prompt: str,
        system_prompt: str = "",
        attachments: list[str] = None,
        context_id: str = None,
        token: str = None
    ):
        """Create an ad-hoc task."""
        return cls(
            name=name,
            prompt=prompt,
            system_prompt=system_prompt,
            attachments=attachments or [],
            context_id=context_id,
            token=token or str(random.randint(1000000000000000000, 9999999999999999999))
        )


class ScheduledTask(BaseTask):
    """Recurring task with cron schedule."""
    type: Literal[TaskType.SCHEDULED] = TaskType.SCHEDULED
    schedule: TaskSchedule

    @classmethod
    def create(
        cls,
        name: str,
        prompt: str,
        schedule: TaskSchedule,
        system_prompt: str = "",
        attachments: list[str] = None,
        context_id: str = None,
        timezone: str = None
    ):
        """Create a scheduled task."""
        if timezone:
            schedule.timezone = timezone
        return cls(
            name=name,
            prompt=prompt,
            system_prompt=system_prompt,
            schedule=schedule,
            attachments=attachments or [],
            context_id=context_id
        )

    def check_schedule(self, frequency_seconds: float = 60.0) -> bool:
        """Check if task should run now based on schedule."""
        try:
            from crontab import CronTab

            crontab = CronTab(crontab=self.schedule.to_crontab())
            task_timezone = pytz.timezone(self.schedule.timezone or "UTC")

            # Get reference time (now - frequency_seconds to avoid missing runs)
            reference_time = datetime.now(task_timezone) - timedelta(seconds=frequency_seconds)

            # Check if schedule matches
            return crontab.test(reference_time)
        except Exception as e:
            print(f"  ⚠️ Schedule check error: {e}")
            return False


class PlannedTask(BaseTask):
    """Future task with specific datetime."""
    type: Literal[TaskType.PLANNED] = TaskType.PLANNED
    plan: TaskPlan

    @classmethod
    def create(
        cls,
        name: str,
        prompt: str,
        launch_time: datetime,
        system_prompt: str = "",
        attachments: list[str] = None,
        context_id: str = None
    ):
        """Create a planned task."""
        plan = TaskPlan.create(todo=[launch_time])
        return cls(
            name=name,
            prompt=prompt,
            system_prompt=system_prompt,
            plan=plan,
            attachments=attachments or [],
            context_id=context_id
        )

    def check_plan(self) -> bool:
        """Check if task should run now based on plan."""
        if not self.plan.todo:
            return False

        now = datetime.now(timezone.utc)
        # Check if any todo time has passed
        for launch_time in self.plan.todo:
            if launch_time <= now:
                return True
        return False
