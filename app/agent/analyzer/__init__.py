"""
Prompt Analysis Module
=====================

Tái sử dụng code từ core/checklist_manager và tools/ để tạo prompt analysis layer.
Module này chứa:
- Checklist management (tái sử dụng từ core/)
- Task breakdown (tái sử dụng từ tools/)
- Target verification (tái sử dụng từ tools/)
- User prompt analyzer (mới - General Model analysis)
"""

# Tái sử dụng từ checklist_manager
from .checklist_manager import (
    ChecklistManager,
    get_checklist_manager,
    Task,
    TaskStatus,
)

# Tái sử dụng từ tools
from .task_breakdown_tool import TaskBreakdownTool
from .target_verification_tool import TargetVerificationTool

# File mới
from .user_prompt_analyzer import UserPromptAnalyzer, get_user_prompt_analyzer

__all__ = [
    # Checklist Management (tái sử dụng)
    "ChecklistManager",
    "get_checklist_manager",
    "Task",
    "TaskStatus",
    # Task Breakdown (tái sử dụng)
    "TaskBreakdownTool",
    # Target Verification (tái sử dụng)
    "TargetVerificationTool",
    # User Prompt Analyzer (mới)
    "UserPromptAnalyzer",
    "get_user_prompt_analyzer",
]
