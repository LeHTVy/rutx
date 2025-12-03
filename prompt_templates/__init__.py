"""
Prompts Package - Template-Based Prompt Management

This package contains:
- prompt_manager.py: Template engine with {{VAR}} and @include() support
- *.txt: Template files for each phase
- shared/*.txt: Reusable prompt components
"""

from .prompt_manager import (
    PromptManager,
    load_prompt,
    save_prompt_snapshot,
    get_prompt_manager
)

__all__ = [
    'PromptManager',
    'load_prompt',
    'save_prompt_snapshot',
    'get_prompt_manager'
]
