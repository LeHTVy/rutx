"""
Prompt Loader - Load prompts from .md files
===========================================

Centralized prompt loading for all agents.
Prompts are stored in app/agent/prompts/*.md
"""
from pathlib import Path
from typing import Dict, Any, Optional
import os


from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from pathlib import Path
import os
import re

# Directory containing prompt files
PROMPTS_DIR = Path(__file__).parent / "prompts"


@dataclass
class RolePrompt:
    """Parsed role prompt specificiation"""
    name: str
    description: str = ""
    system_prompt: str = ""
    user_prompt_template: str = "{query}"
    allowed_tools: List[str] = field(default_factory=list)


class PromptLoader:
    """Loads and manages prompts from file system."""
    
    def __init__(self, prompts_dir: Path = PROMPTS_DIR):
        self.prompts_dir = prompts_dir
        
    def list_prompts(self) -> List[str]:
        """List all available prompt files."""
        if not self.prompts_dir.exists():
            return []
        return [f.stem for f in self.prompts_dir.glob("*.md")]

    def list_roles(self) -> List[str]:
        """List all available roles (same as prompts for now)."""
        return self.list_prompts()
        
    def load_prompt(self, name: str) -> str:
        """Load raw prompt text."""
        prompt_path = self.prompts_dir / f"{name}.md"
        if not prompt_path.exists():
            role_path = self.prompts_dir / "roles" / f"{name}.md"
            if role_path.exists():
                prompt_path = role_path
            else:
                return ""
        
        try:
            with open(prompt_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""

    def load_role(self, role_name: str) -> Optional[RolePrompt]:
        """
        Load a role prompt. 
        For now, treats the .md file content as the system prompt.
        Future: parse frontmatter for metadata.
        """
        content = self.load_prompt(role_name)
        if not content:
            return None
            
        return RolePrompt(
            name=role_name,
            description=f"Role for {role_name}",
            system_prompt=content,
            user_prompt_template="{query}",
            allowed_tools=[] # Default to all or none, managed by role config
        )

    def format_prompt(self, template: str, context: Optional[Dict] = None) -> str:
        """Format a prompt string with context."""
        if context is None:
            context = {}
        try:
            return template.format(**context)
        except KeyError:
            for key, value in context.items():
                template = template.replace(f"{{{key}}}", str(value))
            return template
            
    def reload(self, name: str = None):
        """Clear cache (noop for now as we read from disk)."""
        pass


# Singleton instance
_loader: Optional[PromptLoader] = None

def get_prompt_loader() -> PromptLoader:
    """Get singleton PromptLoader instance."""
    global _loader
    if _loader is None:
        _loader = PromptLoader()
    return _loader


def load_prompt(name: str) -> str:
    """Legacy helper function."""
    return get_prompt_loader().load_prompt(name)

def format_prompt(name: str, **kwargs) -> str:
    """Legacy helper function."""
    template = load_prompt(name)
    return get_prompt_loader().format_prompt(template, kwargs)

def list_prompts() -> list:
    """Legacy helper function."""
    return get_prompt_loader().list_prompts()


