"""
Prompt Loader - Load and parse Markdown prompt templates
=========================================================

Loads agent role prompts from .md files in prompts/roles/
Format follows NeuroSploit pattern with ## sections.
"""
import re
from pathlib import Path
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class RolePrompt:
    """Parsed prompt data for an agent role"""
    name: str
    system_prompt: str
    user_prompt_template: str
    allowed_tools: list
    description: str = ""


class PromptLoader:
    """
    Load and parse Markdown prompt templates for agent roles.
    
    Expected format:
    ```markdown
    # Agent Name
    
    ## Description
    Brief description of the agent's role.
    
    ## System Prompt
    You are an expert...
    
    ## User Prompt
    **Target:** {target_info}
    **Task:** {user_input}
    
    ## Allowed Tools
    - tool1
    - tool2
    ```
    """
    
    PROMPTS_DIR = Path(__file__).parent / "roles"
    
    def __init__(self, prompts_dir: Path = None):
        self.prompts_dir = prompts_dir or self.PROMPTS_DIR
        self._cache: Dict[str, RolePrompt] = {}
    
    def list_roles(self) -> list:
        """List all available role names from .md files"""
        if not self.prompts_dir.exists():
            return []
        return [f.stem for f in self.prompts_dir.glob("*.md")]
    
    def load_role(self, role_name: str) -> Optional[RolePrompt]:
        """Load a role prompt from its .md file"""
        # Check cache first
        if role_name in self._cache:
            return self._cache[role_name]
        
        filepath = self.prompts_dir / f"{role_name}.md"
        if not filepath.exists():
            return None
        
        content = filepath.read_text(encoding='utf-8')
        prompt = self._parse_markdown(role_name, content)
        
        # Cache it
        self._cache[role_name] = prompt
        return prompt
    
    def _parse_markdown(self, role_name: str, content: str) -> RolePrompt:
        """Parse markdown content into RolePrompt"""
        sections = {}
        current_section = None
        current_content = []
        
        for line in content.split('\n'):
            # Check for ## section headers
            if line.startswith('## '):
                # Save previous section
                if current_section:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = line[3:].strip().lower().replace(' ', '_')
                current_content = []
            elif line.startswith('# ') and not current_section:
                # Title line - extract agent name
                sections['title'] = line[2:].strip()
            else:
                current_content.append(line)
        
        # Save last section
        if current_section:
            sections[current_section] = '\n'.join(current_content).strip()
        
        # Parse allowed tools (list items with -)
        tools = []
        tools_text = sections.get('allowed_tools', '')
        for line in tools_text.split('\n'):
            line = line.strip()
            if line.startswith('- '):
                tools.append(line[2:].strip())
        
        return RolePrompt(
            name=sections.get('title', role_name),
            description=sections.get('description', ''),
            system_prompt=sections.get('system_prompt', ''),
            user_prompt_template=sections.get('user_prompt', ''),
            allowed_tools=tools
        )
    
    def format_prompt(self, template: str, context: Dict) -> str:
        """
        Format a prompt template with context variables.
        
        Safely handles missing keys by leaving placeholders intact.
        """
        # Use regex to find all {placeholder} patterns
        def replace_placeholder(match):
            key = match.group(1)
            if key in context:
                value = context[key]
                # Convert dicts/lists to JSON string
                if isinstance(value, (dict, list)):
                    import json
                    return json.dumps(value, indent=2)
                return str(value)
            return match.group(0)  # Keep original if not found
        
        return re.sub(r'\{(\w+)\}', replace_placeholder, template)
    
    def reload(self, role_name: str = None):
        """Clear cache and reload prompts"""
        if role_name:
            self._cache.pop(role_name, None)
        else:
            self._cache.clear()


# Singleton instance
_loader: Optional[PromptLoader] = None


def get_prompt_loader() -> PromptLoader:
    """Get singleton PromptLoader instance"""
    global _loader
    if _loader is None:
        _loader = PromptLoader()
    return _loader
