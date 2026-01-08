"""
Agent Role Manager
==================

Manages agent roles and their configurations.
Integrates with PromptLoader to get role-specific prompts.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path

from app.prompts import get_prompt_loader, RolePrompt


@dataclass
class AgentRole:
    """Configuration for an agent role"""
    name: str
    description: str
    system_prompt: str
    user_prompt_template: str
    tools_allowed: List[str]
    enabled: bool = True
    
    @classmethod
    def from_role_prompt(cls, prompt: RolePrompt, enabled: bool = True) -> 'AgentRole':
        """Create AgentRole from RolePrompt"""
        return cls(
            name=prompt.name,
            description=prompt.description,
            system_prompt=prompt.system_prompt,
            user_prompt_template=prompt.user_prompt_template,
            tools_allowed=prompt.allowed_tools,
            enabled=enabled
        )


@dataclass 
class RoleConfig:
    """Role configuration loaded from config"""
    enabled: bool = True
    tools_override: List[str] = field(default_factory=list)
    llm_profile: str = "default"


class RoleManager:
    """
    Manages agent roles and their prompts.
    
    Roles are defined in markdown files under app/prompts/roles/
    This manager loads and caches them for use by specialized agents.
    """
    
    # Default role configurations
    DEFAULT_CONFIGS: Dict[str, RoleConfig] = {
        "recon_agent": RoleConfig(enabled=True),
        "web_pentest_agent": RoleConfig(enabled=True),
        "vuln_hunter_agent": RoleConfig(enabled=True),
        "network_analyst_agent": RoleConfig(enabled=True),
        "exploit_expert_agent": RoleConfig(enabled=True),
    }
    
    def __init__(self, config: Dict = None):
        self.loader = get_prompt_loader()
        self.config = config or {}
        self._roles: Dict[str, AgentRole] = {}
    
    def list_roles(self) -> List[str]:
        """List all available role names"""
        return self.loader.list_roles()
    
    def list_enabled_roles(self) -> List[str]:
        """List only enabled roles"""
        enabled = []
        for name in self.list_roles():
            role_config = self._get_role_config(name)
            if role_config.enabled:
                enabled.append(name)
        return enabled
    
    def _get_role_config(self, role_name: str) -> RoleConfig:
        """Get role configuration, with defaults"""
        if role_name in self.config:
            cfg = self.config[role_name]
            return RoleConfig(
                enabled=cfg.get('enabled', True),
                tools_override=cfg.get('tools_override', []),
                llm_profile=cfg.get('llm_profile', 'default')
            )
        return self.DEFAULT_CONFIGS.get(role_name, RoleConfig())
    
    def load_role(self, role_name: str) -> Optional[AgentRole]:
        """Load a specific agent role by name"""
        # Check cache
        if role_name in self._roles:
            return self._roles[role_name]
        
        # Load from prompt file
        prompt = self.loader.load_role(role_name)
        if not prompt:
            return None
        
        role_config = self._get_role_config(role_name)
        role = AgentRole.from_role_prompt(prompt, enabled=role_config.enabled)
        
        # Apply tool overrides if configured
        if role_config.tools_override:
            role.tools_allowed = role_config.tools_override
        
        # Cache and return
        self._roles[role_name] = role
        return role
    
    def get_role_info(self, role_name: str) -> Optional[Dict]:
        """Get information about a role without full loading"""
        role = self.load_role(role_name)
        if not role:
            return None
        return {
            "name": role.name,
            "description": role.description,
            "tools": role.tools_allowed,
            "enabled": role.enabled
        }
    
    def format_user_prompt(self, role_name: str, context: Dict) -> Optional[str]:
        """Format the user prompt template for a role with context"""
        role = self.load_role(role_name)
        if not role:
            return None
        return self.loader.format_prompt(role.user_prompt_template, context)
    
    def reload(self, role_name: str = None):
        """Reload role(s) from disk"""
        if role_name:
            self._roles.pop(role_name, None)
            self.loader.reload(role_name)
        else:
            self._roles.clear()
            self.loader.reload()


# Singleton instance
_manager: Optional[RoleManager] = None


def get_role_manager(config: Dict = None) -> RoleManager:
    """Get singleton RoleManager instance"""
    global _manager
    if _manager is None:
        _manager = RoleManager(config)
    return _manager
