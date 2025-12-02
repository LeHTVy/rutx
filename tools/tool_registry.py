"""
Tool Registry for LLM-Autonomous Security Scanning

This module provides a structured registry of all available security tools
that the LLM can autonomously select and chain together.

Inspired by OSINT tool aggregation patterns, but with LLM-driven orchestration.
"""

from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass, field


class ToolCategory(Enum):
    """Categories of security tools."""
    NETWORK = "network"                    # IP, port scanning, network recon
    DOMAIN = "domain"                      # DNS, WHOIS, domain intelligence
    SUBDOMAIN = "subdomain"                # Subdomain enumeration
    WEB = "web"                            # Web app scanning, crawling
    VULNERABILITY = "vulnerability"        # Vulnerability scanning, CVE checking
    THREAT_INTEL = "threat_intelligence"   # Threat intelligence, reputation
    EMAIL = "email"                        # Email verification, OSINT
    PHONE = "phone"                        # Phone number intelligence
    USERNAME = "username"                  # Username enumeration
    SOCIAL = "social"                      # Social media OSINT
    BREACH = "breach"                      # Data breach checking
    MALWARE = "malware"                    # Malware scanning, threat detection
    CRYPTO = "crypto"                      # Cryptocurrency, blockchain
    GEOLOCATION = "geolocation"            # IP geolocation, travel risk
    OSINT = "osint"                        # General OSINT aggregation


class InputType(Enum):
    """Types of input that tools can accept."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    HASH = "hash"
    CVE = "cve"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    PERSON_NAME = "person_name"
    ORGANIZATION = "organization"
    FILE_PATH = "file_path"
    TEXT = "text"
    ANY = "any"


@dataclass
class ToolParameter:
    """Defines a parameter for a tool."""
    name: str
    type: InputType
    description: str
    required: bool = True
    default: Any = None
    examples: List[str] = field(default_factory=list)


@dataclass
class ToolOutput:
    """Defines the output format of a tool."""
    format: str  # "json", "text", "xml", etc.
    schema: Dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass
class ToolMetadata:
    """
    Metadata about a security tool.

    This structure allows the LLM to understand:
    - What the tool does
    - When to use it
    - What inputs it needs
    - What outputs it provides
    - How it chains with other tools
    """
    # Basic info
    name: str
    function_name: str  # Actual Python function to call
    description: str
    category: ToolCategory

    # Input/Output
    parameters: List[ToolParameter]
    output: ToolOutput

    # LLM selection hints
    use_cases: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)  # Keywords that suggest this tool
    prerequisites: List[str] = field(default_factory=list)  # Tools that should run first
    chains_to: List[str] = field(default_factory=list)  # Tools that can follow this one

    # Execution metadata
    timeout: int = 120  # seconds
    requires_api_key: bool = False
    api_key_env: str = ""
    rate_limited: bool = False
    max_parallel: int = 1

    # Cost/Risk
    is_intrusive: bool = False  # Does it actively scan/probe?
    is_safe: bool = True  # Safe to run without authorization?
    cost_estimate: str = "free"  # "free", "low", "medium", "high"

    # Status
    enabled: bool = True
    deprecated: bool = False


class ToolRegistry:
    """
    Central registry of all available security tools.

    The LLM queries this registry to discover tools and their capabilities.
    """

    def __init__(self):
        self._tools: Dict[str, ToolMetadata] = {}
        self._categories: Dict[ToolCategory, List[str]] = {}
        self._by_input_type: Dict[InputType, List[str]] = {}
        self._function_map: Dict[str, Callable] = {}

    def register(self, metadata: ToolMetadata, function: Callable):
        """
        Register a new tool.

        Args:
            metadata: Tool metadata
            function: Python function to execute the tool
        """
        self._tools[metadata.name] = metadata
        self._function_map[metadata.function_name] = function

        # Index by category
        if metadata.category not in self._categories:
            self._categories[metadata.category] = []
        self._categories[metadata.category].append(metadata.name)

        # Index by input types
        for param in metadata.parameters:
            if param.type not in self._by_input_type:
                self._by_input_type[param.type] = []
            if metadata.name not in self._by_input_type[param.type]:
                self._by_input_type[param.type].append(metadata.name)

    def get_tool(self, name: str) -> Optional[ToolMetadata]:
        """Get tool metadata by name."""
        return self._tools.get(name)

    def get_function(self, function_name: str) -> Optional[Callable]:
        """Get the actual function for a tool."""
        return self._function_map.get(function_name)

    def list_all(self) -> List[ToolMetadata]:
        """List all registered tools."""
        return list(self._tools.values())

    def list_by_category(self, category: ToolCategory) -> List[ToolMetadata]:
        """List all tools in a category."""
        tool_names = self._categories.get(category, [])
        return [self._tools[name] for name in tool_names if name in self._tools]

    def list_by_input_type(self, input_type: InputType) -> List[ToolMetadata]:
        """List all tools that accept a specific input type."""
        tool_names = self._by_input_type.get(input_type, [])
        return [self._tools[name] for name in tool_names if name in self._tools]

    def search_by_keyword(self, keyword: str) -> List[ToolMetadata]:
        """
        Search tools by keyword.

        Searches in:
        - Tool name
        - Description
        - Use cases
        - Triggers
        """
        keyword_lower = keyword.lower()
        results = []

        for tool in self._tools.values():
            # Check name
            if keyword_lower in tool.name.lower():
                results.append(tool)
                continue

            # Check description
            if keyword_lower in tool.description.lower():
                results.append(tool)
                continue

            # Check use cases
            if any(keyword_lower in uc.lower() for uc in tool.use_cases):
                results.append(tool)
                continue

            # Check triggers
            if any(keyword_lower in trigger.lower() for trigger in tool.triggers):
                results.append(tool)
                continue

        return results

    def get_tool_chain(self, start_tool: str) -> List[str]:
        """
        Get recommended tool chain starting from a tool.

        Returns:
            List of tool names in execution order
        """
        tool = self.get_tool(start_tool)
        if not tool:
            return []

        chain = [start_tool]
        visited = {start_tool}

        # BFS to find all chained tools
        queue = list(tool.chains_to)

        while queue:
            next_tool_name = queue.pop(0)
            if next_tool_name in visited:
                continue

            visited.add(next_tool_name)
            chain.append(next_tool_name)

            next_tool = self.get_tool(next_tool_name)
            if next_tool:
                for chained in next_tool.chains_to:
                    if chained not in visited:
                        queue.append(chained)

        return chain

    def get_llm_tool_catalog(self) -> str:
        """
        Generate a formatted tool catalog for LLM consumption.

        Returns:
            Formatted string describing all available tools
        """
        catalog = "# AVAILABLE SECURITY TOOLS\n\n"

        # Group by category
        for category in ToolCategory:
            tools = self.list_by_category(category)
            if not tools:
                continue

            catalog += f"## {category.value.upper().replace('_', ' ')}\n\n"

            for tool in tools:
                if not tool.enabled or tool.deprecated:
                    continue

                catalog += f"### {tool.name}\n"
                catalog += f"**Function**: `{tool.function_name}`\n"
                catalog += f"**Description**: {tool.description}\n"

                # Parameters
                catalog += "**Parameters**:\n"
                for param in tool.parameters:
                    req = "required" if param.required else "optional"
                    catalog += f"- `{param.name}` ({param.type.value}, {req}): {param.description}\n"
                    if param.examples:
                        catalog += f"  - Examples: {', '.join(param.examples[:3])}\n"

                # Use cases
                if tool.use_cases:
                    catalog += "**Use Cases**:\n"
                    for uc in tool.use_cases[:3]:
                        catalog += f"- {uc}\n"

                # Chains to
                if tool.chains_to:
                    catalog += f"**Chains to**: {', '.join(tool.chains_to[:5])}\n"

                catalog += "\n"

        return catalog

    def to_dict(self) -> Dict[str, Any]:
        """Export registry as dictionary for serialization."""
        return {
            "tools": {
                name: {
                    "name": tool.name,
                    "function_name": tool.function_name,
                    "description": tool.description,
                    "category": tool.category.value,
                    "parameters": [
                        {
                            "name": p.name,
                            "type": p.type.value,
                            "description": p.description,
                            "required": p.required,
                            "examples": p.examples
                        }
                        for p in tool.parameters
                    ],
                    "use_cases": tool.use_cases,
                    "triggers": tool.triggers,
                    "chains_to": tool.chains_to,
                    "enabled": tool.enabled
                }
                for name, tool in self._tools.items()
            }
        }


# Global registry instance
_global_registry = ToolRegistry()


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    return _global_registry


def register_tool(metadata: ToolMetadata):
    """
    Decorator to register a tool with metadata.

    Usage:
        @register_tool(ToolMetadata(...))
        def my_tool(target: str) -> dict:
            ...
    """
    def decorator(func: Callable):
        _global_registry.register(metadata, func)
        return func
    return decorator
