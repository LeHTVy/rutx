"""
ToolRegistry - Unified Tool Management for SNODE
=================================================

Auto-discovers installed security tools and provides
consistent execution API with proper timeout handling.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path
from enum import Enum
import subprocess
import shutil
import time
import os


class ToolCategory(Enum):
    """Categories of security tools."""
    RECON = "recon"
    SCANNING = "scanning"
    VULN = "vulnerability"
    EXPLOIT = "exploitation"
    ENUM = "enumeration"
    OSINT = "osint"
    BRUTE = "brute_force"
    UTIL = "utility"


@dataclass
class ToolResult:
    """Standardized result from tool execution."""
    success: bool
    tool: str
    action: str
    output: str
    error: str = ""
    exit_code: int = 0
    elapsed_time: float = 0.0
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_observation(self) -> str:
        """Convert to agent observation string."""
        if self.success:
            return self.output
        else:
            return f"Error running {self.tool}: {self.error or self.output}"


@dataclass
class CommandTemplate:
    """Template for a tool command."""
    args: List[str]                  # Command args with {placeholders}
    timeout: int = 300               # Seconds
    requires_sudo: bool = False
    output_format: str = "text"      # text, json, xml
    success_codes: List[int] = field(default_factory=lambda: [0])


@dataclass
class ToolSpec:
    """
    Specification for a security tool.
    
    Defines executable location, available commands,
    and how to parse outputs.
    """
    name: str
    category: ToolCategory
    description: str
    
    # Executable discovery
    executable_names: List[str]      # Names to search for
    install_hint: str                # How to install if missing
    
    # Commands this tool supports
    commands: Dict[str, CommandTemplate] = field(default_factory=dict)
    
    # Runtime state (set by registry)
    executable_path: Optional[str] = None
    is_available: bool = False
    
    def find_executable(self) -> Optional[str]:
        """Find the tool executable on the system."""
        # Check common paths first
        common_paths = [
            "/home/hellrazor/go/bin",
            "/usr/bin",
            "/usr/local/bin",
            "/snap/bin",
            os.path.expanduser("~/go/bin"),
        ]
        
        for name in self.executable_names:
            # Check common paths
            for path_dir in common_paths:
                full_path = Path(path_dir) / name
                if full_path.exists() and os.access(full_path, os.X_OK):
                    return str(full_path)
            
            # Fall back to which
            path = shutil.which(name)
            if path:
                return path
        
        return None


class ToolRegistry:
    """
    Central registry for all security tools.
    
    Provides:
    - Auto-discovery of installed tools
    - Consistent execution API
    - Proper timeout handling
    - Structured output parsing
    """
    
    def __init__(self):
        self.tools: Dict[str, ToolSpec] = {}
        self._load_builtin_specs()
        self._discover_tools()
    
    def _load_builtin_specs(self):
        """Load built-in tool specifications."""
        from app.tools.specs import get_all_specs
        for spec in get_all_specs():
            self.register(spec)
    
    def register(self, spec: ToolSpec) -> None:
        """Register a tool specification."""
        self.tools[spec.name] = spec
    
    def _discover_tools(self) -> None:
        """Discover which tools are installed."""
        for name, spec in self.tools.items():
            # Python-based tools are always available
            if name == "clatscope":
                spec.is_available = True
                spec.executable_path = "python"  # Python-based
                continue
            
            path = spec.find_executable()
            if path:
                spec.executable_path = path
                spec.is_available = True
                # Silently discovered - no verbose output
            else:
                spec.is_available = False
    
    def is_available(self, tool: str) -> bool:
        """Check if a tool is available."""
        return tool in self.tools and self.tools[tool].is_available
    
    def list_tools(self, category: ToolCategory = None) -> List[str]:
        """List available tools, optionally filtered by category."""
        tools = []
        for name, spec in self.tools.items():
            if spec.is_available:
                if category is None or spec.category == category:
                    tools.append(name)
        return tools
    
    def get_install_hint(self, tool: str) -> str:
        """Get installation hint for a missing tool."""
        if tool in self.tools:
            return self.tools[tool].install_hint
        return f"Unknown tool: {tool}"
    
    def execute(
        self,
        tool: str,
        command: str,
        params: Dict[str, Any],
        timeout_override: int = None
    ) -> ToolResult:
        """
        Execute a tool command.
        
        Args:
            tool: Tool name (e.g., "nmap")
            command: Command name (e.g., "service_scan")
            params: Parameters for the command
            timeout_override: Override default timeout
        
        Returns:
            ToolResult with output and parsed data
        """
        # Validate tool
        if tool not in self.tools:
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"Unknown tool: {tool}"
            )
        
        spec = self.tools[tool]
        
        if not spec.is_available:
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"⚠️ TOOL NOT INSTALLED: {tool}. {spec.install_hint}"
            )
        
        # Validate command
        if command not in spec.commands:
            available = ", ".join(spec.commands.keys())
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"Unknown command '{command}' for {tool}. Available: {available}"
            )
        
        template = spec.commands[command]
        
        # Build command args
        try:
            args = self._build_args(spec, template, params)
        except KeyError as e:
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"Missing parameter: {e}"
            )
        
        # Execute
        timeout = timeout_override or template.timeout
        start_time = time.time()
        
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL
            )
            elapsed = time.time() - start_time
            
            success = result.returncode in template.success_codes
            
            return ToolResult(
                success=success,
                tool=tool,
                action=command,
                output=result.stdout.strip(),
                error=result.stderr.strip() if not success else "",
                exit_code=result.returncode,
                elapsed_time=elapsed
            )
            
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"Timeout after {timeout}s",
                elapsed_time=elapsed
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=str(e),
                elapsed_time=elapsed
            )
    
    def _build_args(
        self,
        spec: ToolSpec,
        template: CommandTemplate,
        params: Dict[str, Any]
    ) -> List[str]:
        """Build command arguments from template and params."""
        args = []
        
        # Add sudo if required
        if template.requires_sudo:
            args.append("sudo")
        
        # Add executable
        args.append(spec.executable_path)
        
        # Process template args
        for arg in template.args:
            if "{" in arg and "}" in arg:
                # Replace placeholders
                for key, value in params.items():
                    arg = arg.replace(f"{{{key}}}", str(value))
                
                # Check for unreplaced placeholders
                if "{" in arg:
                    import re
                    missing = re.findall(r'\{(\w+)\}', arg)
                    if missing:
                        raise KeyError(missing[0])
            
            args.append(arg)
        
        return args
    
    def get_tool_info(self, tool: str) -> Dict[str, Any]:
        """Get information about a tool."""
        if tool not in self.tools:
            return {"error": f"Unknown tool: {tool}"}
        
        spec = self.tools[tool]
        return {
            "name": spec.name,
            "category": spec.category.value,
            "description": spec.description,
            "available": spec.is_available,
            "path": spec.executable_path,
            "commands": list(spec.commands.keys()),
            "install_hint": spec.install_hint if not spec.is_available else None
        }
    
    def execute_stream(
        self,
        tool: str,
        command: str,
        params: Dict[str, Any],
        timeout_override: int = None,
        line_callback: Callable[[str], None] = None
    ) -> ToolResult:
        """
        Execute a tool command with streaming output.
        
        Args:
            tool: Tool name (e.g., "nmap")
            command: Command name (e.g., "service_scan")
            params: Parameters for the command
            timeout_override: Override default timeout
            line_callback: Callback function for each output line
        
        Returns:
            ToolResult with output and parsed data
        """
        # Validate tool
        if tool not in self.tools:
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"Unknown tool: {tool}"
            )
        
        spec = self.tools[tool]
        
        if not spec.is_available:
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"⚠️ TOOL NOT INSTALLED: {tool}. {spec.install_hint}"
            )
        
        # Validate command
        if command not in spec.commands:
            available = ", ".join(spec.commands.keys())
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"Unknown command '{command}' for {tool}. Available: {available}"
            )
        
        template = spec.commands[command]
        
        # Build command args
        try:
            args = self._build_args(spec, template, params)
        except KeyError as e:
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="",
                error=f"Missing parameter: {e}"
            )
        
        # Execute with streaming
        timeout = timeout_override or template.timeout
        start_time = time.time()
        output_lines = []
        
        try:
            import select
            
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,  # Line buffered
                stdin=subprocess.DEVNULL
            )
            
            # Stream output line by line
            while True:
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    process.kill()
                    return ToolResult(
                        success=False,
                        tool=tool,
                        action=command,
                        output="\n".join(output_lines),
                        error=f"Timeout after {timeout}s",
                        elapsed_time=elapsed
                    )
                
                # Read line
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                line = line.rstrip()
                output_lines.append(line)
                
                # Call callback if provided
                if line_callback:
                    line_callback(line)
            
            elapsed = time.time() - start_time
            success = process.returncode in template.success_codes
            
            return ToolResult(
                success=success,
                tool=tool,
                action=command,
                output="\n".join(output_lines),
                error="" if success else f"Exit code: {process.returncode}",
                exit_code=process.returncode,
                elapsed_time=elapsed
            )
            
        except Exception as e:
            elapsed = time.time() - start_time
            return ToolResult(
                success=False,
                tool=tool,
                action=command,
                output="\n".join(output_lines),
                error=str(e),
                elapsed_time=elapsed
            )


# Global registry instance
_registry: Optional[ToolRegistry] = None

def get_registry() -> ToolRegistry:
    """Get the global ToolRegistry instance."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
