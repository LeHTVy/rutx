"""
Validators - Post-LLM Validation Layer
=======================================

Validates LLM outputs BEFORE acting on them.
This is the Cursor-style "validation layer" pattern.

Catches:
- Missing required parameters
- Unavailable tools
- Incoherent plans
- Wrong tools for the task
"""
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set
from enum import Enum


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""
    ERROR = "error"      # Cannot proceed
    WARNING = "warning"  # Can proceed with caution
    INFO = "info"        # FYI


@dataclass
class ValidationIssue:
    """A single validation issue."""
    severity: ValidationSeverity
    code: str
    message: str
    field: Optional[str] = None
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of validation check."""
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    
    @property
    def errors(self) -> List[str]:
        """Get error messages."""
        return [i.message for i in self.issues if i.severity == ValidationSeverity.ERROR]
    
    @property
    def warnings(self) -> List[str]:
        """Get warning messages."""
        return [i.message for i in self.issues if i.severity == ValidationSeverity.WARNING]
    
    @property
    def suggestions(self) -> List[str]:
        """Get all suggestions."""
        return [i.suggestion for i in self.issues if i.suggestion]
    
    def add_error(self, code: str, message: str, field: str = None, suggestion: str = None):
        """Add an error issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.ERROR,
            code=code,
            message=message,
            field=field,
            suggestion=suggestion
        ))
        self.is_valid = False
    
    def add_warning(self, code: str, message: str, field: str = None, suggestion: str = None):
        """Add a warning issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.WARNING,
            code=code,
            message=message,
            field=field,
            suggestion=suggestion
        ))
    
    def add_info(self, code: str, message: str, suggestion: str = None):
        """Add an info issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.INFO,
            code=code,
            message=message,
            suggestion=suggestion
        ))
    
    def merge(self, other: "ValidationResult") -> "ValidationResult":
        """Merge another validation result into this one."""
        self.issues.extend(other.issues)
        if not other.is_valid:
            self.is_valid = False
        return self


# Tool capability mappings
TOOL_CAPABILITIES = {
    # Reconnaissance
    "amass": ["subdomain", "passive_recon", "dns"],
    "subfinder": ["subdomain", "passive_recon"],
    "assetfinder": ["subdomain", "passive_recon"],
    "clatscope": ["osint", "whois", "ip_lookup", "phone", "email"],
    
    # Scanning
    "nmap": ["port_scan", "service_detection", "os_detection", "vuln_scan"],
    "masscan": ["port_scan", "fast_scan"],
    "rustscan": ["port_scan", "fast_scan"],
    "httpx": ["http_probe", "tech_detection"],
    
    # Directory/Content Discovery
    "gobuster": ["directory_bruteforce", "dns_bruteforce", "vhost"],
    "ffuf": ["directory_bruteforce", "fuzzing", "parameter"],
    "dirsearch": ["directory_bruteforce"],
    "feroxbuster": ["directory_bruteforce"],
    
    # Vulnerability Scanning
    "nuclei": ["vuln_scan", "cve_detection", "template_scan"],
    "nikto": ["vuln_scan", "web_server"],
    "wpscan": ["wordpress", "cms_scan"],
    
    # Exploitation
    "sqlmap": ["sqli", "database"],
    "hydra": ["brute_force", "password"],
    "medusa": ["brute_force", "password"],
    "searchsploit": ["exploit_search"],
    
    # Post-Exploitation
    "linpeas": ["privesc", "linux"],
    "winpeas": ["privesc", "windows"],
    "crackmapexec": ["lateral_movement", "smb", "password_spray"],
}

# Required parameters for common tools
TOOL_REQUIRED_PARAMS = {
    "nmap": ["target"],
    "masscan": ["target", "ports"],
    "nuclei": ["target"],
    "gobuster": ["url", "wordlist"],
    "ffuf": ["url"],
    "sqlmap": ["url"],
    "hydra": ["target", "user"],
    "wpscan": ["url"],
    "nikto": ["host"],
}

# Tool fallbacks
TOOL_FALLBACKS = {
    "nmap": ["masscan", "rustscan"],
    "masscan": ["nmap", "rustscan"],
    "gobuster": ["ffuf", "dirsearch", "feroxbuster"],
    "ffuf": ["gobuster", "dirsearch"],
    "nuclei": ["nikto"],
    "amass": ["subfinder", "assetfinder"],
    "subfinder": ["amass", "assetfinder"],
    "sqlmap": ["ghauri"],
    "hydra": ["medusa"],
}


class ToolValidator:
    """
    Validate tool selection before execution.
    
    Checks:
    - Tool is available in registry
    - Tool has required parameters
    - Tool can do what we're asking
    """
    
    def __init__(self):
        self._registry = None
    
    @property
    def registry(self):
        """Lazy-load tool registry."""
        if self._registry is None:
            from app.tools.registry import get_registry
            self._registry = get_registry()
        return self._registry
    
    def validate_tool_available(self, tool: str) -> ValidationResult:
        """
        Check if tool is in registry and installed.
        
        Args:
            tool: Tool name
            
        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)
        
        # Check if tool exists in registry
        if tool not in self.registry.tools:
            result.add_error(
                code="TOOL_NOT_REGISTERED",
                message=f"Tool '{tool}' is not registered",
                field="tool",
                suggestion=f"Check tool name or use alternative: {', '.join(TOOL_FALLBACKS.get(tool, [])[:2])}"
            )
            return result
        
        # Check if tool is available (installed)
        if not self.registry.is_available(tool):
            fallbacks = TOOL_FALLBACKS.get(tool, [])
            available_fallbacks = [t for t in fallbacks if self.registry.is_available(t)]
            
            if available_fallbacks:
                result.add_warning(
                    code="TOOL_NOT_INSTALLED",
                    message=f"Tool '{tool}' is not installed",
                    field="tool",
                    suggestion=f"Use alternative: {available_fallbacks[0]}"
                )
            else:
                hint = self.registry.get_install_hint(tool)
                result.add_error(
                    code="TOOL_NOT_INSTALLED",
                    message=f"Tool '{tool}' is not installed",
                    field="tool",
                    suggestion=f"Install with: {hint}" if hint else "Install the tool first"
                )
        
        return result
    
    def validate_params(self, tool: str, command: str, params: Dict[str, Any]) -> ValidationResult:
        """
        Check if all required parameters are present.
        
        Args:
            tool: Tool name
            command: Command name
            params: Provided parameters
            
        Returns:
            ValidationResult with missing params
        """
        result = ValidationResult(is_valid=True)
        
        # Get required params from our mapping
        required = TOOL_REQUIRED_PARAMS.get(tool, [])
        
        # Check each required param
        missing = []
        for param in required:
            # Check various possible param names
            param_variants = [param, param.replace("_", ""), f"{param}s"]
            has_param = any(params.get(p) for p in param_variants)
            
            if not has_param:
                missing.append(param)
        
        if missing:
            result.add_error(
                code="MISSING_PARAMS",
                message=f"Tool '{tool}' missing required parameters: {', '.join(missing)}",
                field="params",
                suggestion=f"Provide: {', '.join(missing)}"
            )
        
        return result
    
    def validate_capability_match(self, tool: str, task_type: str) -> ValidationResult:
        """
        Check if tool can actually do what we're asking.
        
        Args:
            tool: Tool name
            task_type: What we want to do (e.g., "subdomain", "port_scan")
            
        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)
        
        capabilities = TOOL_CAPABILITIES.get(tool, [])
        
        if not capabilities:
            # Unknown tool - can't validate
            result.add_info(
                code="UNKNOWN_CAPABILITIES",
                message=f"Unknown capabilities for '{tool}'"
            )
            return result
        
        # Check if task matches capabilities
        task_lower = task_type.lower().replace(" ", "_")
        
        # Fuzzy match
        matches = any(
            task_lower in cap or cap in task_lower
            for cap in capabilities
        )
        
        if not matches:
            # Find better tool
            better_tools = []
            for t, caps in TOOL_CAPABILITIES.items():
                if task_lower in caps or any(task_lower in c for c in caps):
                    if self.registry.is_available(t):
                        better_tools.append(t)
            
            result.add_warning(
                code="CAPABILITY_MISMATCH",
                message=f"Tool '{tool}' may not be ideal for '{task_type}'",
                field="tool",
                suggestion=f"Consider: {', '.join(better_tools[:2])}" if better_tools else None
            )
        
        return result
    
    def validate_tool(self, tool: str, command: str, params: Dict[str, Any], 
                     task_type: str = None) -> ValidationResult:
        """
        Full validation of a tool selection.
        
        Args:
            tool: Tool name
            command: Command name
            params: Provided parameters
            task_type: What we want to do (optional)
            
        Returns:
            Merged ValidationResult
        """
        result = ValidationResult(is_valid=True)
        
        # Check availability
        availability = self.validate_tool_available(tool)
        result.merge(availability)
        
        # Check params (only if tool is available)
        if availability.is_valid:
            params_result = self.validate_params(tool, command, params)
            result.merge(params_result)
        
        # Check capability match
        if task_type:
            capability = self.validate_capability_match(tool, task_type)
            result.merge(capability)
        
        return result


class PlanValidator:
    """
    Validate agent plans before confirmation.
    
    Checks:
    - Plan has necessary components
    - Tools are appropriate for phase
    - Phase progression is logical
    """
    
    def __init__(self):
        self._tool_validator = ToolValidator()
    
    def validate_plan(self, plan: Dict[str, Any], context: Dict[str, Any]) -> ValidationResult:
        """
        Validate a complete plan before execution.
        
        Args:
            plan: Plan from agent (tools, commands, reasoning)
            context: Current session context
            
        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)
        
        tools = plan.get("tools", [])
        commands = plan.get("commands", {})
        
        # Check if plan has tools
        if not tools:
            result.add_warning(
                code="NO_TOOLS",
                message="Plan has no tools selected",
                suggestion="Add specific tools or ask for clarification"
            )
        
        # Check if we have a target
        target = (context.get("target_domain") or 
                 context.get("last_domain") or 
                 context.get("target_ip"))
        
        if not target and tools:
            # Check if any tool needs a target
            target_required_tools = [t for t in tools if t in TOOL_REQUIRED_PARAMS]
            if target_required_tools:
                result.add_error(
                    code="NO_TARGET",
                    message=f"No target specified but tools {target_required_tools} need one",
                    suggestion="Ask user for target domain or IP"
                )
        
        # Validate each tool
        for tool in tools:
            command = commands.get(tool, "default")
            params = {
                "target": target,
                "domain": target,
                "host": target,
                "url": f"https://{target}" if target else None,
                **context
            }
            
            tool_result = self._tool_validator.validate_tool(tool, command, params)
            result.merge(tool_result)
        
        # Check phase progression
        current_phase = context.get("current_phase", 1)
        phase_result = self._validate_phase_progression(tools, current_phase, context)
        result.merge(phase_result)
        
        return result
    
    def _validate_phase_progression(self, tools: List[str], current_phase: int, 
                                    context: Dict[str, Any]) -> ValidationResult:
        """Check if tools match expected phase progression."""
        result = ValidationResult(is_valid=True)
        
        # Phase tool mappings
        phase_tools = {
            1: {"amass", "subfinder", "assetfinder", "clatscope", "whois"},
            2: {"nmap", "masscan", "httpx", "gobuster", "ffuf", "dirsearch"},
            3: {"nuclei", "nikto", "wpscan", "wafw00f"},
            4: {"sqlmap", "hydra", "searchsploit", "metasploit"},
            5: {"linpeas", "winpeas", "mimikatz", "crackmapexec", "bloodhound"},
            6: set(),  # Reporting - no tools
        }
        
        # Check for phase skipping
        expected_phase_tools = phase_tools.get(current_phase, set())
        
        for tool in tools:
            # Find which phase this tool belongs to
            tool_phase = None
            for phase, phase_tool_set in phase_tools.items():
                if tool in phase_tool_set:
                    tool_phase = phase
                    break
            
            if tool_phase and tool_phase > current_phase + 1:
                result.add_warning(
                    code="PHASE_SKIP",
                    message=f"Tool '{tool}' is for phase {tool_phase}, but current phase is {current_phase}",
                    suggestion=f"Complete phase {current_phase} first, or confirm phase skip"
                )
        
        # Check prerequisites
        if current_phase >= 2 and not context.get("subdomains"):
            recon_tools = {"amass", "subfinder", "assetfinder"}
            scan_tools = set(tools) & {"nmap", "masscan", "nuclei", "nikto"}
            if scan_tools and not (set(tools) & recon_tools):
                result.add_info(
                    code="NO_RECON_DATA",
                    message="No subdomains discovered yet - scanning main domain only",
                    suggestion="Run subdomain enumeration first for broader coverage"
                )
        
        if current_phase >= 3 and not context.get("open_ports"):
            vuln_tools = set(tools) & {"nuclei", "nikto", "wpscan"}
            if vuln_tools:
                result.add_info(
                    code="NO_PORT_DATA",
                    message="No open ports discovered yet - using default ports",
                    suggestion="Run port scan first for targeted vuln scanning"
                )
        
        return result
    
    def suggest_fixes(self, result: ValidationResult, context: Dict[str, Any]) -> List[str]:
        """
        Suggest fixes for validation errors.
        
        Args:
            result: ValidationResult with issues
            context: Current context
            
        Returns:
            List of actionable suggestions
        """
        suggestions = []
        
        for issue in result.issues:
            if issue.suggestion:
                suggestions.append(issue.suggestion)
            elif issue.code == "NO_TARGET":
                suggestions.append("Please provide a target domain or IP address")
            elif issue.code == "TOOL_NOT_INSTALLED":
                # Find available alternatives
                pass
        
        return suggestions


def get_tool_validator() -> ToolValidator:
    """Get tool validator instance."""
    return ToolValidator()


def get_plan_validator() -> PlanValidator:
    """Get plan validator instance."""
    return PlanValidator()
