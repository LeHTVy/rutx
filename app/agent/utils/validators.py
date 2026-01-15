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


# No hardcoded mappings - use tool registry and other services instead


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
            # Try to get fallback from fallback_manager
            fallback_suggestion = ""
            try:
                from app.agent.utils.fallback_manager import get_fallback_manager
                fallback_mgr = get_fallback_manager()
                fallback_tool = fallback_mgr.get_fallback(tool)
                if fallback_tool:
                    fallback_suggestion = f" or use alternative: {fallback_tool}"
            except Exception:
                pass
            
            result.add_error(
                code="TOOL_NOT_REGISTERED",
                message=f"Tool '{tool}' is not registered",
                field="tool",
                suggestion=f"Check tool name{fallback_suggestion}"
            )
            return result
        
        # Check if tool is available (installed)
        if not self.registry.is_available(tool):
            # Use fallback_manager instead of hardcoded TOOL_FALLBACKS
            try:
                from app.agent.utils.fallback_manager import get_fallback_manager
                fallback_mgr = get_fallback_manager()
                fallback_tool = fallback_mgr.get_fallback(tool)
                
                if fallback_tool:
                    result.add_warning(
                        code="TOOL_NOT_INSTALLED",
                        message=f"Tool '{tool}' is not installed",
                        field="tool",
                        suggestion=f"Use alternative: {fallback_tool}"
                    )
                else:
                    hint = self.registry.get_install_hint(tool)
                    result.add_error(
                        code="TOOL_NOT_INSTALLED",
                        message=f"Tool '{tool}' is not installed",
                        field="tool",
                        suggestion=f"Install with: {hint}" if hint else "Install the tool first"
                    )
            except Exception:
                # Fallback if fallback_manager unavailable
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
        
        Extracts required params from tool registry CommandTemplate.args.
        No hardcode - uses tool registry metadata.
        
        Args:
            tool: Tool name
            command: Command name
            params: Provided parameters
            
        Returns:
            ValidationResult with missing params
        """
        result = ValidationResult(is_valid=True)
        
        # Get tool spec from registry
        spec = self.registry.tools.get(tool.lower())
        if not spec:
            return result  # Unknown tool, skip validation
        
        # Get command template
        template = spec.commands.get(command)
        if not template:
            # Try default command
            template = spec.commands.get("default") or (list(spec.commands.values())[0] if spec.commands else None)
        
        if not template:
            return result  # No template, skip validation
        
        # Extract required params from template args (e.g., "{target}", "{domain}")
        import re
        required = []
        for arg in template.args:
            # Find {param} placeholders
            matches = re.findall(r'\{(\w+)\}', arg)
            required.extend(matches)
        
        # Remove duplicates
        required = list(set(required))
        
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
        
        Uses tool_capability_service instead of hardcoded TOOL_CAPABILITIES.
        
        Args:
            tool: Tool name
            task_type: What we want to do (e.g., "subdomain", "port_scan")
            
        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)
        
        # Use tool_capability_service instead of hardcode
        try:
            from app.agent.utils.tool_capability_service import get_tool_capability_service
            capability_service = get_tool_capability_service()
            
            # Get tool category from registry
            spec = self.registry.tools.get(tool.lower())
            if not spec:
                result.add_info(
                    code="UNKNOWN_TOOL",
                    message=f"Unknown tool '{tool}'"
                )
                return result
            
            # Check if task matches category (simplified validation)
            task_lower = task_type.lower().replace(" ", "_")
            category = spec.category.value if spec.category else ""
            
            # Basic category matching
            category_matches = {
                "recon": ["subdomain", "dns", "osint", "recon"],
                "scanning": ["port", "scan", "service"],
                "vulnerability": ["vuln", "cve", "security"],
                "enumeration": ["enum", "directory", "fuzz"],
            }
            
            matches = False
            for cat_key, keywords in category_matches.items():
                if cat_key in category.lower():
                    matches = any(kw in task_lower for kw in keywords)
                    if matches:
                        break
            
            if not matches:
                # Find better tools from same category
                better_tools = []
                for t_name, t_spec in self.registry.tools.items():
                    if t_spec.category == spec.category and t_spec.is_available:
                        if t_name != tool:
                            better_tools.append(t_name)
                
                result.add_warning(
                    code="CAPABILITY_MISMATCH",
                    message=f"Tool '{tool}' may not be ideal for '{task_type}'",
                    field="tool",
                    suggestion=f"Consider: {', '.join(better_tools[:2])}" if better_tools else None
                )
        except Exception:
            # Fallback: skip validation if service unavailable
            pass
        
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
            # Check if any tool needs a target (extract from registry)
            target_required_tools = []
            for t in tools:
                spec = self._tool_validator.registry.tools.get(t.lower())
                if spec:
                    # Check if any command template has {target}, {domain}, or {host}
                    for cmd_template in spec.commands.values():
                        import re
                        args_str = " ".join(cmd_template.args)
                        if re.search(r'\{target\}|\{domain\}|\{host\}', args_str):
                            target_required_tools.append(t)
                            break
            
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
        """
        Check if tools match expected phase progression.
        
        Uses phase metadata from CommandTemplate if available, otherwise falls back to tool category.
        No hardcode - uses tool registry metadata.
        """
        result = ValidationResult(is_valid=True)
        
        registry = self._tool_validator.registry
        
        # Check for phase skipping using command phase metadata
        for tool in tools:
            spec = registry.tools.get(tool.lower())
            if not spec:
                continue
            
            # Get command from plan (if specified)
            # For now, use first command or default
            command_name = "default"  # Could be extracted from plan if available
            template = spec.commands.get(command_name) or (list(spec.commands.values())[0] if spec.commands else None)
            
            if template and template.phase:
                # Use phase from command template metadata
                tool_phase = template.phase
                phase_reason = template.phase_reason or f"Command '{command_name}' is designed for phase {tool_phase}"
            else:
                # Fallback to tool category-based phase
                try:
                    from app.agent.core.phase_manager import get_tool_phase
                    tool_phase = get_tool_phase(tool)
                    phase_reason = f"Tool category suggests phase {tool_phase}"
                except ImportError:
                    continue
            
            if tool_phase > current_phase + 1:
                result.add_warning(
                    code="PHASE_SKIP",
                    message=f"Tool '{tool}' command is for phase {tool_phase}, but current phase is {current_phase}",
                    suggestion=f"Complete phase {current_phase} first, or confirm phase skip. {phase_reason}"
                )
        
        # Check prerequisites using tool categories instead of hardcoded lists
        registry = self._tool_validator.registry
        
        # Check if we have scanning tools but no recon data
        if current_phase >= 2 and not context.get("subdomains"):
            from app.tools.registry import ToolCategory
            
            # Find scanning tools (category SCANNING or VULN)
            scan_tools = []
            recon_tools = []
            for tool in tools:
                spec = registry.tools.get(tool.lower())
                if spec and spec.category:
                    if spec.category in [ToolCategory.SCANNING, ToolCategory.VULN]:
                        scan_tools.append(tool)
                    elif spec.category in [ToolCategory.RECON, ToolCategory.OSINT]:
                        recon_tools.append(tool)
            
            if scan_tools and not recon_tools:
                result.add_info(
                    code="NO_RECON_DATA",
                    message="No subdomains discovered yet - scanning main domain only",
                    suggestion="Run subdomain enumeration first for broader coverage"
                )
        
        # Check if we have vuln tools but no port data
        if current_phase >= 3 and not context.get("open_ports"):
            from app.tools.registry import ToolCategory
            
            vuln_tools = []
            for tool in tools:
                spec = registry.tools.get(tool.lower())
                if spec and spec.category == ToolCategory.VULN:
                    vuln_tools.append(tool)
            
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
