"""
Executor Tool - Clean Refactored Version

Executes security tools via registry with proper parameter handling and context updates.
"""
import re
import urllib.parse
from typing import Dict, Any, Optional, Tuple
from app.agent.tools.base import AgentTool
from app.tools.registry import get_registry
from app.agent.orchestration import get_coordinator
from app.agent.core import get_context_manager
from app.ui import get_logger

logger = get_logger()


def validate_tool_params(tool_name: str, command: str, params: dict, registry) -> Tuple[bool, list, str]:
    """
    Validate that all required parameters are available for a tool command.
    Returns (is_valid, missing_params, error_message).
    """
    spec = registry.tools.get(tool_name)
    if not spec:
        return False, [], f"Tool not found: {tool_name}"
    
    template = spec.commands.get(command) if command else None
    if not template:
        # Try default command
        default_cmds = ["scan", "quick", "quick_scan", "enum", "default"]
        for cmd in default_cmds:
            if cmd in spec.commands:
                template = spec.commands[cmd]
                break
    
    if not template:
        return False, [], f"No command found for {tool_name}"
    
    # Extract required params from args template
    missing = []
    for arg in template.args:
        placeholders = re.findall(r'\{(\w+)\}', arg)
        for p in placeholders:
            if not params.get(p):
                missing.append(p)
    
    if missing:
        return False, missing, f"Missing parameters: {', '.join(missing)}"
    
    return True, [], ""


def _resolve_target(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve target from context and update params."""
    ctx_manager = get_context_manager()
    
    # Sync context manager with current state
    if context:
        ctx_manager.update_context(context)
    
    # Get prioritized target from ContextManager
    resolved_target = ctx_manager.get_target()
    
    # Ensure domain is in params from context (backwards compatible)
    if not params.get("domain"):
        params["domain"] = resolved_target or context.get("last_domain") or context.get("target_domain")
    
    if not params.get("target"):
        params["target"] = resolved_target or context.get("last_domain") or context.get("target_domain")
    
    # Use full URL if available (for web-based attacks)
    if not params.get("url") and context.get("url_target"):
        params["url"] = context.get("url_target")
        url = context.get("url_target")
        if url and not params.get("target"):
            parsed = urllib.parse.urlparse(url)
            params["target"] = parsed.netloc
            params["domain"] = parsed.netloc
    
    # Build URL for web tools if needed
    domain = params.get("domain") or params.get("target")
    if domain and not params.get("url"):
        params["url"] = f"https://{domain}"
    
    # Set host for tools that need it
    if domain and not params.get("host"):
        params["host"] = domain
    
    return params


def _collect_targets(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Collect targets using TargetCollector service."""
    domain = params.get("domain") or params.get("target") or context.get("last_domain") or context.get("target_domain")
    
    if not domain:
        return params
    
    try:
        from app.agent.core import get_target_collector
        target_collector = get_target_collector()
        
        # Collect all targets
        all_targets = target_collector.collect_all_targets(domain, context)
        
        # Update params with collected targets if not already set
        if not params.get("targets") and all_targets["all"]:
            current_domain = domain.lower().replace("www.", "")
            filtered_targets = []
            
            for t in all_targets["all"]:
                t_lower = t.lower()
                if (t_lower == current_domain or 
                    t_lower.endswith("." + current_domain) or 
                    current_domain in t_lower):
                    filtered_targets.append(t)
            
            if not filtered_targets:
                filtered_targets = [domain] if domain else []
            
            params["targets"] = filtered_targets[:50]
            params["target"] = " ".join(filtered_targets[:20])
            
            # Log if multiple targets
            if len(filtered_targets) > 1:
                summary = target_collector.get_targets_summary(domain, context)
                logger.info(f"Collected targets for {domain}:\n{summary}")
    except Exception as e:
        logger.warning(f"Target collection failed: {e}")
    
    return params


def _prepare_tool_params(tool_name: str, command: str, params: Dict[str, Any], 
                         context: Dict[str, Any], state: Any, registry) -> Tuple[str, Dict[str, Any]]:
    """Prepare tool parameters using agent's method."""
    # Get or infer agent
    agent_name = context.get("current_agent")
    if not agent_name or agent_name == "base":
        coordinator = get_coordinator()
        agent = coordinator.get_agent_by_tool(tool_name)
        if agent:
            agent_name = agent.AGENT_NAME
            context["current_agent"] = agent_name
        else:
            agent_name = "base"
            context["current_agent"] = agent_name
            agent = coordinator.get_agent(agent_name)
    else:
        agent = get_coordinator().get_agent(agent_name)
    
    # Get command from suggested_commands or use default
    suggested_commands = state.get("suggested_commands", {}) if state else {}
    if not command:
        command = suggested_commands.get(tool_name)
        if not command:
            spec = registry.tools.get(tool_name)
            if spec and spec.commands:
                command = list(spec.commands.keys())[0]
    
    # Update context with query for target collector
    if not context.get("query"):
        context["query"] = state.get("query", "") if state else ""
    
    # Prepare tool parameters using agent's method
    domain = params.get("domain") or params.get("target") or context.get("last_domain") or context.get("target_domain") or ""
    
    tool_params = agent.prepare_tool_params(
        tool_name, 
        command, 
        context,
        targets=params.get("targets")
    )
    
    # Check if command was overridden
    if "_command_override" in tool_params:
        command = tool_params.pop("_command_override")
    
    # Merge with params from planner
    tool_params.update({k: v for k, v in params.items() if k not in ["targets", "target"]})
    
    return command, tool_params


def _auto_fill_missing_params(missing: list, tool_params: Dict[str, Any], domain: str) -> Dict[str, Any]:
    """Auto-fill missing parameters with defaults."""
    for param in missing:
        if param == "wordlist" and not tool_params.get("wordlist"):
            tool_params["wordlist"] = "wordlists/common.txt"
        elif param == "user" and not tool_params.get("user"):
            tool_params["user"] = "admin"
        elif param == "ports" and not tool_params.get("ports"):
            tool_params["ports"] = "22,80,443,8080,8443"
        elif param == "target" and not tool_params.get("target"):
            tool_params["target"] = domain or ""
    return tool_params


def _execute_clatscope(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Execute clatscope OSINT tool (Python-based, not CLI)."""
    from app.tools.specs.osint import execute_clatscope, format_clatscope_result
    
    # Determine OSINT command
    osint_command = params.get("command", "whois")
    
    if params.get("ip"):
        osint_command = "ip"
    elif params.get("phone"):
        osint_command = "phone"
    elif params.get("email"):
        osint_command = "breach" if "breach" in str(params) else "email"
    
    logger.info(f"OSINT: {osint_command}", icon="")
    
    osint_result = execute_clatscope(osint_command, params)
    formatted = format_clatscope_result(osint_command, osint_result)
    
    result = {
        "success": osint_result.get("success", False),
        "output": formatted,
        "data": osint_result.get("data")
    }
    
    # Update context with OSINT findings
    if osint_result.get("success"):
        data = osint_result.get("data", {})
        if osint_command == "subdomain" and data.get("subdomains"):
            existing_subs = context.get("subdomains", [])
            new_subs = data.get("subdomains", [])
            context["subdomains"] = list(set(existing_subs + new_subs))
            context["subdomain_count"] = len(context["subdomains"])
            context["has_subdomains"] = True
    
    return result


def _parse_tool_output(tool_name: str, output: str, domain: str, context: Dict[str, Any]) -> None:
    """Parse tool output and update context with findings."""
    try:
        from app.agent.utils.output_parser import get_output_parser
        parser = get_output_parser()
        
        # Parse output with LLM - extracts subdomains, hosts, ports, vulns, etc.
        findings = parser.parse(tool_name, output, domain)
        
        if findings:
            # Update context with extracted findings
            parser.update_context(context, findings)
            
            # Log what was found
            found_items = []
            if findings.get("subdomains"):
                found_items.append(f"{len(findings['subdomains'])} subdomains")
            if findings.get("hosts"):
                found_items.append(f"{len(findings['hosts'])} hosts")
            if findings.get("ports"):
                found_items.append(f"{len(findings['ports'])} ports")
            if findings.get("vulnerabilities"):
                found_items.append(f"{len(findings['vulnerabilities'])} vulns")
            if findings.get("emails"):
                found_items.append(f"{len(findings['emails'])} emails")
            if findings.get("technologies"):
                found_items.append(f"{len(findings['technologies'])} technologies")
            
            if found_items:
                logger.info(f"LLM Parser: {', '.join(found_items)}", icon="")
            
            # Persist to RAG
            try:
                from app.rag.unified_memory import get_unified_rag
                rag = get_unified_rag()
                for sub in findings.get("subdomains", [])[:100]:
                    ip = ""
                    for h in findings.get("hosts", []):
                        if h.get("hostname") == sub:
                            ip = h.get("ip", "")
                            break
                    rag.add_subdomain(sub, domain, ip=ip, source=tool_name)
                for h in findings.get("hosts", [])[:50]:
                    if h.get("ip"):
                        rag.add_host(h.get("ip"), h.get("hostname"), domain=domain)
                for v in findings.get("vulnerabilities", [])[:20]:
                    rag.add_vulnerability(v.get("type", ""), v.get("severity", ""), 
                                        v.get("target", ""), v.get("details", ""),
                                        tool=tool_name, domain=domain)
            except Exception:
                pass  # RAG storage is optional
    except Exception as e:
        logger.warning(f"Universal parser: {e}")


def _update_context_flags(tool_name: str, context: Dict[str, Any], params: Dict[str, Any]) -> None:
    """Update context flags using ToolCapabilityService."""
    try:
        from app.agent.utils.tool_capability_service import get_tool_capability_service
        capability_service = get_tool_capability_service()
        capability_service.update_context_flags(tool_name, context, params)
    except Exception:
        pass  # Flags are optional


def _detect_security_tech_single(tool_name: str, output: str, context: Dict[str, Any]) -> None:
    """Detect security tech (WAF/CDN) from single tool output."""
    try:
        from app.agent.utils.tool_capability_service import get_tool_capability_service
        from app.rag.security_tech import SECURITY_TECH_DB
        
        capability_service = get_tool_capability_service()
        
        if not capability_service.can_detect_security_tech(tool_name):
            return
        
        detected_security = context.get("detected_security_tech", [])
        output_lower = output.lower()
        
        for tech_id, tech in SECURITY_TECH_DB.items():
            for pattern in tech.detection_patterns:
                if pattern.lower() in output_lower:
                    if tech_id not in detected_security:
                        detected_security.append(tech_id)
                        logger.info(f"Detected security tech in output: {tech.name}", icon="")
                    break
        
        if detected_security:
            context["detected_security_tech"] = list(set(detected_security))
    except Exception:
        pass


def _detect_security_tech_all(results: Dict[str, Any], context: Dict[str, Any]) -> None:
    """Detect security tech from all tool outputs."""
    try:
        from app.rag.security_tech import SECURITY_TECH_DB
        
        # Combine all outputs for scanning
        all_output = ""
        for tool, data in results.items():
            if data.get("output"):
                all_output += data["output"].lower()
        
        detected_security = context.get("detected_security_tech", [])
        for tech_id, tech in SECURITY_TECH_DB.items():
            for pattern in tech.detection_patterns:
                if pattern.lower() in all_output:
                    if tech_id not in detected_security:
                        detected_security.append(tech_id)
                        logger.info(f"Detected security tech in output: {tech.name}", icon="")
                    break
        
        if detected_security:
            context["detected_security_tech"] = list(set(detected_security))
    except Exception:
        pass


def _sync_to_memory(tools: list, context: Dict[str, Any]) -> None:
    """Sync context to shared memory."""
    try:
        from app.memory import get_session_memory
        session = get_session_memory()
        
        # Update session memory from context
        if context.get("last_domain"):
            session.agent_context.domain = context["last_domain"]
        if context.get("subdomains"):
            session.agent_context.add_subdomains(context["subdomains"])
        if context.get("detected_tech"):
            for tech in context["detected_tech"]:
                session.agent_context.add_technology(tech)
        
        # Log which tools ran
        for tool in tools:
            session.agent_context.add_tool_run(tool)
    except Exception:
        pass  # Shared memory is optional


def _execute_single_tool(tool_name: str, params: Dict[str, Any], context: Dict[str, Any], 
                         state: Any, registry) -> Dict[str, Any]:
    """Execute a single tool and return result."""
    # Check if tool is available
    if not registry.is_available(tool_name):
        return {
            "success": False,
            "output": f"Tool not available: {tool_name}"
        }
    
    spec = registry.tools.get(tool_name)
    if not spec or not spec.commands:
        return {
            "success": False,
            "output": f"No commands for: {tool_name}"
        }
    
    # Special handling for clatscope
    if tool_name == "clatscope":
        return _execute_clatscope(params, context)
    
    # Prepare tool parameters
    command, tool_params = _prepare_tool_params(tool_name, None, params, context, state, registry)
    
    logger.info(f"Executing {tool_name}:{command}", icon="")
    
    # Validate parameters
    domain = params.get("domain") or params.get("target") or context.get("last_domain") or context.get("target_domain") or ""
    is_valid, missing, error_msg = validate_tool_params(tool_name, command, tool_params, registry)
    
    if not is_valid and missing:
        # Auto-fill missing params
        tool_params = _auto_fill_missing_params(missing, tool_params, domain)
        
        # Re-validate
        is_valid, still_missing, _ = validate_tool_params(tool_name, command, tool_params, registry)
        if not is_valid and still_missing:
            logger.warning(f"Skipping {tool_name}: missing {', '.join(still_missing)}")
            return {
                "success": False,
                "output": f"Missing required params: {', '.join(still_missing)}"
            }
    
    # Extension hook: before_tool_execution
    try:
        from app.extensions import call_extensions_sync
        agent = get_coordinator().get_agent(context.get("current_agent", "base"))
        call_extensions_sync("before_tool_execution", agent=agent, tool_name=tool_name, 
                           command=command, params=tool_params)
    except Exception:
        pass
    
    # Execute via agent
    agent = get_coordinator().get_agent(context.get("current_agent", "base"))
    logger.info(f"Agent '{agent.AGENT_NAME}' executing {tool_name}...", icon="")
    execution_result = agent.execute_tool(tool_name, command, tool_params)
    
    # Extension hook: after_tool_execution
    try:
        from app.extensions import call_extensions_sync
        call_extensions_sync("after_tool_execution", agent=agent, tool_name=tool_name, result=execution_result)
    except Exception:
        pass
    
    # Update context if successful
    if execution_result.get("success"):
        output = execution_result.get("output", "")
        
        # Print output (full for OSINT tools, truncated for verbose tools)
        osint_tools = {"securitytrails", "shodan", "clatscope", "whois", "dig", "dnsrecon"}
        if tool_name in osint_tools or len(output) < 5000:
            logger.dim(output)
        else:
            logger.dim(f"{output[:1500]}...\n... (truncated {len(output)} chars) ...\n{output[-1500:]}")
        
        # Parse output and update context
        _parse_tool_output(tool_name, output, domain, context)
        
        # Update context flags
        _update_context_flags(tool_name, context, params)
        
        # Detect security tech
        _detect_security_tech_single(tool_name, output, context)
    
    return execution_result


class ExecutorTool(AgentTool):
    """Tool for executing security tools via registry."""
    
    def execute(self, tools: list = None, params: Dict[str, Any] = None, context: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """
        Execute tools via registry.
        
        Args:
            tools: List of tool names to execute
            params: Tool parameters
            context: Current context dictionary
            
        Returns:
            Dictionary with execution results and context updates
        """
        if tools is None:
            tools = self.state.get("selected_tools", []) if self.state else []
        if params is None:
            params = self.state.get("tool_params", {}) if self.state else {}
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        
        # Extension hook: executor_start
        try:
            from app.extensions import call_extensions_sync
            call_extensions_sync("executor_start", agent=None, state=self.state)
        except Exception:
            pass
        
        registry = get_registry()
        results = {}
        
        # Resolve target
        params = _resolve_target(params, context)
        
        # Collect targets
        params = _collect_targets(params, context)
        
        # Default query for searchsploit
        if not params.get("query"):
            detected_tech = context.get("detected_tech", [])
            if detected_tech:
                params["query"] = detected_tech[0]
            else:
                params["query"] = params.get("domain") or params.get("target") or "apache"
        
        # Display target
        target_display = params.get("url") or params.get("target") or params.get("domain") or "unknown"
        
        # Execute tools sequentially
        if len(tools) > 1:
            logger.info(f"Executing {len(tools)} tools SEQUENTIALLY: {', '.join(tools)} on {target_display}")
        else:
            logger.info(f"Executing: {', '.join(tools)} on {target_display}")
        
        # Execute each tool
        for tool_name in tools:
            result = _execute_single_tool(tool_name, params, context, self.state, registry)
            results[tool_name] = result
        
        # Update tools_run with executed tools
        if tools:
            tools_run = context.get("tools_run", [])
            tools_run.extend(tools)
            context["tools_run"] = list(set(tools_run))
        
        # Universal security tech detection (all tool outputs)
        _detect_security_tech_all(results, context)
        
        # Sync to shared memory
        _sync_to_memory(tools, context)
        
        return {
            "execution_results": results,
            "context": context,
            "next_action": "analyze"
        }
