"""
Planner Tool - Clean Refactored Version

Plans using specialized agents via Coordinator.
Main purpose: Select appropriate security tools based on user query and context, validate plan, and check tool availability.

Focus: Clean code structure with helper functions.
"""
from typing import Dict, Any, Optional, List, Tuple
from app.agent.tools.base import AgentTool
from app.agent.orchestration import get_coordinator
from app.ui import get_logger
from app.agent.core import (
    get_context_manager, get_context_aggregator,
    get_phase_manager, PHASE_NAMES, PhaseGateAction,
)
from app.agent.analyzer.checklist_planning_service import prepare_query_with_task
from app.agent.utils import (
    get_plan_validator, get_fallback_manager,
)
from app.tools.registry import get_registry

logger = get_logger()


def _aggregate_context(query: str, state: Any, context: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
    """Aggregate all relevant context before planning."""
    aggregator = get_context_aggregator()
    ctx_manager = get_context_manager()
    
    # Aggregate all relevant context before planning
    agg_context = aggregator.aggregate_for_planning(query, state)
    
    # Sync ContextManager with current state context
    if context:
        ctx_manager.update_context(context)
    
    # Get target from aggregated context (prioritized resolution)
    target = agg_context.target or context.get("target_domain") or context.get("last_domain")
    
    # Update context with resolved target
    if target and not context.get("target_domain"):
        context["last_domain"] = target
        ctx_manager.set_target(target, source="planner")
    
    # Log aggregated context
    if agg_context.has_past_data():
        print(f"  📚 Context: {len(agg_context.relevant_facts)} past findings available")
    if agg_context.learning_hints:
        print(f"  ⚡ Learning: {agg_context.learning_hints[0]}")
    
    return agg_context, context


def _load_analyzer_recommendation(context: Dict[str, Any], query_lower: str) -> None:
    """Load analyzer recommendation from context or session memory."""
    analyzer_next_tool = context.get("analyzer_next_tool") or context.get("user_requested_tool")
    
    # Check if "do the next step" command
    is_suggestion_command = (
        "next step" in query_lower or 
        ("do" in query_lower and "step" in query_lower) or 
        ("suggest" in query_lower and "step" in query_lower) or
        ("do" in query_lower and "suggestion" in query_lower) or
        ("as" in query_lower and "suggestion" in query_lower) or
        ("your suggestion" in query_lower)
    )
    
    if (is_suggestion_command and not analyzer_next_tool) or not context.get("analyzer_next_tool"):
        try:
            from app.memory import get_session_memory
            session_memory = get_session_memory()
            if hasattr(session_memory, 'analyzer_recommendations') and session_memory.analyzer_recommendations:
                rec = session_memory.analyzer_recommendations
                if rec and rec.get("next_tool"):
                    context["analyzer_next_tool"] = rec.get("next_tool")
                    context["analyzer_next_target"] = rec.get("next_target")
                    context["analyzer_next_reason"] = rec.get("next_reason")
                    context["user_requested_tool"] = rec.get("next_tool")
        except Exception:
            pass


def _check_phase_gates(tools: List[str], context: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, Any]], Optional[Dict[str, Any]]]:
    """
    Check each tool against phase gates.
    Returns: (allowed_tools, blocked_tools, block_message_dict)
    """
    phase_mgr = get_phase_manager()
    phase_status = phase_mgr.get_phase_status(context)
    current_phase = phase_status["current_phase"]
    current_phase_name = phase_status["current_phase_name"]
    
    blocked_tools = []
    allowed_tools = []
    
    for tool in tools:
        gate_result = phase_mgr.check_phase_gate(tool, context)
        
        if gate_result.is_blocked:
            blocked_tools.append((tool, gate_result))
            print(f"  🚫 Phase Gate BLOCKED: {tool} (Phase {gate_result.requested_phase})")
        else:
            allowed_tools.append(tool)
            if gate_result.action == PhaseGateAction.WARN:
                logger.warning(f"Phase Gate WARN: {tool} (Phase {gate_result.requested_phase})")
    
    # If ALL tools are blocked, return remediation message
    if blocked_tools and not allowed_tools:
        tool_name, gate_result = blocked_tools[0]
        requested_phase_name = PHASE_NAMES.get(gate_result.requested_phase, f"Phase {gate_result.requested_phase}")
        
        block_message = f"""🚫 **Phase Gate: Cannot proceed with {requested_phase_name} tools yet**

📍 **Current Phase:** {current_phase} - {current_phase_name}
🎯 **Requested Phase:** {gate_result.requested_phase} - {requested_phase_name}

**Missing Requirements:**
"""
        for req in gate_result.missing_requirements:
            block_message += f"  • {req}\n"
        
        block_message += f"\n💡 **Remediation:** {gate_result.remediation}"
        block_message += f"\n\n_Progress: {phase_status['progress_summary']}_"
        
        return [], blocked_tools, {
            "suggested_tools": [],
            "suggestion_message": block_message,
            "next_action": "end"
        }
    
    return allowed_tools, blocked_tools, None


def _validate_plan(plan: Dict[str, Any], context: Dict[str, Any]) -> Tuple[Any, str]:
    """Validate plan and return validation result and updated reasoning."""
    validator = get_plan_validator()
    validation = validator.validate_plan(plan, context)
    
    reasoning = plan.get("reasoning") or f"I have selected {len(plan.get('tools', []))} tools to proceed with your request."
    
    validation_dict = None
    if not validation.is_valid:
        logger.warning(f"Validation issues: {', '.join(validation.errors)}")
        validation_dict = {
            "is_valid": validation.is_valid,
            "errors": validation.errors,
            "warnings": validation.warnings,
            "suggestions": validation.suggestions,
        }
        
        # Add suggestions to reasoning
        if validation.suggestions:
            reasoning += f"\n\n⚠️ Note: {'; '.join(validation.suggestions)}"
    elif validation.warnings:
        logger.warning(f"Warnings: {', '.join(validation.warnings)}")
    
    return validation, validation_dict, reasoning


def _check_tool_availability(tools: List[str], commands: Dict[str, str], 
                            context: Dict[str, Any]) -> Tuple[List[str], List[str], str]:
    """
    Check tool availability and suggest fallbacks.
    Returns: (adjusted_tools, fallback_tools, unavailable_msg)
    """
    fallback_mgr = get_fallback_manager()
    registry = get_registry()
    adjusted_tools = []
    fallback_tools = []
    unavailable_tools = []
    
    for tool in tools:
        if not fallback_mgr.registry.is_available(tool):
            # Get tool spec for install hint
            spec = registry.tools.get(tool)
            install_hint = spec.install_hint if spec else f"Install {tool} manually"
            
            fallback = fallback_mgr.get_fallback(tool)
            if fallback and fallback_mgr.registry.is_available(fallback):
                print(f"  🔄 Fallback: {tool} → {fallback}")
                adjusted_tools.append(fallback)
                fallback_tools.append(fallback)
                # Update commands for fallback tool
                if tool in commands:
                    commands[fallback] = commands.pop(tool)
                # Still notify about the original tool
                unavailable_tools.append({
                    "tool": tool,
                    "hint": install_hint,
                    "fallback": fallback
                })
            else:
                logger.warning(f"Tool unavailable: {tool}")
                unavailable_tools.append({
                    "tool": tool,
                    "hint": install_hint,
                    "fallback": None
                })
        else:
            adjusted_tools.append(tool)
    
    # Build notification message for unavailable tools
    unavailable_msg = ""
    if unavailable_tools:
        unavailable_msg = "\n\n⚠️ **Some suggested tools are not installed:**\n"
        for ut in unavailable_tools:
            if ut["fallback"]:
                unavailable_msg += f"• `{ut['tool']}` → using `{ut['fallback']}` instead\n"
            else:
                unavailable_msg += f"• `{ut['tool']}` - {ut['hint']}\n"
    
    return adjusted_tools, fallback_tools, unavailable_msg


class PlannerTool(AgentTool):
    """
    Tool for planning security tasks using specialized agents.
    
    Main purpose:
    - Aggregate context from past scans and findings
    - Route query to appropriate specialized agent (recon, scan, vuln, exploit, etc.)
    - Get plan (tools, commands, reasoning) from agent
    - Enforce phase gates (prevent skipping phases)
    - Validate plan (check for errors/warnings)
    - Check tool availability and suggest fallbacks
    """
    
    def execute(self, query: str = None, context: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """
        Plan using specialized agents via Coordinator.
        
        Args:
            query: User query string
            context: Current context dictionary
            
        Returns:
            Dictionary with plan (tools, commands, reasoning) and context updates
        """
        if query is None and self.state:
            query = self.state.get("query", "")
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        
        coordinator = get_coordinator()
        
        # STEP 1: Context aggregation
        agg_context, context = _aggregate_context(query, self.state, context)
        
        # STEP 1.5: Checklist integration (delegated to analyzer service)
        query, context = prepare_query_with_task(query, context)
        
        # STEP 2: Get plan from coordinator
        print(f"  🧠 Coordination: Routing '{query}'...")
        
        # Load analyzer recommendation if needed
        query_lower = query.lower()
        _load_analyzer_recommendation(context, query_lower)
        
        try:
            # Pass enriched context to coordinator
            enriched_context = {
                **context,
                "aggregated_facts": len(agg_context.relevant_facts),
                "has_past_failures": len(agg_context.past_failures) > 0,
                "suggested_cves": [c.get("cve_id") for c in agg_context.relevant_cves[:3]],
            }
            
            plan = coordinator.plan_with_agent(query, enriched_context)
            
            agent_name = plan.get("agent", "base")
            tools = plan.get("tools", [])
            commands = plan.get("commands", {})
            reasoning = plan.get("reasoning") or f"I have selected {len(tools)} tools to proceed with your request."
            
            print(f"  🤖 Agent '{agent_name}' selected tools: {tools}")
            
            # STEP 2.5: Phase gate check
            allowed_tools, blocked_tools, block_result = _check_phase_gates(tools, context)
            
            if block_result:
                # All tools blocked
                block_result["context"] = context
                return block_result
            
            # If some tools blocked, use only allowed ones and add warning
            if blocked_tools:
                tools = allowed_tools
                blocked_names = [t for t, _ in blocked_tools]
                reasoning += f"\n\n⚠️ Skipped {len(blocked_tools)} tools due to phase requirements: {', '.join(blocked_names)}"
            
            # STEP 3: Validation
            validation, validation_dict, reasoning = _validate_plan(plan, context)
            plan["reasoning"] = reasoning  # Update reasoning in plan
            
            # STEP 4: Check tool availability
            tools, fallback_tools, unavailable_msg = _check_tool_availability(tools, commands, context)
            
            # Append unavailable tools message to reasoning
            if unavailable_msg:
                reasoning += unavailable_msg
            
            # Store current agent in context for executor
            context["current_agent"] = agent_name
            
            return {
                "suggested_tools": tools,
                "suggested_commands": commands,
                "suggestion_message": reasoning,
                "context": context,
                "aggregated_context": agg_context.to_prompt_context() if agg_context else None,
                "validation_result": validation_dict,
                "fallback_tools": fallback_tools,
                "retry_count": self.state.get("retry_count", 0) if self.state else 0,
                "next_action": "end"  # Wait for user approval
            }
            
        except Exception as e:
            logger.error(f"Planning failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                "suggested_tools": [], 
                "suggestion_message": f"Planning failed: {e}",
                "next_action": "respond"
            }
