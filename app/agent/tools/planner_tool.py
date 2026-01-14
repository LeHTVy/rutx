"""
Planner Tool

Extracts and encapsulates logic from planner_node().
Plans using specialized agents via Coordinator.
"""
from typing import Dict, Any, Optional
from app.agent.tools.base import AgentTool
from app.agent.orchestration import get_coordinator
from app.ui import get_logger

logger = get_logger()
from app.agent.core import (
    get_context_manager, get_context_aggregator,
    get_phase_manager, PHASE_NAMES, PhaseGateAction,
)
from app.agent.utils import (
    get_plan_validator, get_fallback_manager,
)
from app.tools.registry import get_registry


class PlannerTool(AgentTool):
    """Tool for planning security tasks using specialized agents."""
    
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
        
        # ============================================================
        # STEP 1: CONTEXT AGGREGATION (Pre-LLM)
        # ============================================================
        aggregator = get_context_aggregator()
        ctx_manager = get_context_manager()
        
        # Aggregate all relevant context before planning
        agg_context = aggregator.aggregate_for_planning(query, self.state)
        
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
        
        # ============================================================
        # STEP 1.5: CHECKLIST INTEGRATION (if checklist exists)
        # ============================================================
        checklist = context.get("checklist", [])
        current_task_id = context.get("current_task_id")
        checklist_manager = get_checklist_manager()
        session_id = context.get("session_id", "default")
        
        # If checklist exists, get next task
        if checklist:
            # Load checklist into manager if not already loaded
            if not checklist_manager.get_checklist(session_id):
                from app.agent.core import Task
                for task_data in checklist:
                    task = Task.from_dict(task_data)
                    checklist_manager.add_task(task, session_id)
            
            # Get next task from checklist
            next_task = checklist_manager.get_next_task(session_id)
            
            if next_task:
                # Mark task as in progress
                checklist_manager.mark_in_progress(next_task.id, session_id)
                context["current_task_id"] = next_task.id
                
                # Update query to focus on current task
                query = f"{query} - Task: {next_task.description}"
                
                # Add task's required tools as context
                if next_task.required_tools:
                    context["task_required_tools"] = next_task.required_tools
                    context["task_phase"] = next_task.phase
                
                print(f"  📋 Working on task: {next_task.description} (Phase {next_task.phase})")
            else:
                # All tasks done or blocked
                progress = checklist_manager.get_progress(session_id)
                if progress["completed"] == progress["total"]:
                    print(f"  ✅ All checklist tasks completed ({progress['completed']}/{progress['total']})")
                    context["checklist_complete"] = True
                else:
                    print(f"  ⚠️ No available tasks (Progress: {progress['completed']}/{progress['total']})")
        
        # ============================================================
        # STEP 2: GET PLAN FROM COORDINATOR
        # ============================================================
        print(f"  🧠 Coordination: Routing '{query}'...")
        
        analyzer_next_tool = context.get("analyzer_next_tool") or context.get("user_requested_tool")
        
        # If "do the next step" and no analyzer recommendation in context, force load from session memory
        query_lower = query.lower()
        # Match: "next step", "do the next step", "do as your suggestion", "as your suggestion", etc.
        is_suggestion_command = (
            "next step" in query_lower or 
            ("do" in query_lower and "step" in query_lower) or 
            ("suggest" in query_lower and "step" in query_lower) or
            ("do" in query_lower and "suggestion" in query_lower) or
            ("as" in query_lower and "suggestion" in query_lower) or
            ("your suggestion" in query_lower)
        )
        if is_suggestion_command and not analyzer_next_tool:
            try:
                from app.memory import get_session_memory
                session_memory = get_session_memory()
                if hasattr(session_memory, 'analyzer_recommendations') and session_memory.analyzer_recommendations:
                    rec = session_memory.analyzer_recommendations
                    if rec and rec.get("next_tool"):
                        analyzer_next_tool = rec.get("next_tool")
                        context["analyzer_next_tool"] = analyzer_next_tool
                        context["analyzer_next_target"] = rec.get("next_target")
                        context["analyzer_next_reason"] = rec.get("next_reason")
                        context["user_requested_tool"] = analyzer_next_tool  # Also set user_requested_tool
            except Exception:
                pass
        
        try:
            # Ensure analyzer recommendation is in context
            if not context.get("analyzer_next_tool") and not context.get("user_requested_tool"):
                # Try to load from session memory as fallback
                try:
                    from app.memory import get_session_memory
                    session_memory = get_session_memory()
                    if hasattr(session_memory, 'analyzer_recommendations') and session_memory.analyzer_recommendations:
                        rec = session_memory.analyzer_recommendations
                        if rec and rec.get("next_tool"):
                            context["analyzer_next_tool"] = rec.get("next_tool")
                            context["analyzer_next_target"] = rec.get("next_target")
                            context["analyzer_next_reason"] = rec.get("next_reason")
                except Exception:
                    pass
            
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
            
            # ============================================================
            # STEP 2.5: PHASE GATE CHECK - Enforce pentest phase order
            # ============================================================
            phase_mgr = get_phase_manager()
            phase_status = phase_mgr.get_phase_status(context)
            current_phase = phase_status["current_phase"]
            current_phase_name = phase_status["current_phase_name"]
            
            # Check each tool against phase gates
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
            
            # If ALL tools are blocked, return remediation instead of suggestion
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
                
                return {
                    "suggested_tools": [],
                    "suggestion_message": block_message,
                    "context": context,
                    "next_action": "end"
                }
            
            # If some tools blocked, use only allowed ones and add warning
            if blocked_tools:
                tools = allowed_tools
                blocked_names = [t for t, _ in blocked_tools]
                reasoning += f"\n\n⚠️ Skipped {len(blocked_tools)} tools due to phase requirements: {', '.join(blocked_names)}"
            
            # ============================================================
            # STEP 3: VALIDATION (Post-LLM)
            # ============================================================
            validator = get_plan_validator()
            validation = validator.validate_plan(plan, context)
            
            # Log validation issues
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
            
            # ============================================================
            # STEP 4: CHECK TOOL AVAILABILITY & NOTIFY USER
            # ============================================================
            fallback_mgr = get_fallback_manager()
            registry = get_registry()
            adjusted_tools = []
            fallback_tools = []
            unavailable_tools = []  # Track unavailable tools to notify user
            
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
            
            # Update tools with fallbacks applied
            tools = adjusted_tools
            
            # Build notification message for unavailable tools
            unavailable_msg = ""
            if unavailable_tools:
                unavailable_msg = "\n\n⚠️ **Some suggested tools are not installed:**\n"
                for ut in unavailable_tools:
                    if ut["fallback"]:
                        unavailable_msg += f"• `{ut['tool']}` → using `{ut['fallback']}` instead\n"
                    else:
                        unavailable_msg += f"• `{ut['tool']}` - {ut['hint']}\n"
            
            # Append to reasoning
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
