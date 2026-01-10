"""
LangGraph Agent - State Machine for Pentest Agent
==================================================

Proper agentic flow:
1. Intent Node (LLM) - Classify user input
2. Planner Node (LLM) - Suggest tools, NO auto-execution
3. Confirm Node - Wait for user approval
4. Executor Node (CODE) - Run tools via registry
5. Analyzer Node (LLM) - Decide DONE/CONTINUE

Key principle: LLM plans, CODE executes, LLM analyzes.
"""
from typing import TypedDict, List, Dict, Any, Literal, Optional, Annotated
from enum import Enum
import operator
import json
import re

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from app.llm import get_llm_config
from app.tools.registry import get_registry

# Reorganized imports - using new folder structure
from app.agent.orchestration import get_coordinator
from app.agent.core import (
    get_context_manager, SessionContext,
    get_context_aggregator, AggregatedContext,
    get_phase_manager, PHASE_NAMES,
)
from app.agent.utils import (
    get_plan_validator, get_tool_validator, ValidationResult,
    get_fallback_manager,
)


# ============================================================
# STATE SCHEMA
# ============================================================

class Message(TypedDict):
    """A message in the conversation."""
    role: str  # "user" or "assistant"
    content: str


class AgentState(TypedDict):
    """State passed between nodes in the graph."""
    
    # User input
    query: str
    
    # Conversation history (persisted across turns)
    messages: List[Message]
    
    # Intent classification
    intent: str  # "security_task", "question", "confirm", "tool_select"
    
    # Planning
    suggested_tools: List[str]
    suggested_commands: Dict[str, str]  # {tool_name: command_name} from semantic search
    suggestion_message: str
    tool_params: Dict[str, Any]
    
    # Execution
    confirmed: bool
    selected_tools: List[str]
    execution_results: Dict[str, Any]
    
    # Memory/Context (accumulated)
    context: Annotated[Dict[str, Any], operator.or_]
    
    # NEW: Aggregated context from ContextAggregator
    aggregated_context: Optional[Dict[str, Any]]
    
    # NEW: Validation results from validators
    validation_result: Optional[Dict[str, Any]]
    
    # NEW: Fallback tracking
    retry_count: int
    fallback_tools: List[str]
    
    # Output
    response: str
    
    # Flow control
    next_action: str  # "plan", "confirm", "execute", "analyze", "respond", "end"


# ============================================================
# LLM CLIENT - Imported from app.llm.client
# ============================================================

from app.llm.client import OllamaClient, get_current_model, set_current_model


# ============================================================
# NODE IMPLEMENTATIONS
# ============================================================

def intent_node(state: AgentState) -> AgentState:
    """
    Classify user intent using LLM.
    
    Returns:
    - security_task: Needs tool execution (scan, exploit, enumerate, etc.)
    - memory_query: User wants to see stored data (subdomains, results, findings)
    - question: Simple question, answer directly
    - confirm: User confirming/denying previous suggestion
    """
    # Sanitize input - remove box-drawing characters and extra whitespace
    query = state["query"]
    # Remove common terminal box-drawing and special characters
    query = re.sub(r'[│┌┐└┘├┤┬┴┼─═║╔╗╚╝╠╣╦╩╬]', '', query)
    query = re.sub(r'\s+', ' ', query)  # Collapse whitespace
    query = query.lower().strip()
    
    suggested_tools = state.get("suggested_tools", [])
    context = state.get("context", {})
    
    # ─────────────────────────────────────────────────────────
    # AUTONOMOUS MODE DETECTION
    # "attack" command enables auto_mode for full autonomous chain
    # ─────────────────────────────────────────────────────────
    auto_mode_triggers = ["attack ", "autonomous ", "auto ", "pentest ", "pwn ", "hack "]
    if any(query.startswith(trigger) for trigger in auto_mode_triggers):
        context["auto_mode"] = True
        context["auto_chain_count"] = 0
        print(f"  🤖 AUTONOMOUS MODE enabled - will auto-chain tools")
        # Don't modify the query, just set the flag
    
    # Quick confirmations (exact matches - no LLM needed)
    if query in ["yes", "y", "ok", "go", "run", "execute", "proceed"]:
        return {**state, "intent": "confirm", "confirmed": True}

    if suggested_tools and ("yes" in query or query.endswith(" y")):
        print(f"  📋 Confirming pending suggestion: {suggested_tools}")
        return {**state, "intent": "confirm", "confirmed": True}
    
    if query in ["no", "n", "cancel", "stop", "abort"]:
        return {**state, "intent": "confirm", "confirmed": False}
    
    if query.startswith("no") and len(query) > 5:
        correction_indicators = ["its", "it's", "the one", "actually", "meant", "in ", "from ", ".za", ".co", ".com"]
        if any(ind in query for ind in correction_indicators):
            print(f"  🔄 Target correction detected: routing to verification")
            context["is_correction"] = True
            context["correction_query"] = state["query"]
            return {**state, "intent": "security_task", "context": context}
    
    if query.startswith(("yes", "ok", "let's", "lets", "go with")):
        is_short_confirmation = len(query) < 20
        
        selected = []
        for tool in suggested_tools:
            if tool.lower() in query:
                selected.append(tool)
        
        if selected:
            return {
                **state,
                "intent": "confirm",
                "confirmed": True,
                "selected_tools": selected
            }
        
        # Only confirm if we have pending tools AND query is short
        if suggested_tools and is_short_confirmation:
            return {**state, "intent": "confirm", "confirmed": True}
    
    # ============================================================
    # LLM-BASED INTENT CLASSIFICATION
    # ============================================================
    llm = OllamaClient()
    
    # Build context summary
    context_summary = ""
    if context.get("tools_run"):
        context_summary += f"Tools already run: {', '.join(context.get('tools_run', []))}\n"
    if context.get("subdomain_count"):
        context_summary += f"Subdomains found: {context.get('subdomain_count')}\n"
    if context.get("has_ports"):
        context_summary += "Port scan completed\n"
    if context.get("detected_tech"):
        context_summary += f"Technologies detected: {', '.join(context.get('detected_tech', [])[:5])}\n"
    if context.get("subdomains"):
        context_summary += f"Subdomains stored in memory: {len(context.get('subdomains', []))}\n"
    
    # Check if query contains a domain/IP - strong signal for SECURITY_TASK
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    has_domain = bool(re.search(domain_pattern, state["query"]))
    
    # Load intent prompt
    from app.agent.prompt_loader import format_prompt
    
    prompt = format_prompt("intent_classifier",
        query=state["query"],
        context_summary=context_summary if context_summary else "No prior context",
        domain_note="NOTE: Message contains a domain/IP address" if has_domain else ""
    )

    # ─────────────────────────────────────────────────────────
    # INTELLIGENT INTENT CLASSIFICATION
    # Uses: Semantic understanding, Context retrieval, Rich prompts
    # ─────────────────────────────────────────────────────────
    
    print("  🧠 Intelligence layer analyzing...")
    
    try:
        # Use intelligence layer for semantic understanding
        from app.agent.intelligence import get_intelligence
        intel = get_intelligence()
        
        # Get semantic understanding of query
        understanding = intel.understand_query(state["query"], context)
        
        # Store understanding in state for later use
        state["query_understanding"] = understanding
        
        # Use intelligence layer for intent classification
        intent = intel.classify_intent(state["query"], context)
        
        # Log what we understood
        if understanding.get("detected_target"):
            print(f"  📍 Target: {understanding['detected_target']}")
        if understanding.get("relevant_tools"):
            print(f"  🔧 Suggested tools: {', '.join(understanding['relevant_tools'][:3])}")
        print(f"  → Intent: {intent.upper()}")
        
        intent_map = {
            "SECURITY_TASK": "security_task",
            "MEMORY_QUERY": "memory_query", 
            "QUESTION": "question"
        }
        return {**state, "intent": intent_map.get(intent, "security_task")}
        
    except Exception as e:
        print(f"  ⚠️ Intelligence layer: {e}, using fallback")
        
        # Fallback to simple LLM classification
        try:
            response = llm.generate(prompt, timeout=30)
            response_clean = response.strip().upper()
            
            if "MEMORY" in response_clean:
                return {**state, "intent": "memory_query"}
            elif "QUESTION" in response_clean:
                return {**state, "intent": "question"}
            else:
                return {**state, "intent": "security_task"}
        except Exception:
            return {**state, "intent": "security_task"}


# ============================================================
# PHASE INFERENCE - Imported from intelligence module
# ============================================================

from app.agent.intelligence import infer_phase



def target_verification_node(state: AgentState) -> AgentState:
    """
    Verify and resolve target ambiguity using LLM intelligence.
    
    NO HARDCODED KEYWORDS. All extraction and analysis is LLM-driven.
    
    Flow:
    1. If query has clear domain/IP, bypass (existing).
    2. LLM extracts entity name and user context from FULL query.
    3. Web search using LLM-generated query.
    4. LLM analyzes results with user context to resolve or ask.
    """
    import re
    import json
    
    intent = state.get("intent")
    
    # Only verify for security tasks
    if intent != "security_task":
        return state
        
    context = state.get("context", {})
    query = state["query"]
    
    # helper to proceed to planner
    def proceed_to_planner():
        return {**state, "next_action": "planner"}
    
    # ============================================================
    # CORRECTION DETECTION: Check context flag (set by intent_node)
    # The LLM extraction will also detect corrections semantically
    # ============================================================
    is_correction_from_context = context.get("is_correction", False)
    
    # If correction flag is set, clear the old target BEFORE we check for existing targets
    if is_correction_from_context:
        old_target = context.get("target_domain")
        if old_target:
            print(f"  🗑️ Correction mode: clearing previous target '{old_target}'")
            context.pop("target_domain", None)
            context["last_candidate"] = old_target.split(".")[0] if "." in old_target else old_target
        context["is_correction"] = False  # Reset flag
    
    # 1. Check if we already have a verified target in context (SKIP re-verification)
    # BUT only if this is NOT a correction!
    if not is_correction_from_context:
        if context.get("target_domain") and "." in context.get("target_domain"):
            print(f"  📍 Using verified target: {context.get('target_domain')}")
            return proceed_to_planner()
        if context.get("last_domain") and "." in context.get("last_domain"):
            return proceed_to_planner()
        
    # 2. Quick regex check for explicit domain/IP (bypass verification)
    # NOTE: Even if the domain looks like a typo, store it and proceed
    # The LLM in planner_node will correct it if needed
    domain_match = re.search(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', query)
    if domain_match:
        potential_domain = domain_match.group()
        # Store it even if it might be a typo - better to have something than nothing
        if not context.get("last_domain"):
            context["last_domain"] = potential_domain
            print(f"  📍 Domain found in query: {potential_domain}")
        return {**state, "context": context, "next_action": "planner"}
    
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
    if ip_match:
        return proceed_to_planner()

    
    # 3. LLM-ONLY Target Extraction (NO KEYWORD LISTS)
    try:
        from app.agent.prompt_loader import format_prompt
        from app.llm.client import OllamaClient
        
        # Build conversation context from recent messages
        messages = state.get("messages", [])
        conversation_context = "None"
        if messages:
            recent = messages[-6:]  # Last 3 exchanges
            context_lines = []
            for msg in recent:
                role = msg.get("role", "user").upper()
                content = msg.get("content", "")[:200]
                context_lines.append(f"{role}: {content}")
            conversation_context = "\n".join(context_lines) if context_lines else "None"
        
        # Also include any stored entities from context
        if context.get("last_candidate"):
            conversation_context += f"\n(Previously discussed: {context.get('last_candidate')})"
        if context.get("target_domain"):
            conversation_context += f"\n(Resolved domain: {context.get('target_domain')})"
        
        extraction_prompt = format_prompt("target_extraction", query=query, conversation_context=conversation_context)
        llm = OllamaClient()
        extraction_response = llm.generate(extraction_prompt, timeout=20).strip()
        
        # Parse extraction JSON
        extraction = {}
        try:
            json_match = re.search(r'\{.*\}', extraction_response, re.DOTALL)
            if json_match:
                extraction = json.loads(json_match.group(), strict=False)
        except Exception as e:
            print(f"  ⚠️ Extraction parse error: {e}")
        
        entity_name = extraction.get("entity_name", "").strip()
        user_context = extraction.get("user_context", "")
        search_query = extraction.get("search_query", "")
        is_followup = extraction.get("is_followup", False)
        is_correction = extraction.get("is_correction", False)  # LLM detects corrections semantically
        resolved_domain = extraction.get("resolved_domain", "")
        corrected_from = extraction.get("corrected_from")
        confidence = extraction.get("confidence", "medium")
        interpretation = extraction.get("interpretation", "")
        
        # Log typo corrections
        if corrected_from:
            print(f"  ✏️ Corrected typo: '{corrected_from}' → '{entity_name or resolved_domain}'")
        
        # Log LLM interpretation for debugging
        if interpretation:
            print(f"  💭 Understood: {interpretation}")
        
        # ============================================================
        # LLM DETECTED CORRECTION: Clear old target and re-verify
        # This is the semantic approach - LLM understands "no its X" is a correction
        # ============================================================
        if is_correction:
            old_target = context.get("target_domain")
            if old_target:
                print(f"  🔄 LLM detected correction: clearing '{old_target}'")
                context.pop("target_domain", None)
                context["last_candidate"] = old_target.split(".")[0] if "." in old_target else old_target
        
        # Handle follow-up references (pronouns, "assess them", etc.)
        if is_followup and not is_correction:
            if context.get("last_candidate") and not entity_name:
                entity_name = context.get("last_candidate")
                print(f"  🧠 Follow-up detected, using: {entity_name}") 
            if context.get("target_domain") and not resolved_domain:
                resolved_domain = context.get("target_domain")
        
        # If LLM extracted a domain directly (e.g., "no, its hellogroup.co.za" or corrected typo)
        if resolved_domain and "." in resolved_domain:
            print(f"  ✅ Direct domain resolved: {resolved_domain}")
            context["target_domain"] = resolved_domain
            context["last_candidate"] = entity_name or resolved_domain.split(".")[0]
            return {**state, "context": context, "next_action": "planner"}
        
        if not entity_name or len(entity_name) < 2:
            # Last resort: check if we have a stored domain to use
            if context.get("target_domain"):
                print(f"  🧠 Using stored domain: {context.get('target_domain')}")
                return {**state, "next_action": "planner"}
            print("  ⚠️ No entity extracted. Proceeding to planner.")
            return proceed_to_planner()
        
        print(f"  🤔 Target '{entity_name}' (context: {user_context or 'none'}) detected. Verifying...")
        
        # 4. Web Search with LLM-generated query
        from app.tools.custom.web_research import web_search
        
        if not search_query:
            search_query = f"{entity_name} {user_context} official website".strip()
        
        print(f"  🌐 Researching: {search_query}...")
        research = web_search(search_query, max_results=5)
        
        if not research or not research.get("success"):
            print("  ⚠️ No search results. Proceeding to planner.")
            return proceed_to_planner()
        
        research_str = ""
        for i, (snip, src) in enumerate(zip(research.get("snippets", []), research.get("sources", []))):
            research_str += f"Source {i+1}: {src.get('title', 'N/A')} ({src.get('url', '')})\nSnippet: {snip}\n\n"
        
        # 5. LLM Analysis with Full Context
        verification_prompt = format_prompt(
            "target_verification",
            entity_name=entity_name,
            original_query=query,
            user_context=user_context or "None provided",
            research_str=research_str
        )
        
        response = llm.generate(verification_prompt, timeout=45).strip()
        
        # Parse verification JSON (with strict=False for control chars)
        analysis = {}
        try:
            clean_response = re.sub(r'^```json\s*', '', response, flags=re.MULTILINE)
            clean_response = re.sub(r'^```\s*', '', clean_response, flags=re.MULTILINE)
            clean_response = re.sub(r'\s*```$', '', clean_response)
            clean_response = re.sub(r'//.*$', '', clean_response, flags=re.MULTILINE)  # Remove comments
            
            json_match = re.search(r'\{.*\}', clean_response, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group(), strict=False)
        except Exception as e:
            print(f"  ⚠️ Verification parse error: {e}")
        
        status = analysis.get("status", "unknown")
        
        # Store candidate for follow-up queries
        context["last_candidate"] = entity_name
        
        if status == "clear" and analysis.get("primary_domain"):
            real_domain = analysis.get("primary_domain")
            print(f"  ✅ Resolved '{entity_name}' -> '{real_domain}'")
            return {
                **state,
                "response": f"Did you mean **{real_domain}**? I found this as the likely domain for '{entity_name}'.\n\nType 'yes' to proceed with **{real_domain}**, or type the correct domain.",
                "suggested_tools": [],
                "context": {**context, "target_domain": real_domain},
                "next_action": "end"
            }
            
        elif status == "ambiguous":
            print(f"  ❓ Ambiguous target '{entity_name}'. Asking user...")
            question = analysis.get("clarification_question", f"I found multiple entities for '{entity_name}'. Could you specify?")
            
            candidates_str = ""
            for c in analysis.get("candidates", [])[:3]:
                loc = c.get('location', 'Global')
                if isinstance(loc, list):
                    loc = ", ".join(loc[:2])
                candidates_str += f"- **{c.get('name')}** ({loc}): {c.get('domain')} - {c.get('desc', 'N/A')}\n"
            
            return {
                **state,
                "response": f"{question}\n\nI found these potential matches:\n{candidates_str}\n\nPlease specify which one you mean, or provide the domain directly.",
                "context": context,
                "next_action": "end"
            }
        else:
            return proceed_to_planner()
            
    except Exception as e:
        print(f"  ⚠️ Verification error: {e}")
        return proceed_to_planner()




def planner_node(state: AgentState) -> AgentState:
    """
    Plan using specialized agents via Coordinator.
    
    ENHANCED with Cursor-style patterns:
    1. Context Aggregation - Gather all context BEFORE LLM call
    2. Coordinator routes query to appropriate agent
    3. Validation - Check plan BEFORE returning to user
    4. Fallback - Suggest alternatives for unavailable tools
    """
    coordinator = get_coordinator()
    context = state.get("context", {})
    query = state["query"]
    
    # ============================================================
    # STEP 1: CONTEXT AGGREGATION (Pre-LLM)
    # ============================================================
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
    
    # ============================================================
    # STEP 2: GET PLAN FROM COORDINATOR
    # ============================================================
    print(f"  🧠 Coordination: Routing '{query}'...")
    
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
        gate_message = ""
        
        for tool in tools:
            gate_result = phase_mgr.check_phase_gate(tool, context)
            
            if gate_result.is_blocked:
                blocked_tools.append((tool, gate_result))
                print(f"  🚫 Phase Gate BLOCKED: {tool} (Phase {gate_result.requested_phase})")
            else:
                allowed_tools.append(tool)
                if gate_result.action == PhaseGateAction.WARN:
                    print(f"  ⚠️ Phase Gate WARN: {tool} (Phase {gate_result.requested_phase})")
        
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
                **state,
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
            print(f"  ⚠️ Validation issues: {', '.join(validation.errors)}")
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
            print(f"  ⚠️ Warnings: {', '.join(validation.warnings)}")
        
        # ============================================================
        # STEP 4: FALLBACK FOR UNAVAILABLE TOOLS
        # ============================================================
        fallback_mgr = get_fallback_manager()
        adjusted_tools = []
        fallback_tools = []
        
        for tool in tools:
            if not fallback_mgr.registry.is_available(tool):
                fallback = fallback_mgr.get_fallback(tool)
                if fallback:
                    print(f"  🔄 Fallback: {tool} → {fallback}")
                    adjusted_tools.append(fallback)
                    fallback_tools.append(fallback)
                    # Update commands for fallback tool
                    if tool in commands:
                        commands[fallback] = commands.pop(tool)
                else:
                    print(f"  ❌ Tool unavailable, no fallback: {tool}")
            else:
                adjusted_tools.append(tool)
        
        # Update tools with fallbacks applied
        tools = adjusted_tools
        
        # Store current agent in context for executor
        context["current_agent"] = agent_name
        
        return {
            **state,
            "suggested_tools": tools,
            "suggested_commands": commands,
            "suggestion_message": reasoning,
            "context": context,
            "aggregated_context": agg_context.to_prompt_context() if agg_context else None,
            "validation_result": validation_dict,
            "fallback_tools": fallback_tools,
            "retry_count": state.get("retry_count", 0),
            "next_action": "end"  # Wait for user approval
        }
        
    except Exception as e:
        print(f"  ⚠️ Planning failed: {e}")
        import traceback
        traceback.print_exc()
        return {
            **state, 
            "suggested_tools": [], 
            "suggestion_message": f"Planning failed: {e}",
            "next_action": "respond"
        }



def confirm_node(state: AgentState) -> AgentState:
    """
    Handle user confirmation.
    
    This node is reached when user responds to a suggestion.
    User can say "yes lets use amass" to select specific tools.
    """
    if state.get("confirmed", False):
        selected = state.get("selected_tools") or state.get("tools") or state.get("suggested_tools", [])
        context = state.get("context", {})
        if not selected and context.get("target_domain"):
            print(f"  ✓ Target '{context.get('target_domain')}' confirmed. Getting tool suggestions...")
            return {
                **state,
                "next_action": "planner"
            }
        
        print(f"  ✓ User confirmed. Running: {selected}")
        
        return {
            **state,
            "selected_tools": selected,
            "next_action": "executor"
        }
    else:
        # User declined
        return {
            **state,
            "response": "Cancelled. What would you like to do instead?",
            "next_action": "respond"
        }


def validate_tool_params(tool_name: str, command: str, params: dict, registry) -> tuple:
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
    import re
    missing = []
    for arg in template.args:
        placeholders = re.findall(r'\{(\w+)\}', arg)
        for p in placeholders:
            if not params.get(p):
                missing.append(p)
    
    if missing:
        return False, missing, f"Missing parameters: {', '.join(missing)}"
    
    return True, [], ""


def get_adaptive_timeout(base_timeout: int, context: dict, tool_name: str) -> int:
    """
    Scale timeout based on number of targets and tool type.
    """
    n_subdomains = len(context.get("subdomains", []))
    n_ports = len(context.get("open_ports", []))
    
    # Base scaling factor
    scale = 1
    
    # Scale for multi-target scans
    if n_subdomains > 10:
        scale = max(scale, n_subdomains // 10)
    
    # Minimum timeouts for slow tools
    min_timeouts = {
        "nmap": 300,
        "nuclei": 600,
        "wpscan": 300,
        "nikto": 300,
        "amass": 600,
        "masscan": 300,
    }
    
    min_t = min_timeouts.get(tool_name, base_timeout)
    scaled = max(min_t, base_timeout * scale)
    
    # Cap at 30 minutes
    return min(scaled, 1800)

def executor_node(state: AgentState) -> AgentState:
    """
    Execute tools via registry.
    
    ENHANCED with Cursor-style patterns:
    - Uses ContextManager for target resolution
    - Integrates FallbackManager for failure handling
    - Records failures for learning
    
    This is PURE CODE - no LLM involvement.
    Auditable, safe, controlled.
    """
    registry = get_registry()
    results = {}
    context = state.get("context", {})
    
    tools = state.get("selected_tools", [])
    params = state.get("tool_params", {})
    
    # ============================================================
    # USE CONTEXT MANAGER FOR TARGET RESOLUTION
    # ============================================================
    ctx_manager = get_context_manager()
    fallback_mgr = get_fallback_manager()
    
    # Sync context manager with current state
    if context:
        ctx_manager.update_context(context)
    
    # Get prioritized target from ContextManager
    resolved_target = ctx_manager.get_target()
    
    # CRITICAL: Ensure domain is in params from context (backwards compatible)
    if not params.get("domain"):
        params["domain"] = resolved_target or context.get("last_domain") or context.get("target_domain")
        
    if not params.get("target"):
        params["target"] = resolved_target or context.get("last_domain") or context.get("target_domain")
    
    # Use full URL if available (for web-based attacks)
    if not params.get("url") and context.get("url_target"):
        params["url"] = context.get("url_target")
        # Also extract domain from URL for target
        url = context.get("url_target")
        if url and not params.get("target"):
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            params["target"] = parsed.netloc
            params["domain"] = parsed.netloc

    
    # Also build URL for web tools if needed
    domain = params.get("domain") or params.get("target")
    if domain and not params.get("url"):
        params["url"] = f"https://{domain}"
    
    # Also set host for tools that need it
    if domain and not params.get("host"):
        params["host"] = domain
    
    # ============================================================
    # DEFAULT PARAMETERS FOR COMMON TOOLS
    # ============================================================
    
    # Default wordlist paths (common Kali/SecLists locations)
    if not params.get("wordlist"):
        # Try common wordlist locations
        import os
        wordlist_paths = [
            "wordlists/common.txt", 
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ]
        for wl in wordlist_paths:
            if os.path.exists(wl):
                params["wordlist"] = wl
                break
        if not params.get("wordlist"):
            # Fallback - use local wordlist
            params["wordlist"] = "wordlists/common.txt"
    
    # For brute-force tools, use password wordlist instead of directory wordlist
    if any(t in ["hydra", "medusa", "john", "hashcat"] for t in tools):
        import os
        password_lists = [
            "wordlists/passwords.txt",
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        ]
        for pwl in password_lists:
            if os.path.exists(pwl):
                params["wordlist"] = pwl
                break
    
    # Default user for brute-force tools (hydra, medusa)
    if not params.get("user"):
        params["user"] = "admin"  # Most common default username
    
    # Default port for nikto if not specified
    if not params.get("port"):
        params["port"] = "443"
    
    # Default ports for port scanners (masscan, nmap)
    if not params.get("ports"):
        from app.rag.port_metadata import PORT_PROFILES
        params["ports"] = PORT_PROFILES["critical"]
    
    # Default query for searchsploit (use domain/tech if available)
    if not params.get("query"):
        detected_tech = context.get("detected_tech", [])
        if detected_tech:
            params["query"] = detected_tech[0]  # Use first detected tech
        else:
            params["query"] = params.get("domain") or params.get("target") or "apache"
    
    # Clean, simplified output - only show what matters
    target_display = params.get("url") or params.get("target") or params.get("domain") or "unknown"
    
    # TODO: Parallel execution - requires refactoring executor into _execute_tool helper
    # For now, run tools sequentially
    if len(tools) > 1:
        print(f"  🚀 Executing {len(tools)} tools SEQUENTIALLY: {', '.join(tools)} on {target_display}")
    else:
        print(f"  🚀 Executing: {', '.join(tools)} on {target_display}")
    
    for tool_name in tools:
        if not registry.is_available(tool_name):
            results[tool_name] = {
                "success": False,
                "output": f"Tool not available: {tool_name}"
            }
            continue
        
        spec = registry.tools.get(tool_name)
        if not spec or not spec.commands:
            results[tool_name] = {
                "success": False,
                "output": f"No commands for: {tool_name}"
            }
            continue
        
        # ============================================================
        # CLATSCOPE OSINT - Python-based, not CLI
        # ============================================================
        if tool_name == "clatscope":
            from app.tools.specs.osint import execute_clatscope, format_clatscope_result
            
            # Determine which OSINT command to run based on params/query
            osint_command = params.get("command", "whois")  # Default to whois
            
            # Auto-detect command from params
            if params.get("ip") or params.get("target"):
                if params.get("ip"):
                    osint_command = "ip"
            if params.get("phone"):
                osint_command = "phone"
            if params.get("email"):
                osint_command = "breach" if "breach" in str(params) else "email"
            
            print(f"  🔍 OSINT: {osint_command}")
            
            osint_result = execute_clatscope(osint_command, params)
            formatted = format_clatscope_result(osint_command, osint_result)
            
            results[tool_name] = {
                "success": osint_result.get("success", False),
                "output": formatted,
                "data": osint_result.get("data")
            }
            
            # Update context with OSINT findings
            if osint_result.get("success"):
                data = osint_result.get("data", {})
                if osint_command == "subdomain" and data.get("subdomains"):
                    context["subdomains"] = data["subdomains"]
                    context["subdomain_count"] = len(data["subdomains"])
                    context["has_subdomains"] = True
            
            continue
        
        tool_params = params.copy()
        domain = params.get("domain", params.get("target", ""))
        subdomains = context.get("subdomains", [])
        
        # PRIORITY 1: Use command from semantic search (via suggested_commands)
        suggested_commands = state.get("suggested_commands", {})
        command = suggested_commands.get(tool_name)
        if command:
            print(f"  📋 Using semantic command: {tool_name}:{command}")
        
        BATCH_SIZE = 50 
        
        if tool_name in ["nmap", "masscan", "nuclei"] and subdomains:
            total_targets = len(subdomains)
            all_outputs = []
            
            num_batches = (total_targets + BATCH_SIZE - 1) // BATCH_SIZE
            
            if num_batches > 1:
                print(f"  📋 Scanning {total_targets} targets in {num_batches} batches")
            
            for batch_num in range(num_batches):
                start_idx = batch_num * BATCH_SIZE
                end_idx = min(start_idx + BATCH_SIZE, total_targets)
                batch_targets = subdomains[start_idx:end_idx]
                
                # Write batch to temp file
                target_file = f"/tmp/snode_targets_{domain.replace('.', '_')}_batch{batch_num+1}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(batch_targets))
                
                # Only show batch progress for multiple batches
                if num_batches > 1:
                    print(f"  📦 Batch {batch_num+1}/{num_batches}: {len(batch_targets)} targets")
                
                # Configure tool for batch
                batch_params = tool_params.copy()
                if tool_name == "nmap":
                    command = "from_file"
                    batch_params["file"] = target_file
                    batch_params["file"] = target_file
                    from app.rag.port_metadata import PORT_PROFILES
                    batch_params["ports"] = PORT_PROFILES["web"]  # Batch scans usually focus on web ports
                elif tool_name == "nuclei":
                    # Use scan_list for batch targets
                    batch_params["file"] = target_file
                    command = "scan_list"
                elif tool_name == "masscan":
                    batch_params["target"] = target_file
                    command = "scan"
                
                # Execute batch
                batch_result = registry.execute(tool_name, command, batch_params)
                
                if batch_result.success:
                    all_outputs.append(f"=== Batch {batch_num+1} ({len(batch_targets)} targets) ===\n{batch_result.output}")
                else:
                    all_outputs.append(f"=== Batch {batch_num+1} FAILED ===\n{batch_result.error}")
            
            # Combine all batch results
            combined_output = "\n\n".join(all_outputs)
            results[tool_name] = {
                "success": True,
                "output": combined_output,
                "batches": num_batches,
                "total_targets": total_targets
            }
            
            # Update context with scan info
            context["has_ports"] = True
            context["last_scan"] = {"tool": tool_name, "targets": total_targets}
            continue  # Skip the normal execution below
            
        else:
            # Single target mode
            if tool_name in ["nuclei", "nmap", "masscan"]:
                tool_params["target"] = domain
            if tool_name in ["wpscan", "nikto", "httpx", "katana", "wafw00f", "whatweb", "arjun", "dirsearch", "feroxbuster"]:
                tool_params["url"] = f"https://{domain}" if domain and not domain.startswith("http") else domain
            if tool_name in ["subfinder", "amass", "bbot", "dig"]:
                tool_params["domain"] = domain
            
            # SHODAN: Smart command selection based on target type
            if tool_name == "shodan":
                import re
                target = domain or params.get("target", "")
                user_query = state.get("query", "")
                
                # Check for Shodan filters in user query (e.g. ssl:, port:, org:)
                shodan_filters = ["ssl:", "port:", "org:", "net:", "city:", "country:", "os:"]
                has_filter = any(f in user_query for f in shodan_filters)
                
                # Extract filters from user query if present
                if has_filter:
                    query_parts = user_query.split(" on ")
                    if len(query_parts) > 1:
                        shodan_query = query_parts[-1].strip()
                    else:
                        tokens = user_query.split()
                        filter_tokens = [t for t in tokens if any(f in t for f in shodan_filters)]
                        shodan_query = " ".join(filter_tokens) if filter_tokens else f"hostname:{target}"
                    
                    command = "search"
                    tool_params["query"] = shodan_query
                    print(f"  🔍 Shodan: Using user filters '{shodan_query}'")
                    
                # Standard IP check
                elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                    command = "host"
                    tool_params["target"] = target
                    print(f"  🔍 Shodan: Using 'host' for IP {target}")
                
                else:
                    command = "search"
                    tool_params["query"] = f"hostname:{target}"
                    print(f"  🔍 Shodan: Using 'search hostname:{target}'")
            
            # Exploit tools need special handling
            if tool_name == "msfconsole":
                detected_tech = context.get("detected_tech", [])
                if detected_tech:
                    search_term = detected_tech[0] if detected_tech else "apache"
                else:
                    search_term = "apache"  # Default search
                tool_params["command"] = f"search {search_term}; exit"
                print(f"  🔴 MSF command: search {search_term}")
            
            if tool_name == "searchsploit":
                # Use domain or detected tech as search query
                query = tool_params.get("query", "")
                if not query:
                    detected_tech = context.get("detected_tech", [])
                    if detected_tech:
                        tool_params["query"] = detected_tech[0]
                    else:
                        tool_params["query"] = domain or "apache"
            
        # ============================================================
        # COMMAND SELECTION: Trust semantic search, use default as fallback
        # ============================================================
        # The semantic search already picked the best command for the context.
        # No hardcoded keyword matching - pure semantic + LLM reasoning.
        
        if command is None:
            available_commands = list(spec.commands.keys())
            # Use first available command as default
            command = available_commands[0] if available_commands else None
        
        print(f"  🔧 Executing {tool_name}:{command}")
        
        # ============================================================
        # VALIDATE PARAMETERS BEFORE EXECUTION
        # ============================================================
        is_valid, missing, error_msg = validate_tool_params(tool_name, command, tool_params, registry)
        if not is_valid and missing:
            # Try to auto-fill missing params with defaults
            for param in missing:
                if param == "wordlist" and not tool_params.get("wordlist"):
                    tool_params["wordlist"] = "wordlists/common.txt"
                elif param == "user" and not tool_params.get("user"):
                    tool_params["user"] = "admin"
                elif param == "ports" and not tool_params.get("ports"):
                    tool_params["ports"] = "22,80,443,8080,8443"
                elif param == "target" and not tool_params.get("target"):
                    tool_params["target"] = params.get("domain", "")
            
            # Re-validate after auto-fill
            is_valid, still_missing, _ = validate_tool_params(tool_name, command, tool_params, registry)
            if not is_valid and still_missing:
                results[tool_name] = {
                    "success": False,
                    "output": f"Missing required params: {', '.join(still_missing)}"
                }
                print(f"  ⚠️ Skipping {tool_name}: missing {', '.join(still_missing)}")
                continue
        
        # Get adaptive timeout based on target count
        spec = registry.tools.get(tool_name)
        template = spec.commands.get(command) if spec and command else None
        base_timeout = template.timeout if template else 300
        timeout = get_adaptive_timeout(base_timeout, context, tool_name)
        
        # Execute via specialized agent
        agent_name = context.get("current_agent", "base")
        agent = get_coordinator().get_agent(agent_name)
        
        print(f"  🤖 Agent '{agent.AGENT_NAME}' executing {tool_name}...")
        
        # Execute tool (agent decides how)
        # Note: Streaming temporarily disabled in favor of agent architecture
        execution_result = agent.execute_tool(tool_name, command, tool_params)
        
        results[tool_name] = execution_result
        
        # Update context
        if execution_result.get("success"):
            output = execution_result.get("output", "")
            
            # Print output (since we lost streaming)
            if len(output) < 1000:
                print(output)
            else:
                print(f"{output[:300]}...\n... (truncated) ...\n{output[-300:]}")
            try:
                from app.agent.utils.output_parser import OutputParser
                get_output_parser = OutputParser
                parser = get_output_parser()
                domain = params.get("domain", context.get("last_domain", ""))
                
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
                        print(f"  📊 LLM Parser: {', '.join(found_items)}")
                    
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
                        pass  # RAG storage is optional enhancement
                        
            except Exception as e:
                # Universal parser failed, continue with specific parsers
                print(f"  ⚠️ Universal parser: {e}")
            
            # ─────────────────────────────────────────────────────────
            # TOOL-SPECIFIC ENHANCEMENTS (optional, adds extra context)
            # SUBDOMAIN ENUMERATION TOOLS
            # ─────────────────────────────────────────────────────────
            if tool_name in ["subfinder", "amass", "bbot", "recon-ng", "theHarvester"]:
                context["has_subdomains"] = True
                context["last_domain"] = params.get("domain", "")
                
                import re
                subdomains = []
                hosts_with_ips = [] 
                
                if tool_name == "recon-ng":
                    lines = output.strip().split("\n")
                    current_host = None
                    for line in lines:
                        line = line.strip()
                        host_match = re.search(r'\[\*\]\s*Host:\s*(\S+)', line)
                        if host_match:
                            current_host = host_match.group(1)
                            if current_host and '.' in current_host:
                                subdomains.append(current_host)
                        # Match: [*] Ip_Address: 1.2.3.4
                        ip_match = re.search(r'\[\*\]\s*Ip_Address:\s*(\S+)', line)
                        if ip_match and current_host:
                            ip = ip_match.group(1)
                            hosts_with_ips.append({"host": current_host, "ip": ip})
                    
                    # Store hosts with IPs separately for analysis
                    if hosts_with_ips:
                        context["hosts"] = [h["host"] for h in hosts_with_ips]
                        context["ips"] = list(set([h["ip"] for h in hosts_with_ips]))
                        context["host_ip_map"] = {h["host"]: h["ip"] for h in hosts_with_ips}
                        print(f"  📍 Found {len(hosts_with_ips)} hosts with IPs from recon-ng")
                else:
                    # Standard subdomain parsing for other tools
                    lines = output.strip().split("\n")
                    subdomain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$')
                    for line in lines:
                        line = line.strip()
                        if not line or ' ' in line or '/' in line or 'http' in line.lower():
                            continue
                        if subdomain_pattern.match(line) and len(line) > 4:
                            subdomains.append(line)
                
                # Store subdomains
                subdomains = list(set(subdomains))  # Dedupe
                context["subdomain_count"] = len(subdomains)
                context["subdomains"] = subdomains[:50]
                
                # ─────────────────────────────────────────────────────────
                # PERSIST TO RAG FOR CROSS-SESSION MEMORY
                # ─────────────────────────────────────────────────────────
                try:
                    from app.rag.unified_memory import get_unified_rag
                    rag = get_unified_rag()
                    domain = params.get("domain", "")
                    for sub in subdomains[:100]:
                        ip = context.get("host_ip_map", {}).get(sub, "")
                        rag.add_subdomain(sub, domain, ip=ip, source=tool_name)
                    if subdomains:
                        print(f"  💾 Stored {len(subdomains[:100])} subdomains in RAG")
                except Exception as e:
                    pass
            
            # ─────────────────────────────────────────────────────────
            # ASN EXTRACTION - Runs for ALL tools (amass, httpx, etc.)
            # ─────────────────────────────────────────────────────────
            try:
                import re
                asn_list = context.get("asns", [])
                
                # Pattern: "ASN: 13335 - CLOUDFLARENET - Cloudflare, Inc."
                asn_pattern = r'ASN:\s*(\d+)\s*[-–]\s*([A-Z0-9_-]+)(?:\s*[-–,]\s*(.+?))?(?:\n|$)'
                for match in re.finditer(asn_pattern, output, re.IGNORECASE):
                    asn_num = match.group(1)
                    asn_name = match.group(2).strip()
                    asn_org = match.group(3).strip() if match.group(3) else ""
                    
                    asn_entry = {
                        "asn": int(asn_num),
                        "name": asn_name,
                        "org": asn_org
                    }
                    
                    # Avoid duplicates
                    if not any(a.get("asn") == asn_entry["asn"] for a in asn_list):
                        asn_list.append(asn_entry)
                
                if asn_list and len(asn_list) != context.get("asn_count", 0):
                    context["asns"] = asn_list
                    context["asn_count"] = len(asn_list)
                    print(f"  🌐 ASNs detected: {len(asn_list)} (e.g., AS{asn_list[0]['asn']} - {asn_list[0]['name']})")
            except Exception:
                pass
            
            # ─────────────────────────────────────────────────────────
            # PORT SCANNING TOOLS
            # ─────────────────────────────────────────────────────────
            if tool_name == "nmap":
                context["has_ports"] = True
                context["last_target"] = params.get("target", "")
                
                # Parse open ports with service info
                open_ports = []
                import re
                # Match lines like: 22/tcp   open  ssh     OpenSSH 8.2
                port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?'
                for match in re.finditer(port_pattern, output):
                    port_info = {
                        "port": int(match.group(1)),
                        "protocol": match.group(2),
                        "service": match.group(3),
                        "version": match.group(4).strip() if match.group(4) else ""
                    }
                    open_ports.append(port_info)
                
                if open_ports:
                    context["open_ports"] = open_ports
                    context["port_count"] = len(open_ports)
                    
                    # Persist to RAG for cross-session memory
                    try:
                        from app.rag.unified_memory import get_unified_rag
                        rag = get_unified_rag()
                        target = params.get("target", "")
                        ports = [p["port"] for p in open_ports]
                        services = {p["port"]: p.get("service", "") for p in open_ports}
                        rag.add_host(ip=target, ports=ports, services=services, domain=context.get("last_domain", ""))
                        print(f"  💾 Stored {len(open_ports)} open ports in RAG")
                    except Exception:
                        pass
                
                # Parse OS detection
                os_match = re.search(r'OS details?:\s*(.+)', output)
                if os_match:
                    context["os_detected"] = os_match.group(1).strip()
            
            elif tool_name == "masscan":
                context["has_ports"] = True
                context["last_target"] = params.get("target", "")
                
                # Parse masscan output: "open tcp 80 192.168.1.1"
                import re
                open_ports = []
                port_pattern = r'open\s+(tcp|udp)\s+(\d+)\s+(\S+)'
                for match in re.finditer(port_pattern, output):
                    open_ports.append({
                        "port": int(match.group(2)),
                        "protocol": match.group(1),
                        "ip": match.group(3)
                    })
                if open_ports:
                    context["open_ports"] = open_ports
                    context["port_count"] = len(open_ports)
            
            elif tool_name == "httpx":
                context["has_http_probes"] = True
                # Parse httpx output with status codes and tech
                http_probes = []
                for line in output.strip().split("\n"):
                    if line.strip() and ("http://" in line or "https://" in line):
                        http_probes.append(line.strip())
                if http_probes:
                    context["http_probes"] = http_probes[:50]
                
                # Detect WAF/CDN from response patterns
                try:
                    from app.rag.security_tech import SECURITY_TECH_DB
                    detected_security = []
                    output_lower = output.lower()
                    
                    for tech_id, tech in SECURITY_TECH_DB.items():
                        for pattern in tech.detection_patterns:
                            if pattern.lower() in output_lower:
                                detected_security.append(tech_id)
                                break
                    
                    if detected_security:
                        context["detected_security_tech"] = list(set(detected_security))
                        print(f"  🛡️ Security tech detected: {', '.join(detected_security)}")
                except Exception:
                    pass
                
                # ─────────────────────────────────────────────────────────
                # ASN EXTRACTION from amass/other tools
                # ─────────────────────────────────────────────────────────
                try:
                    import re
                    asn_list = context.get("asns", [])
                    
                    # Pattern: "ASN: 13335 - CLOUDFLARENET - Cloudflare, Inc."
                    asn_pattern = r'ASN:\s*(\d+)\s*[-–]\s*([A-Z0-9_-]+)(?:\s*[-–,]\s*(.+?))?(?:\n|$)'
                    for match in re.finditer(asn_pattern, output, re.IGNORECASE):
                        asn_num = match.group(1)
                        asn_name = match.group(2).strip()
                        asn_org = match.group(3).strip() if match.group(3) else ""
                        
                        asn_entry = {
                            "asn": int(asn_num),
                            "name": asn_name,
                            "org": asn_org
                        }
                        
                        # Avoid duplicates
                        if not any(a["asn"] == asn_entry["asn"] for a in asn_list):
                            asn_list.append(asn_entry)
                    
                    if asn_list:
                        context["asns"] = asn_list
                        context["asn_count"] = len(asn_list)
                        print(f"  🌐 ASNs detected: {len(asn_list)} (e.g., AS{asn_list[0]['asn']} - {asn_list[0]['name']})")
                except Exception:
                    pass
            
            # ─────────────────────────────────────────────────────────
            # VULNERABILITY SCANNING TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "nuclei":
                context["has_nuclei"] = True
                context["vuln_scan_done"] = True
                
                # Parse nuclei findings: [severity] [template-id] matched
                import re
                vulnerabilities = []
                # Match: [critical] [cve-2021-xxxx] http://target
                vuln_pattern = r'\[(critical|high|medium|low|info)\]\s*\[([^\]]+)\]\s*(.+)'
                for match in re.finditer(vuln_pattern, output, re.IGNORECASE):
                    vulnerabilities.append({
                        "severity": match.group(1).lower(),
                        "template": match.group(2),
                        "matched": match.group(3).strip()
                    })
                if vulnerabilities:
                    context["vulnerabilities"] = vulnerabilities
                    context["vuln_count"] = len(vulnerabilities)
                    # Count by severity
                    context["critical_vulns"] = len([v for v in vulnerabilities if v["severity"] == "critical"])
                    context["high_vulns"] = len([v for v in vulnerabilities if v["severity"] == "high"])
            
            elif tool_name == "nikto":
                context["has_nikto"] = True
                context["vuln_scan_done"] = True
                
                # Parse nikto findings: + OSVDB-xxxx: /path: Description
                nikto_findings = []
                for line in output.strip().split("\n"):
                    if line.strip().startswith("+") and ":" in line:
                        nikto_findings.append(line.strip()[2:])  
                if nikto_findings:
                    context["nikto_findings"] = nikto_findings[:50]
            
            elif tool_name == "sqlmap":
                context["has_sqlmap"] = True
                # Check if vulnerable
                if "is vulnerable" in output.lower() or "sqli" in output.lower():
                    context["sqli_vulnerable"] = True
                # Parse databases if found
                import re
                db_match = re.search(r'available databases \[(\d+)\]:', output)
                if db_match:
                    context["databases_found"] = int(db_match.group(1))
            
            # ─────────────────────────────────────────────────────────
            # WEB DISCOVERY TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name in ["gobuster", "katana"]:
                context["has_web_discovery"] = True
                
                # Parse discovered paths
                discovered_paths = []
                for line in output.strip().split("\n"):
                    line = line.strip()
                    # gobuster: /admin (Status: 200) or just paths
                    if line and ("/" in line or "http" in line):
                        # Extract just the path/URL
                        import re
                        path_match = re.search(r'(https?://[^\s]+|/[^\s\(]+)', line)
                        if path_match:
                            discovered_paths.append(path_match.group(1))
                if discovered_paths:
                    context["discovered_paths"] = list(set(discovered_paths))[:100]
                    context["path_count"] = len(context["discovered_paths"])
            
            elif tool_name == "ffuf":
                context["has_web_discovery"] = True
                # Parse ffuf output
                discovered_paths = []
                for line in output.strip().split("\n"):
                    if line.strip() and not line.startswith("["):
                        # ffuf shows: path [Status: 200, Size: 1234]
                        import re
                        path_match = re.search(r'^(\S+)', line.strip())
                        if path_match:
                            discovered_paths.append(path_match.group(1))
                if discovered_paths:
                    context["discovered_paths"] = context.get("discovered_paths", []) + discovered_paths
                    context["discovered_paths"] = list(set(context["discovered_paths"]))[:100]
            
            elif tool_name == "feroxbuster":
                context["has_web_discovery"] = True
                discovered_paths = []
                for line in output.strip().split("\n"):
                    if "http" in line:
                        import re
                        url_match = re.search(r'(https?://[^\s]+)', line)
                        if url_match:
                            discovered_paths.append(url_match.group(1))
                if discovered_paths:
                    context["discovered_paths"] = list(set(discovered_paths))[:100]
            
            elif tool_name == "dirsearch":
                context["has_web_discovery"] = True
                discovered_paths = []
                for line in output.strip().split("\n"):
                    if line.strip() and ("200" in line or "301" in line or "302" in line or "403" in line):
                        import re
                        path_match = re.search(r'(https?://[^\s]+|/[^\s]+)', line)
                        if path_match:
                            discovered_paths.append(path_match.group(1))
                if discovered_paths:
                    context["discovered_paths"] = list(set(discovered_paths))[:100]
            
            # ─────────────────────────────────────────────────────────
            # WEB TECHNOLOGY DETECTION
            # ─────────────────────────────────────────────────────────
            elif tool_name == "wpscan":
                context["has_wpscan"] = True
                
                # Parse WordPress version
                import re
                ver_match = re.search(r'WordPress version:\s*(\S+)', output)
                if ver_match:
                    context["wordpress_version"] = ver_match.group(1)
                
                # Parse users
                users = []
                user_pattern = r'\[i\] User\(s\) Identified:.*?(?=\[\+\]|\[!\]|$)'
                user_section = re.search(user_pattern, output, re.DOTALL)
                if user_section:
                    for line in user_section.group(0).split("\n"):
                        if "| - " in line:
                            users.append(line.replace("| - ", "").strip())
                if users:
                    context["wp_users"] = users
                
                # Parse vulnerable plugins
                vuln_plugins = re.findall(r'\[!\].*vulnerable.*?:\s*(\S+)', output, re.IGNORECASE)
                if vuln_plugins:
                    context["wp_vulnerable_plugins"] = vuln_plugins
            
            elif tool_name == "whatweb":
                context["has_whatweb"] = True
                
                # Parse technologies from whatweb output
                technologies = []
                import re
                # WhatWeb shows: [tech1] [tech2] [tech3]
                tech_pattern = r'\[([^\]]+)\]'
                for match in re.finditer(tech_pattern, output):
                    tech = match.group(1)
                    if tech and len(tech) < 50:  # Avoid long descriptions
                        technologies.append(tech)
                if technologies:
                    context["web_technologies"] = list(set(technologies))[:30]
            
            elif tool_name == "wafw00f":
                context["has_waf_check"] = True
                
                # Parse WAF detection
                if "is behind" in output.lower():
                    context["waf_detected"] = True
                    import re
                    waf_match = re.search(r'is behind\s+(.+?)(?:\s+WAF|\s*$)', output, re.IGNORECASE)
                    if waf_match:
                        context["waf_name"] = waf_match.group(1).strip()
                elif "no waf" in output.lower():
                    context["waf_detected"] = False
            
            # ─────────────────────────────────────────────────────────
            # BRUTE FORCE TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "hydra":
                context["has_hydra"] = True
                
                # Parse cracked credentials: [port][service] host login: user password: pass
                cracked = []
                import re
                cred_pattern = r'\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)'
                for match in re.finditer(cred_pattern, output):
                    cracked.append({
                        "port": match.group(1),
                        "service": match.group(2),
                        "host": match.group(3),
                        "username": match.group(4),
                        "password": match.group(5)
                    })
                if cracked:
                    context["cracked_credentials"] = cracked
                    context["creds_count"] = len(cracked)
            
            # ─────────────────────────────────────────────────────────
            # EXPLOIT TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "searchsploit":
                context["has_searchsploit"] = True
                
                # Parse exploits: Title | Path
                exploits = []
                for line in output.strip().split("\n"):
                    if "|" in line and "/" in line:
                        parts = line.split("|")
                        if len(parts) >= 2:
                            title = parts[0].strip()
                            path = parts[1].strip()
                            if title and path and not title.startswith("-"):
                                exploits.append({
                                    "title": title,
                                    "path": path
                                })
                if exploits:
                    context["exploits_found"] = exploits
                    context["exploit_count"] = len(exploits)
            
            # ─────────────────────────────────────────────────────────
            # NETWORK/SMB TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "enum4linux":
                context["has_enum4linux"] = True
                
                # Parse SMB shares
                shares = []
                import re
                share_pattern = r'^\s*(\S+)\s+Disk\s+(.*)$'
                for match in re.finditer(share_pattern, output, re.MULTILINE):
                    shares.append(match.group(1))
                if shares:
                    context["smb_shares"] = shares
                
                # Parse users
                users = []
                user_pattern = r'user:\[([^\]]+)\]'
                for match in re.finditer(user_pattern, output):
                    users.append(match.group(1))
                if users:
                    context["smb_users"] = list(set(users))
            
            elif tool_name == "smbclient":
                context["has_smbclient"] = True
                
                # Parse shares from smbclient -L output
                shares = []
                for line in output.strip().split("\n"):
                    if "Disk" in line or "IPC" in line or "Print" in line:
                        parts = line.strip().split()
                        if parts:
                            shares.append(parts[0])
                if shares:
                    context["smb_shares"] = shares
            
            # ─────────────────────────────────────────────────────────
            # OSINT TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "theHarvester":
                # Parse theHarvester output to store emails, hosts, IPs, subdomains
                context["last_domain"] = params.get("domain", "")
                
                # Parse emails
                if "[*] Emails found:" in output:
                    email_section = output.split("[*] Emails found:")[1]
                    # Find next section marker or end
                    for marker in ["[*] Hosts found:", "[*] IPs found:", "[*] No ", "[*] Performing"]:
                        if marker in email_section:
                            email_section = email_section.split(marker)[0]
                            break
                    emails = [line.strip() for line in email_section.strip().split("\n") 
                              if line.strip() and "@" in line and not line.startswith("-")]
                    if emails:
                        context["emails"] = emails
                        context["email_count"] = len(emails)
                
                # Parse hosts/subdomains
                # Pattern for hosts: "host1.example.com:ip_address" or just "host1.example.com"
                hosts_found = []
                ips_found = []
                
                # Regex for hostnames (subdomains)
                # Matches: "sub.domain.com" or "sub.domain.com:1.2.3.4"
                host_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9]+)'
                
                # Regex for simple IPv4
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                
                # Process line by line to handle different output formats
                for line in output.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("[*]") or line.startswith("-") or "target:" in line.lower():
                        continue
                        
                    # Extract potential hosts
                    hosts = re.findall(host_pattern, line)
                    for h in hosts:
                        # Exclude IPs from being counted as hosts
                        if re.match(r'^\d+(\.\d+)+$', h):
                             continue
                        if "." in h and len(h) > 5 and not h.startswith("http"):
                            hosts_found.append(h)
                    
                    # Extract potential IPs
                    ips = re.findall(ip_pattern, line)
                    for ip in ips:
                        ips_found.append(ip)
                
                if hosts_found:
                    context["subdomains"] = list(set(hosts_found))
                    context["subdomain_count"] = len(context["subdomains"])
                    context["has_subdomains"] = True
                
                if ips_found:
                    context["ips"] = list(set(ips_found))


                
                # Parse ASNs
                if "[*] ASNS found:" in output or "[*] ASNs found:" in output:
                    asn_marker = "[*] ASNS found:" if "[*] ASNS found:" in output else "[*] ASNs found:"
                    asn_section = output.split(asn_marker)[1]
                    for marker in ["[*] Interesting", "[*] IPs", "[*] Emails", "[*] Hosts"]:
                        if marker in asn_section:
                            asn_section = asn_section.split(marker)[0]
                            break
                    asns = [line.strip() for line in asn_section.strip().split("\n") 
                            if line.strip() and line.strip().upper().startswith("AS")]
                    if asns:
                        context["asns"] = asns
                
                # Parse interesting URLs
                if "[*] Interesting Urls found:" in output:
                    urls_section = output.split("[*] Interesting Urls found:")[1]
                    for marker in ["[*] No ", "[*] IPs", "[*] Emails", "[*] Hosts", "[*] LinkedIn"]:
                        if marker in urls_section:
                            urls_section = urls_section.split(marker)[0]
                            break
                    urls = [line.strip() for line in urls_section.strip().split("\n") 
                            if line.strip() and line.strip().startswith("http")]
                    if urls:
                        context["interesting_urls"] = urls
    
    # Track which tools have been run (prevent loops)
    tools_run = context.get("tools_run", [])
    tools_run.extend(tools)
    context["tools_run"] = list(set(tools_run))  # Deduplicate
    
    # ============================================================
    # UNIVERSAL SECURITY TECH DETECTION (all tool outputs)
    # ============================================================
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
                        print(f"  🛡️ {tech.name} detected in output")
                    break
        
        if detected_security:
            context["detected_security_tech"] = list(set(detected_security))
    except Exception:
        pass
    
    # ============================================================
    # SYNC TO SHARED MEMORY - Other agents can now access findings
    # ============================================================
    try:
        from app.memory import get_shared_memory
        shared = get_shared_memory()
        shared.update_from_dict(context)
        
        # Log which agent contributed
        if tools:
            shared.add_finding("executor", "tools_run", tools)
    except Exception:
        pass  # Shared memory is optional enhancement
    
    return {
        **state,
        "execution_results": results,
        "context": context,
        "next_action": "analyze"
    }


def _get_security_tech_context(context: dict) -> str:
    """Generate security tech bypass context for the LLM."""
    detected_security = context.get("detected_security_tech", [])
    if not detected_security:
        return ""
    
    try:
        from app.rag.security_tech import SECURITY_TECH_DB
        
        security_context = "\n- **SECURITY DEFENSES DETECTED:**\n"
        for tech_id in detected_security[:3]:  # Top 3
            tech = SECURITY_TECH_DB.get(tech_id)
            if tech:
                security_context += f"  * {tech.name} ({tech.category}): {tech.description[:80]}...\n"
                security_context += f"    BYPASS METHODS:\n"
                for method in tech.bypass_methods[:2]:  # Top 2 methods
                    security_context += f"      - {method['method']}: {method['description'][:60]}...\n"
                if tech.origin_discovery and tech.category == "cdn_waf":
                    security_context += f"    ORIGIN IP DISCOVERY: {', '.join(tech.origin_discovery[:2])}\n"
        
        # Add live web research for latest bypass techniques
        try:
            from app.tools.custom.web_research import research_bypass
            for tech_id in detected_security[:1]:  # Research top 1 only (rate limit)
                tech = SECURITY_TECH_DB.get(tech_id)
                if tech:
                    research_result = research_bypass(tech.name)
                    if research_result and "No research" not in research_result:
                        security_context += f"\n    🌐 WEB RESEARCH:\n"
                        for line in research_result.split("\n")[:5]:
                            security_context += f"      {line}\n"
        except Exception:
            pass  # Web research is optional
        
        return security_context
    except Exception:
        return ""


def analyzer_node(state: AgentState) -> AgentState:
    """
    LLM analyzes execution results.
    
    NEW: Enriches results with CVE data from RAG.
    
    Decides:
    - DONE: Goal achieved, format and return results
    - CONTINUE: Suggest next step
    - ASK_USER: Need clarification
    """
    llm = OllamaClient()
    results = state.get("execution_results", {})
    context = state.get("context", {})
    
    # === CHECK IF ANY TOOLS SUCCEEDED ===
    successful_tools = [t for t, d in results.items() if d.get("success")]
    failed_tools = [t for t, d in results.items() if not d.get("success")]
    
    if not successful_tools:
        # ALL tools failed - provide INTELLIGENT REASONING about why
        detected_security = context.get("detected_security_tech", [])
        
        error_msg = "⚠️ **All scans failed or timed out:**\n\n"
        
        # Analyze each failed tool
        failure_reasons = []
        for tool, data in results.items():
            error = data.get("error", "") or data.get("output", "")
            error_lower = error.lower()
            error_msg += f"- **{tool}**: {error[:100]}...\n" if len(error) > 100 else f"- **{tool}**: {error}\n"
            
            # Categorize failure reasons
            if "timeout" in error_lower or "timed out" in error_lower:
                failure_reasons.append("timeout")
            if "connection refused" in error_lower or "no route" in error_lower:
                failure_reasons.append("connection")
            if "could not connect" in error_lower:
                failure_reasons.append("connection")
        
        # Generate intelligent analysis
        error_msg += "\n**🧠 Failure Analysis:**\n"
        
        # Check if security tech is causing issues - use SECURITY_TECH_DB dynamically
        security_explained = False
        if detected_security:
            try:
                from app.rag.security_tech import SECURITY_TECH_DB
                
                for tech_id in detected_security:
                    tech = SECURITY_TECH_DB.get(tech_id)
                    if tech:
                        security_explained = True
                        error_msg += f"\n🛡️ **{tech.name} Detected!** ({tech.category})\n"
                        error_msg += f"{tech.description}\n\n"
                        
                        # Show bypass methods
                        error_msg += "**Bypass Methods:**\n"
                        for method in tech.bypass_methods[:3]:
                            error_msg += f"- {method['method']}: {method['description']}\n"
                        
                        # For CDN/WAF, show origin discovery
                        if tech.category == "cdn_waf" and tech.origin_discovery:
                            error_msg += "\n**Find Origin IP:**\n"
                            for od in tech.origin_discovery[:3]:
                                error_msg += f"- {od}\n"
                        error_msg += "\n"
            except Exception:
                pass
        
        # If no security tech detected, check for timeout/connection issues
        if not security_explained:
            if "timeout" in failure_reasons or "connection" in failure_reasons:
                error_msg += """
⏱️ **Connection/Timeout Issues:**
- Target may be offline or unreachable
- Port is filtered/closed (not open on target)
- Firewall blocking your IP
- CDN/WAF may be protecting the target

**Try:**
1. Run `httpx` first to confirm target is up
2. Do port scan with `nmap` to find open ports
3. Check if target has CDN protection with `httpx -title -tech-detect`
"""
            else:
                error_msg += """
🔧 **Possible Tool Issues:**
- Missing required parameters
- Wrong target format
- Tool not installed properly

Check tool installation with `/tools`
"""
        
        return {
            **state,
            "response": error_msg,
            "next_action": "respond"
        }
    
    # Format results for LLM - use more context for better analysis
    results_str = ""
    for tool, data in results.items():
        if data.get("success"):
            output = data.get("output", "")[:4000]
            results_str += f"\n{tool}: SUCCESS\n{output}\n"
        else:
            results_str += f"\n{tool}: FAILED - {data.get('error', 'Unknown error')}\n"
            
    # NEW: Append specialized agent analysis
    try:
        # Check imports locally to avoid global scope issues
        from app.agent.orchestration import get_coordinator
        
        agent_name = context.get("current_agent", "base")
        agent = get_coordinator().get_agent(agent_name)
        if agent:
            # Pass context to analyze_results
            agent_analysis = agent.analyze_results(results, context)
            if agent_analysis:
                results_str += f"\n\nAGENCY ANALYSIS ({agent.AGENT_NAME}):\n{agent_analysis}\n"
                print(f"  🧠 Included insights from {agent.AGENT_NAME} agent")
    except Exception as e:
        print(f"  ⚠️ Agent analysis failed: {e}")
    
    # ============================================================
    cve_context = ""
    try:
        from app.rag.cve_rag import search_cves
        from app.agent.prompt_loader import format_prompt
        import re # Ensure re is imported
        import json # Ensure json is imported
        
        # Use LLM to extract technologies (replaces brittle regex)
        tech_prompt = format_prompt("tech_extractor", results_str=results_str)
        try:
            # Quick extraction call (low temp for precision)
            tech_response = llm.generate(tech_prompt, timeout=30, stream=False)
            
            detected_tech = []
            if tech_response and "None" not in tech_response:
                # Clean up response (handle potential newlines or bullets)
                import re
                clean_response = re.sub(r'[\n\r]+', ', ', tech_response)
                # Split by comma
                items = [t.strip() for t in clean_response.split(',')]
                detected_tech = [t for t in items if t and len(t) > 2]
                
            print(f"  🔍 Detected Tech (LLM): {detected_tech}")
            
        except Exception as e:
            print(f"  ⚠️ Tech extraction failed: {e}")
            detected_tech = []
        
        # Store detected tech for exploit tools to use
        if detected_tech:
            context["detected_tech"] = list(set(detected_tech))[:10]
            
            # Search CVEs using the extracted terms
            search_query = ", ".join(detected_tech[:5])  # Search for top 5 terms
            cve_results = search_cves(search_query, n_results=5, severity="high")
            
            if cve_results.get("cves"):
                # Store CVEs in context for later display
                context["last_cves"] = cve_results["cves"]
                context["cve_query"] = search_query
                
                cve_context = "\n\n⚠️ POTENTIAL CVEs (Found via RAG matching):\n"
                cve_context += "Verify if these actually apply to the target version:\n"
                for cve in cve_results["cves"][:3]:
                    cve_id = cve.get("cve_id", "Unknown")
                    desc = cve.get("description", "")[:100]
                    severity = cve.get("severity", "Unknown")
                    affected = cve.get("product", "Unknown product")
                    cve_context += f"- {cve_id} ({severity}) {affected}: {desc}...\n"
                print(f"  🔍 CVE RAG: found {len(cve_results['cves'])} potential CVEs")
        else:
            print(f"  ℹ️ CVE RAG: No technologies detected in output")
            
    except Exception as e:
        print(f"  ⚠️ CVE RAG Error: {e}")
    
    # ============================================================
    # PURE LLM ANALYSIS - Attack Chain Focus
    # ============================================================
    
    # Load prompt from external file
    from app.agent.prompt_loader import format_prompt
    
    prompt = format_prompt("analyzer",
        results_str=results_str,
        cve_context=cve_context,
        domain=context.get('last_domain', 'unknown'),
        subdomain_count=context.get('subdomain_count', 0),
        has_ports=context.get('has_ports', False),
        detected_tech=context.get('detected_tech', []),
        tools_run=context.get('tools_run', []),
        security_tech_context=_get_security_tech_context(context)
    )
    
    
    # Stream the analysis - user wants to see this thinking process
    response = llm.generate(prompt, timeout=90, stream=True, show_thinking=True, show_content=True)
    
    try:
        # Robust JSON extraction with multiple repair strategies
        clean_response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL)
        
        # Try to extract JSON
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', clean_response, re.DOTALL)
        
        data = None
        if json_match:
            json_str = json_match.group()
            
            # Strategy 1: Direct parse
            try:
                data = json.loads(json_str)
            except json.JSONDecodeError:
                pass
            
            # Strategy 2: Fix single quotes to double quotes
            if data is None:
                try:
                    # Replace single quotes with double (carefully)
                    fixed = re.sub(r"'([^']*)':", r'"\1":', json_str)
                    fixed = re.sub(r": '([^']*)'", r': "\1"', fixed)
                    data = json.loads(fixed)
                except json.JSONDecodeError:
                    pass
            
            # Strategy 3: Fix unescaped characters
            if data is None:
                try:
                    # Remove control characters
                    fixed = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_str)
                    # Fix trailing commas
                    fixed = re.sub(r',\s*}', '}', fixed)
                    fixed = re.sub(r',\s*]', ']', fixed)
                    data = json.loads(fixed)
                except json.JSONDecodeError:
                    pass
            
            # Strategy 4: Extract just the key fields manually
            if data is None:
                data = {}
                # Try to extract next_tool
                tool_match = re.search(r'"next_tool"\s*:\s*"([^"]+)"', clean_response)
                if tool_match:
                    data["next_tool"] = tool_match.group(1)
                # Try to extract best_attack
                attack_match = re.search(r'"best_attack"\s*:\s*"([^"]+)"', clean_response)
                if attack_match:
                    data["best_attack"] = attack_match.group(1)
                # Try to extract summary
                summary_match = re.search(r'"summary"\s*:\s*"([^"]+)"', clean_response)
                if summary_match:
                    data["summary"] = summary_match.group(1)
        
        if data:
            
            findings = data.get("findings", [])
            findings_str = ""
            if findings:
                findings_str = "\n\n## 🎯 Attack Vectors Identified\n\n"
                for f in findings:
                    severity = f.get("severity", "Unknown")
                    badge = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                    findings_str += f"{badge} **{f.get('issue')}** ({severity})\n"
                    # Show attack method if present
                    attack = f.get("attack") or f.get("risk", "")
                    if attack:
                        findings_str += f"   → Exploit: {attack}\n\n"
            
            # Best attack vector
            best_attack = data.get("best_attack_vector", "")
            
            # Next step recommendation
            next_tool = data.get("next_tool") or (data.get("next_tools", [None])[0] if data.get("next_tools") else None)
            next_target = data.get("next_target", "")
            next_reason = data.get("next_reason", "")
            summary = data.get("summary", "")
            
            # Build response with attack-focused analysis
            response_text = ""
            
            # Show attack vectors first
            if findings_str:
                response_text += findings_str
            
            # Show best attack vector
            if best_attack:
                response_text += f"\n## ⚡ Best Attack Vector\n{best_attack}\n"
            
            # Show analysis summary
            if summary:
                response_text += f"\n## 📊 Analysis\n{summary}\n"
            
            # NOTE: Removed "Scan Details" section since live streaming 
            # now shows all tool output in real-time. No need to duplicate.
            
            # Show next step with specific target
            if next_tool:
                next_step = f"Use **{next_tool}**"
                if next_target:
                    next_step += f" on `{next_target}`"
                if next_reason:
                    next_step += f" - {next_reason}"
                response_text += f"\n\n**💡 Next Attack Step:** {next_step}"
            elif next_reason:
                response_text += f"\n\n**💡 Recommended next step:** {next_reason}"
            
            # ─────────────────────────────────────────────────────────
            # PHASE COMPLETION CHECK - Does agent recommend advancing?
            # ─────────────────────────────────────────────────────────
            auto_chain = False
            chain_tools = []
            chain_target = None
            
            try:
                from app.agent.orchestration import get_coordinator
                coordinator = get_coordinator()
                advance = coordinator.auto_advance(context)
                
                if advance:
                    phase_msg = f"\n\n---\n🔄 **{advance['phase_name']} Phase Complete!**\n"
                    phase_msg += f"✅ {advance['reason']}\n"
                    if advance.get("next_phase_name"):
                        phase_msg += f"\n**Ready for {advance['next_phase_name']} phase.**"
                        if advance.get("next_action"):
                            phase_msg += f"\n💡 Next: {advance['next_action']}"
                    response_text += phase_msg
                    context["phase_complete"] = True
                    context["current_phase"] = advance.get("next_phase", advance["phase"])
                    
                    # AUTO-CHAIN: If in autonomous mode, prepare next tools
                    if context.get("auto_mode") and advance.get("suggested_tools"):
                        auto_chain = True
                        chain_tools = advance.get("suggested_tools", [])[:2]
                        chain_target = next_target or context.get("last_domain")
                        print(f"  🔗 Auto-chain enabled: will run {chain_tools}")
            except Exception as e:
                print(f"  ⚠️ Phase check error: {e}")
            
            # Also check if we have next_tool suggestion and auto_mode
            if not auto_chain and context.get("auto_mode") and next_tool:
                auto_chain = True
                chain_tools = [next_tool]
                chain_target = next_target or context.get("last_domain")
                print(f"  🔗 Auto-chain from analyzer: {chain_tools}")
            
            # If auto-chaining, set up next execution instead of responding
            if auto_chain and chain_tools:
                # Prepare for auto-execution
                context["pending_auto_tools"] = chain_tools
                context["pending_auto_target"] = chain_target
                
                return {
                    **state,
                    "response": response_text,
                    "context": context,
                    "suggested_tools": chain_tools,
                    "next_action": "auto_chain"
                }
            
            return {
                **state,
                "response": response_text,
                "context": context,
                "next_action": "respond"
            }
        else:
            # data is empty - this shouldn't happen often but handle it
            print(f"  ⚠️ Analyzer extracted empty data, showing raw results")
            raise ValueError("Empty data extracted")  # Trigger fallback
    except Exception as e:
        print(f"  ⚠️ Analyzer parse error: {e}")
    
    # Fallback - show formatted tool results (LLM failed to parse)
    # Show each tool's output in a clean code block
    print(f"  📋 Fallback: formatting {len(results)} tool results...")
    formatted = "**Scan Results:**\n\n"
    
    for tool, data in results.items():
        if isinstance(data, dict):
            if data.get("success"):
                output = data.get("output", "")
                # Clean and truncate output
                if len(output) > 3000:
                    output = output[:3000] + "\n... (truncated)"
                formatted += f"### {tool.upper()}\n```\n{output}\n```\n\n"
            else:
                formatted += f"### {tool.upper()}\n❌ {data.get('error', 'Unknown error')}\n\n"
    
    # Add helpful message
    formatted += "\n---\n**ℹ️ LLM analysis unavailable.** The tool outputs are shown above in raw format. Key findings should be extracted manually.\n"
    
    # Ensure we have something to show
    if formatted.strip() == "**Scan Results:**":
        formatted = "**Note:** No tool results to display. The scan may not have produced output."
    
    print(f"  ✅ Fallback response: {len(formatted)} chars")
    return {
        **state,
        "response": formatted,
        "next_action": "respond"
    }


def auto_chain_node(state: AgentState) -> AgentState:
    """
    Auto-chain node for autonomous mode.
    
    When auto_mode is enabled and we have pending tools to run,
    this node shows a brief countdown then triggers execution.
    
    FIXED: 
    - Cleans URL prefixes from target (no double https://)
    - Uses ALL subdomains for scanning tools
    """
    import re
    
    context = state.get("context", {})
    pending_tools = context.get("pending_auto_tools", [])
    pending_target = context.get("pending_auto_target")
    
    if not pending_tools:
        # No tools to chain, just respond
        return {**state, "next_action": "respond"}
    
    # Show what we're about to do
    print(f"\n  🔗 AUTO-CHAIN: Preparing {pending_tools}")
    
    # Check iteration limit
    chain_count = context.get("auto_chain_count", 0)
    max_chains = 5  # Prevent infinite loops
    
    if chain_count >= max_chains:
        print(f"  ⚠️ Chain limit reached ({max_chains}), stopping")
        context["auto_mode"] = False
        return {
            **state,
            "context": context,
            "response": state.get("response", "") + f"\n\n⚠️ Auto-chain limit reached ({max_chains} iterations)",
            "next_action": "respond"
        }
    
    # Increment chain counter
    context["auto_chain_count"] = chain_count + 1
    
    # ─────────────────────────────────────────────────────────
    # CLEAN TARGET - Remove URL prefixes to get pure domain
    # ─────────────────────────────────────────────────────────
    def clean_domain(target: str) -> str:
        """Extract clean domain from URL or target string."""
        if not target:
            return ""
        # Remove protocol prefix
        target = re.sub(r'^https?://', '', target)
        # Remove trailing slashes and paths
        target = target.split('/')[0]
        # Remove port if present
        target = target.split(':')[0]
        return target
    
    # Get clean domain
    raw_target = pending_target or context.get("last_domain", "")
    domain = clean_domain(raw_target)
    
    # ─────────────────────────────────────────────────────────
    # GET ALL TARGETS (subdomains + main domain)
    # ─────────────────────────────────────────────────────────
    all_targets = [domain] if domain else []
    subdomains = []
    
    try:
        from app.memory import get_shared_memory
        memory = get_shared_memory()
        
        # Get all targets including subdomains
        discovered_targets = memory.get_targets_for_scanning()
        if discovered_targets:
            # Clean all targets
            all_targets = list(set([clean_domain(t) for t in discovered_targets if t]))
            # Get just subdomains (exclude main domain)
            subdomains = [t for t in all_targets if t != domain]
            print(f"  📋 Found {len(all_targets)} targets ({len(subdomains)} subdomains + main)")
        
        # Also check context for subdomains
        if not subdomains and context.get("subdomains"):
            subdomains = [clean_domain(s) for s in context.get("subdomains", []) if s]
            all_targets = list(set([domain] + subdomains)) if domain else subdomains
            print(f"  📋 Using context subdomains: {len(subdomains)}")
            
    except Exception as e:
        print(f"  ⚠️ Could not get subdomains: {e}")
    
    # IMPORTANT: Update context with subdomains for executor to use
    if subdomains:
        context["subdomains"] = subdomains
        context["subdomain_count"] = len(subdomains)
        context["has_subdomains"] = True
    
    # Set up tools for execution
    suggested_commands = {}
    registry = get_registry()
    
    # Check which tools are scanning tools (need multiple targets)
    scanning_tools = ["nmap", "masscan", "rustscan", "naabu", "httpx", "nuclei"]
    
    for tool in pending_tools:
        if registry.is_available(tool):
            spec = registry.tools.get(tool)
            if spec and spec.commands:
                # Get appropriate command
                suggested_commands[tool] = list(spec.commands.keys())[0]
    
    # Prepare params with CLEAN domain (no https://)
    tool_params = {
        "domain": domain,
        "target": domain,
        "url": f"https://{domain}" if domain else "",
        "targets": all_targets[:50],  # All subdomains for batch scanning
        "host": domain,
    }
    
    # For scanning tools, if we have many targets, use first 20
    if any(t in scanning_tools for t in pending_tools) and len(all_targets) > 1:
        print(f"  🎯 Will scan {min(len(all_targets), 20)} targets: {all_targets[:3]}...")
        tool_params["targets"] = all_targets[:20]
    
    print(f"  🚀 Auto-executing: {list(suggested_commands.keys())} on {domain}")
    
    # Clear pending to avoid loops
    context.pop("pending_auto_tools", None)
    context.pop("pending_auto_target", None)
    
    return {
        **state,
        "context": context,
        "suggested_tools": pending_tools,
        "selected_tools": pending_tools,
        "suggested_commands": suggested_commands,
        "tool_params": tool_params,
        "confirmed": True,
        "next_action": "execute"
    }


def respond_node(state: AgentState) -> AgentState:
    """Format and return final response."""
    # If we have a suggestion waiting for confirmation
    if state.get("suggestion_message") and state.get("suggested_tools"):
        return {
            **state,
            "response": state["suggestion_message"],
            "next_action": "end"
        }
    
    # If there's already a response, use it
    if state.get("response"):
        return {**state, "next_action": "end"}
    
    # Fallback if no response
    return {
        **state,
        "response": "I couldn't process that request. Please try again with more details.",
        "next_action": "end"
    }


def question_node(state: AgentState) -> AgentState:
    """Answer using LLM knowledge + scan context + web research."""
    llm = OllamaClient()
    context = state.get("context", {})
    query = state["query"]
    
    context_str = f"""Target: {context.get('last_domain', 'Not set')}
Technologies: {context.get('detected_tech', [])}"""
    
    # Try web research for questions that might need fresh info
    web_context = ""
    needs_research = any(kw in query.lower() for kw in [
        "latest", "new", "recent", "2024", "2025", "2026",
        "how to", "what is", "explain", "tutorial", "guide",
        "bypass", "exploit", "vulnerability", "cve-", "poc"
    ])
    
    if needs_research:
        try:
            from app.tools.custom.web_research import search_and_format
            research = search_and_format(query)
            if research:
                web_context = f"\n\nWEB RESEARCH RESULTS:\n{research}"
                print(f"  🌐 Searched web for: {query[:50]}...")
        except Exception:
            pass
    
    from app.agent.prompt_loader import format_prompt
    prompt = format_prompt("general_chat", query=query, context_str=context_str, web_context=web_context)
    
    response = llm.generate(prompt, timeout=90, stream=True, show_thinking=True)
    
    return {
        **state,
        "response": response or "Please rephrase.",
        "next_action": "end"
    }


def memory_query_node(state: AgentState) -> AgentState:
    """
    Retrieve and display stored data from memory/context.
    
    Handles requests like:
    - "show me the subdomains"
    - "list the findings"
    - "what did we find"
    - "show me emails"
    
    Uses RAG for cross-session persistence when session context is empty.
    """
    context = state.get("context", {})
    query = state.get("query", "").lower()
    
    response_parts = []
    
    # Get domain
    domain = context.get("last_domain", "Unknown target")
    response_parts.append(f"## 📊 Stored Data for {domain}\n")
    
    # ─────────────────────────────────────────────────────────
    # TRY RAG FOR CROSS-SESSION DATA
    # ─────────────────────────────────────────────────────────
    rag_findings = {"subdomains": [], "hosts": [], "vulnerabilities": []}
    try:
        from app.rag.unified_memory import get_unified_rag
        rag = get_unified_rag()
        if domain and domain != "Unknown target":
            rag_findings = rag.get_findings_for_domain(domain)
            if rag_findings.get("subdomains") or rag_findings.get("hosts"):
                response_parts.append("*Cross-session data from RAG:*\n")
    except Exception:
        pass
    
    # Emails
    emails = context.get("emails", [])
    if emails:
        response_parts.append(f"### 📧 Emails ({len(emails)} found)\n")
        for email in emails:
            response_parts.append(f"  • {email}")
        response_parts.append("")
    
    # Subdomains - combine session + RAG
    subdomains = context.get("subdomains", [])
    rag_subs = [s.get("subdomain", "") for s in rag_findings.get("subdomains", [])]
    all_subdomains = list(set(subdomains + rag_subs))  # Dedupe
    subdomain_count = len(all_subdomains) or context.get("subdomain_count", 0)
    
    if all_subdomains:
        rag_indicator = " 💾" if rag_subs else ""
        response_parts.append(f"### 🌐 Subdomains ({subdomain_count} found){rag_indicator}\n")
        for sub in all_subdomains[:50]:
            response_parts.append(f"  • {sub}")
        if len(all_subdomains) > 50:
            response_parts.append(f"  ... and {len(all_subdomains) - 50} more")
        response_parts.append("")
    elif subdomain_count > 0:
        response_parts.append(f"### 🌐 Subdomains\n  {subdomain_count} subdomains discovered (list not in memory)\n")
    
    # Hosts
    hosts = context.get("hosts", [])
    if hosts:
        response_parts.append(f"### 🖥️ Hosts ({len(hosts)} found)\n")
        for host in hosts:
            response_parts.append(f"  • {host}")
        response_parts.append("")
    
    # IPs
    ips = context.get("ips", [])
    if ips:
        response_parts.append(f"### 🔢 IP Addresses ({len(ips)} found)\n")
        for ip in ips:
            response_parts.append(f"  • {ip}")
        response_parts.append("")
    
    # ASNs
    asns = context.get("asns", [])
    if asns:
        response_parts.append(f"### 🏢 ASNs ({len(asns)} found)\n")
        for asn in asns:
            if isinstance(asn, dict):
                asn_str = f"AS{asn.get('asn', '?')} - {asn.get('name', 'Unknown')}"
                if asn.get('org'):
                    asn_str += f" ({asn.get('org')})"
                response_parts.append(f"  • {asn_str}")
            else:
                response_parts.append(f"  • {asn}")
        response_parts.append("")
    
    # Interesting URLs
    interesting_urls = context.get("interesting_urls", [])
    if interesting_urls:
        response_parts.append(f"### 🔗 Interesting URLs ({len(interesting_urls)} found)\n")
        for url in interesting_urls:
            response_parts.append(f"  • {url}")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # PORT SCAN RESULTS
    # ─────────────────────────────────────────────────────────
    open_ports = context.get("open_ports", [])
    if open_ports:
        response_parts.append(f"### 🔌 Open Ports ({len(open_ports)} found)\n")
        for port in open_ports:
            if isinstance(port, dict):
                port_str = f"{port.get('port')}/{port.get('protocol', 'tcp')}"
                service = port.get('service', '')
                version = port.get('version', '')
                if service:
                    port_str += f"  {service}"
                if version:
                    port_str += f" ({version})"
                response_parts.append(f"  • {port_str}")
            else:
                response_parts.append(f"  • {port}")
        response_parts.append("")
    
    # OS Detection
    if context.get("os_detected"):
        response_parts.append(f"### 💻 OS Detected\n  {context['os_detected']}\n")
    
    # ─────────────────────────────────────────────────────────
    # VULNERABILITY RESULTS
    # ─────────────────────────────────────────────────────────
    vulnerabilities = context.get("vulnerabilities", [])
    if vulnerabilities:
        critical = context.get("critical_vulns", 0)
        high = context.get("high_vulns", 0)
        response_parts.append(f"### 🔓 Vulnerabilities ({len(vulnerabilities)} found)")
        if critical or high:
            response_parts.append(f"  🔴 Critical: {critical} | 🟠 High: {high}\n")
        else:
            response_parts.append("")
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown")
            template = vuln.get("template", "unknown")
            matched = vuln.get("matched", "")
            badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(severity, "⚪")
            response_parts.append(f"  {badge} [{template}] {matched}")
        response_parts.append("")
    
    # Nikto Findings
    nikto_findings = context.get("nikto_findings", [])
    if nikto_findings:
        response_parts.append(f"### 🕷️ Nikto Findings ({len(nikto_findings)} found)\n")
        for finding in nikto_findings:
            response_parts.append(f"  • {finding}")
        response_parts.append("")
    
    # SQLi Results
    if context.get("sqli_vulnerable"):
        dbs = context.get("databases_found", 0)
        response_parts.append(f"### � SQL Injection\n  ⚠️ Target is VULNERABLE to SQL injection!")
        if dbs:
            response_parts.append(f"  📁 {dbs} databases discovered")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # WEB DISCOVERY RESULTS
    # ─────────────────────────────────────────────────────────
    discovered_paths = context.get("discovered_paths", [])
    if discovered_paths:
        response_parts.append(f"### 📂 Discovered Paths ({len(discovered_paths)} found)\n")
        for path in discovered_paths:
            response_parts.append(f"  • {path}")
        response_parts.append("")
    
    # HTTP Probes
    http_probes = context.get("http_probes", [])
    if http_probes:
        response_parts.append(f"### 🌍 HTTP Probes ({len(http_probes)} found)\n")
        for probe in http_probes:
            response_parts.append(f"  • {probe}")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # WORDPRESS INFO
    # ─────────────────────────────────────────────────────────
    if context.get("wordpress_version"):
        response_parts.append(f"### 📦 WordPress Info")
        response_parts.append(f"  Version: {context['wordpress_version']}")
        if context.get("wp_users"):
            response_parts.append(f"  Users: {', '.join(context['wp_users'][:10])}")
        if context.get("wp_vulnerable_plugins"):
            response_parts.append(f"  ⚠️ Vulnerable Plugins: {', '.join(context['wp_vulnerable_plugins'])}")
        response_parts.append("")
    
    # WAF Detection
    if context.get("has_waf_check"):
        if context.get("waf_detected"):
            waf_name = context.get("waf_name", "Unknown")
            response_parts.append(f"### �️ WAF Detected\n  ⚠️ {waf_name}\n")
        else:
            response_parts.append("### 🛡️ WAF Detection\n  ✅ No WAF detected\n")
    
    # ─────────────────────────────────────────────────────────
    # CREDENTIALS & EXPLOITS
    # ─────────────────────────────────────────────────────────
    cracked_creds = context.get("cracked_credentials", [])
    if cracked_creds:
        response_parts.append(f"### 🔑 Cracked Credentials ({len(cracked_creds)} found)\n")
        for cred in cracked_creds:
            user = cred.get("username", "?")
            passwd = cred.get("password", "?")
            service = cred.get("service", "")
            host = cred.get("host", "")
            response_parts.append(f"  • {user}:{passwd} ({service}@{host})")
        response_parts.append("")
    
    exploits_found = context.get("exploits_found", [])
    if exploits_found:
        response_parts.append(f"### 💣 Exploits Found ({len(exploits_found)})\n")
        for exp in exploits_found:
            title = exp.get("title", "Unknown")
            response_parts.append(f"  • {title}")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # SMB/NETWORK INFO
    # ─────────────────────────────────────────────────────────
    smb_shares = context.get("smb_shares", [])
    if smb_shares:
        response_parts.append(f"### 📁 SMB Shares ({len(smb_shares)} found)\n")
        for share in smb_shares:
            response_parts.append(f"  • {share}")
        response_parts.append("")
    
    smb_users = context.get("smb_users", [])
    if smb_users:
        response_parts.append(f"### 👤 SMB Users ({len(smb_users)} found)\n")
        for user in smb_users:
            response_parts.append(f"  • {user}")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # TECHNOLOGY & TOOLS
    # ─────────────────────────────────────────────────────────
    # Web Technologies (from whatweb)
    web_tech = context.get("web_technologies", [])
    if web_tech:
        response_parts.append(f"### 🔧 Web Technologies ({len(web_tech)} found)\n")
        for tech in web_tech[:20]:
            response_parts.append(f"  • {tech}")
        response_parts.append("")
    
    # Detected Technologies (from analyzer)
    detected_tech = context.get("detected_tech", [])
    if detected_tech and not web_tech:
        response_parts.append("### 🔧 Detected Technologies\n")
        for tech in detected_tech[:20]:
            response_parts.append(f"  • {tech}")
        response_parts.append("")
    
    # Tools run
    tools_run = context.get("tools_run", [])
    if tools_run:
        response_parts.append("### 🛠️ Tools Executed\n")
        for tool in tools_run:
            response_parts.append(f"  • {tool}")
        response_parts.append("")
    
    # If nothing found
    if len(response_parts) <= 1:
        response_parts.append("No data stored yet. Run some scans first!")
    
    response = "\n".join(response_parts)
    
    return {
        **state,
        "response": response,
        "next_action": "end"
    }


def _format_results(results: Dict[str, Any]) -> str:
    """Format tool results for display."""
    from app.cli.display import format_tool_result
    
    parts = []
    for tool, data in results.items():
        if data.get("success"):
            formatted = format_tool_result(tool, data.get("output", ""), True)
            parts.append(formatted)
        else:
            parts.append(f"**{tool}**: Error - {data.get('error', 'Unknown')}")
    
    return "\n\n".join(parts) if parts else "No results"


# ============================================================
# GRAPH ROUTING
# ============================================================

def route_after_intent(state: AgentState) -> str:
    """Route based on intent classification."""
    intent = state.get("intent", "question")
    
    if intent == "security_task":
        return "target_verification"  # New step: verify target first
    elif intent == "confirm":
        return "confirm"
    elif intent == "memory_query":
        return "memory_query"
    elif intent == "question":
        return "question"
    else:
        return "question"


def route_after_action(state: AgentState) -> str:
    """Route based on next_action field."""
    action = state.get("next_action", "end")
    
    # Map actions to node names
    routes = {
        "plan": "planner",
        "planner": "planner",
        "confirm": "respond",
        "executor": "executor",
        "execute": "executor",
        "analyzer": "analyzer",
        "analyze": "analyzer",
        "respond": "respond",
        "auto_chain": "auto_chain"  # NEW: Auto-chain for autonomous mode
    }
    
    return routes.get(action, END)


# ============================================================
# BUILD GRAPH
# ============================================================

def build_graph():
    """Build the LangGraph state machine."""
    
    # Create graph
    graph = StateGraph(AgentState)
    
    # Add nodes
    graph.add_node("intent", intent_node)
    graph.add_node("target_verification", target_verification_node)
    graph.add_node("planner", planner_node)
    graph.add_node("confirm", confirm_node)
    graph.add_node("executor", executor_node)
    graph.add_node("analyzer", analyzer_node)
    graph.add_node("auto_chain", auto_chain_node)  # NEW: Auto-chain for autonomous mode
    graph.add_node("respond", respond_node)
    graph.add_node("question", question_node)
    graph.add_node("memory_query", memory_query_node)
    
    # Set entry point
    graph.set_entry_point("intent")
    
    # Add conditional edges
    graph.add_conditional_edges(
        "intent",
        route_after_intent,
        {
            "target_verification": "target_verification",
            "planner": "planner",
            "confirm": "confirm",
            "memory_query": "memory_query",
            "question": "question"
        }
    )
    
    # Add routing for target verification
    graph.add_conditional_edges(
        "target_verification",
        route_after_action,
        {
            "planner": "planner",
            "respond": "respond",
            END: END
        }
    )
    
    graph.add_conditional_edges(
        "planner",
        route_after_action,
        {
            "confirm": "respond",
            "respond": "respond",
            END: END
        }
    )
    
    graph.add_conditional_edges(
        "confirm",
        route_after_action,
        {
            "executor": "executor",
            "planner": "planner",  # Route to planner when tools not yet selected
            "respond": "respond",
            END: END
        }
    )
    
    graph.add_conditional_edges(
        "executor",
        route_after_action,
        {
            "analyze": "analyzer",
            "analyzer": "analyzer",
            "respond": "respond",
            END: END
        }
    )
    
    graph.add_conditional_edges(
        "analyzer",
        route_after_action,
        {
            "confirm": "respond",
            "respond": "respond",
            "planner": "planner",
            "auto_chain": "auto_chain",  # NEW: Auto-chain for autonomous mode
            END: END
        }
    )
    
    # NEW: Auto-chain routing - can go to executor or respond
    graph.add_conditional_edges(
        "auto_chain",
        route_after_action,
        {
            "execute": "executor",
            "executor": "executor",
            "respond": "respond",
            END: END
        }
    )
    
    graph.add_edge("respond", END)
    graph.add_edge("question", END)
    graph.add_edge("memory_query", END)
    
    # Compile with memory
    memory = MemorySaver()
    return graph.compile(checkpointer=memory)


# ============================================================
# AGENT CLASS
# ============================================================

class LangGraphAgent:
    """
    LangGraph-powered SNODE agent.
    
    Proper flow:
    1. LLM classifies intent
    2. LLM suggests tools
    3. User confirms
    4. Code executes
    5. LLM analyzes
    
    Key feature: Uses LangChain ConversationSummaryBufferMemory for smart context.
    """
    
    def __init__(self):
        self.graph = build_graph()
        self.context = {}
        self.thread_id = "snode-session"
        self.pending_confirmation = False
        self.last_suggestion = None
        self.last_results = {}  # Store for report generation
        
        # Initialize session memory 
        try:
            from app.memory import get_session_memory
            self.memory = get_session_memory()
        except Exception as e:
            print(f"⚠️ Memory init failed: {e}")
            self.memory = None
    
    def run(self, query: str, context: Dict[str, Any] = None) -> tuple[str, Dict[str, Any], bool]:
        """
        Process user input.
        
        Returns:
            (response, context, needs_confirmation)
        """
        if context:
            self.context.update(context)
        
        # Load conversation history from memory (New System)
        messages = []
        if self.memory:
             try:
                 # Get messages from SessionMemory
                 messages = self.memory.get_llm_context(max_messages=20)
             except Exception as e:
                 print(f"⚠️ Failed to load history: {e}")
        
        # If no memory or empty, ensure current query is added to history view (state only)
        # Note: We don't save to memory yet, that happens after response
        messages.append({"role": "user", "content": query})
        
        # If we have a pending confirmation and user says yes/no
        suggested_tools = []
        tool_params = {}
        if self.pending_confirmation and self.last_suggestion:
            suggested_tools = self.last_suggestion.get("tools", [])
            tool_params = self.last_suggestion.get("params", {})
        
        # Initial state
        state = AgentState(
            query=query,
            messages=messages, # Loaded from memory
            intent="",
            suggested_tools=suggested_tools,  
            suggestion_message="",
            tool_params=tool_params,  
            confirmed=False,
            selected_tools=[],
            execution_results={},
            context=self.context,
            response="",
            next_action=""
        )
        
        # Config with thread
        config = {"configurable": {"thread_id": self.thread_id}}
        
        # Run graph
        result = self.graph.invoke(state, config)
        
        # Update context
        self.context = result.get("context", self.context)
        
        if result.get("execution_results"):
            self.last_results.update(result.get("execution_results", {}))
        
        response = result.get("response") or result.get("suggestion_message") or "No response"
        
        # Save conversation to session memory
        if self.memory:
            self.memory.add_message("user", query)
            self.memory.add_message("assistant", response)
        
        needs_confirmation = (
            len(result.get("suggested_tools", [])) > 0 and
            result.get("next_action") == "end" and
            not result.get("execution_results")
        )
        
        if needs_confirmation:
            self.pending_confirmation = True
            self.last_suggestion = {
                "tools": result.get("suggested_tools"),
                "params": result.get("tool_params")
            }
        else:
            self.pending_confirmation = False
            self.last_suggestion = None
        
        return response, self.context, needs_confirmation
    
    def clear_history(self):
        """Clear conversation history."""
        self.messages = []
        self.context = {}


# Factory function
def create_langgraph_agent() -> LangGraphAgent:
    return LangGraphAgent()
