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
    PhaseGateAction,
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
    intent: str 
    
    # Planning
    suggested_tools: List[str]
    suggested_commands: Dict[str, str] 
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
    
    # Mode management
    mode: str  
    autochain_iteration: int  
    autochain_results: List[Dict[str, Any]]
    
    # Checklist management
    checklist: Optional[List[Dict[str, Any]]]  # Task checklist
    current_task_id: Optional[str]  # Task currently being executed
    checklist_complete: bool  # Flag to route to reasoning when complete  


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
    from app.agent.tools.intent_classifier_tool import IntentClassifierTool
    
    tool = IntentClassifierTool(state)
    result = tool.execute(
        query=state["query"],
        context=state.get("context", {}),
        suggested_tools=state.get("suggested_tools", [])
    )
    
    # Merge result into state
    return {**state, **result}


# ============================================================
# PHASE INFERENCE - Imported from intelligence module
# ============================================================

from app.agent.intelligence import infer_phase



def prompt_analysis_node(state: AgentState) -> AgentState:
    """
    Analyze user prompt with General Model.
    
    Flow:
    1. Analyze prompt → extract requirements
    2. Extract target (with typo handling)
    3. Create checklist from analyzed prompt
    """
    from app.agent.analyzer import get_user_prompt_analyzer
    
    analyzer = get_user_prompt_analyzer()
    query = state.get("query", "")
    context = state.get("context", {})
    
    # Analyze prompt
    analysis = analyzer.analyze_prompt(query, context)
    
    # Extract target
    target = analyzer.extract_target(query, context)
    if target:
        context["target_hint"] = target
    
    # Create checklist if needed
    response_text = ""
    if analysis.get("needs_checklist", True):
        checklist_result = analyzer.create_checklist(query, context)
        context = checklist_result.get("context", context)
        if checklist_result.get("checklist"):
            context["checklist"] = checklist_result["checklist"]
            # Build response message about checklist creation
            checklist = context.get("checklist", [])
            if checklist:
                response_text = f"✅ Created {len(checklist)} tasks in checklist.\n\n"
                response_text += "Next step: Verify target domain, then proceed with execution.\n"
                response_text += "Type 'yes' to continue to target verification."
    
    return {
        **state,
        "context": context,
        "prompt_analysis": analysis,
        "response": response_text if response_text else "Prompt analyzed. Proceeding to target verification...",
        "next_action": "target_verification" if analysis.get("needs_checklist", True) else "planner"
    }


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
    from app.agent.analyzer import TargetVerificationTool
    
    tool = TargetVerificationTool(state)
    result = tool.execute(
        query=state["query"],
        context=state.get("context", {}),
        intent=state.get("intent", "")
    )
    
    # Merge result into state
    return {**state, **result}




def planner_node(state: AgentState) -> AgentState:
    """
    Plan using specialized agents via Coordinator.
    
    ENHANCED with Cursor-style patterns:
    1. Context Aggregation - Gather all context BEFORE LLM call
    2. Coordinator routes query to appropriate agent
    3. Validation - Check plan BEFORE returning to user
    4. Fallback - Suggest alternatives for unavailable tools
    """
    from app.agent.tools.planner_tool import PlannerTool
    
    tool = PlannerTool(state)
    result = tool.execute(
        query=state["query"],
        context=state.get("context", {})
    )
    
    # Merge result into state
    return {**state, **result}



def confirm_node(state: AgentState) -> AgentState:
    """
    Handle user confirmation.
    
    This node is reached when user responds to a suggestion.
    User can say "yes lets use amass" to select specific tools.
    
    AUTOCHAIN MODE: Auto-confirms if mode is "autochain"
    """
    # Auto-confirm in autochain mode
    mode = state.get("mode", "manual")
    if mode == "autochain":
        state["confirmed"] = True
    
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
        
        # Infer correct agent from tool type if not already set
        if not context.get("current_agent") or context.get("current_agent") == "base":
            # Map tools to agents
            # Use coordinator to find agent by tool (uses SPECIALIZED_TOOLS, not hardcoded)
            coordinator = get_coordinator()
            for tool in selected:
                agent = coordinator.get_agent_by_tool(tool)
                if agent:
                    context["current_agent"] = agent.AGENT_NAME
                    break
        
        return {
            **state,
            "selected_tools": selected,
            "context": context,
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
    from app.agent.tools.executor_tool import ExecutorTool
    
    tool = ExecutorTool(state)
    result = tool.execute(
        tools=state.get("selected_tools", []),
        params=state.get("tool_params", {}),
        context=state.get("context", {})
    )
    
    # Merge result into state
    return {**state, **result}


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
    
    AUTOCHAIN MODE:
    - If iteration < 5: Call small analyze
    - If iteration == 5: Call comprehensive analyze
    
    Decides:
    - DONE: Goal achieved, format and return results
    - CONTINUE: Suggest next step
    - ASK_USER: Need clarification
    """
    from app.agent.tools.analyzer_tool import AnalyzerTool
    
    mode = state.get("mode", "manual")
    autochain_iteration = state.get("autochain_iteration", 0)
    autochain_results = state.get("autochain_results", [])
    
    # Handle autochain mode
    if mode == "autochain":
        tool = AnalyzerTool(state)
        
        # Small analyze for iterations 0-4
        if autochain_iteration < 5:
            execution_results = state.get("execution_results", {})
            context = state.get("context", {})
            
            small_result = tool.execute_small_analyze(execution_results, context)
            
            # Store iteration result
            iteration_result = {
                "iteration": autochain_iteration + 1,
                "summary": small_result.get("summary", ""),
                "execution_results": execution_results,
                "successful_tools": small_result.get("successful_tools", []),
                "failed_tools": small_result.get("failed_tools", [])
            }
            autochain_results.append(iteration_result)
            
            # Update state
            state["autochain_results"] = autochain_results
            state["autochain_iteration"] = autochain_iteration + 1
            
            # Show small summary with better formatting using UI components
            iteration_num = autochain_iteration + 1
            summary = small_result.get('summary', '')
            successful = small_result.get('successful_tools', [])
            failed = small_result.get('failed_tools', [])
            
            try:
                from app.ui import AutoChainProgress
                progress = AutoChainProgress()
                progress.render_iteration_summary(iteration_num, summary, successful, failed)
            except ImportError:
                # Fallback if UI not available
                print(f"\n  📊 Iteration {iteration_num}/5 Summary:")
                print(f"     {summary}")
                if successful:
                    print(f"     ✅ Tools executed: {', '.join(successful)}")
                if failed:
                    print(f"     ❌ Failed tools: {', '.join(failed)}")
            
            # If not last iteration, continue to next iteration
            if autochain_iteration + 1 < 5:
                return {
                    **state,
                    "response": f"**Iteration {iteration_num}/5 completed**\n\n{summary}",
                    "next_action": "planner"  # Continue to next iteration
                }
            else:
                # Last iteration, do comprehensive analyze
                try:
                    from app.ui import get_logger
                    logger = get_logger()
                    logger.info("Generating comprehensive analysis from all 5 iterations...")
                except ImportError:
                    print(f"\n  🔍 Generating comprehensive analysis from all 5 iterations...\n")
                comprehensive_result = tool.execute_comprehensive_analyze(autochain_results, context)
                
                # Add summary header
                comprehensive_response = comprehensive_result.get("response", "")
                comprehensive_result["response"] = f"# 🎯 AutoChain Mode - Final Comprehensive Analysis\n\n{comprehensive_response}"
                
                return {
                    **state,
                    **comprehensive_result,
                    "mode": "manual"  # Switch back to manual after autochain completes
                }
        else:
            # Should not reach here, but fallback
            return {**state, "next_action": "respond"}
    else:
        # Manual mode - normal flow
        tool = AnalyzerTool(state)
        result = tool.execute(
            results=state.get("execution_results", {}),
            context=state.get("context", {})
        )
        
        # Merge result into state
        return {**state, **result}


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
            try:
                from app.ui import get_logger
                logger = get_logger()
                logger.info(f"Found {len(all_targets)} targets ({len(subdomains)} subdomains + main)")
            except ImportError:
                print(f"  📋 Found {len(all_targets)} targets ({len(subdomains)} subdomains + main)")
        
        # Also check context for subdomains
        if not subdomains and context.get("subdomains"):
            subdomains = [clean_domain(s) for s in context.get("subdomains", []) if s]
            all_targets = list(set([domain] + subdomains)) if domain else subdomains
            try:
                from app.ui import get_logger
                logger = get_logger()
                logger.info(f"Using context subdomains: {len(subdomains)}")
            except ImportError:
                print(f"  📋 Using context subdomains: {len(subdomains)}")
            
    except Exception as e:
        try:
            from app.ui import get_logger
            logger = get_logger()
            logger.warning(f"Could not get subdomains: {e}")
        except ImportError:
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
    # If response was already streamed/rendered via UI components, just end
    # (UI components already show analysis and recommendations)
    if state.get("response_streamed"):
        return {**state, "next_action": "end"}
    
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
    
    # If we have suggested_tools but no message, create a simple suggestion
    # (This should only happen if UI components weren't used)
    if state.get("suggested_tools"):
        tools = ", ".join(state.get("suggested_tools", []))
        return {
            **state,
            "response": f"Suggested tools: {tools}. Type 'yes' to proceed.",
            "next_action": "end"
        }
    
    return {
        **state,
        "response": "",  
        "next_action": "end"
    }


def question_node(state: AgentState) -> AgentState:
    """Answer using LLM knowledge + scan context + web research."""
    from app.agent.tools.question_tool import QuestionTool
    
    tool = QuestionTool(state)
    result = tool.execute(
        query=state["query"],
        context=state.get("context", {})
    )
    
    # Merge result into state
    return {**state, **result}


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
    from app.agent.tools.memory_query_tool import MemoryQueryTool
    
    tool = MemoryQueryTool(state)
    result = tool.execute(
        context=state.get("context", {})
    )
    
    # Merge result into state
    return {**state, **result}


def task_breakdown_node(state: AgentState) -> AgentState:
    """
    Break down user request into checklist tasks.
    
    Uses general model to analyze user prompt and create structured task checklist.
    Only runs for complex SECURITY_TASK requests (attack, assess, etc.).
    """
    from app.agent.analyzer import TaskBreakdownTool
    
    tool = TaskBreakdownTool(state)
    result = tool.execute(
        query=state.get("query", ""),
        context=state.get("context", {})
    )
    
    # Merge result into state
    return {**state, **result}


def reasoning_node(state: AgentState) -> AgentState:
    """
    Comprehensive reasoning and analysis of all results.
    
    Uses reasoning model to analyze complete checklist results and provide
    final assessment, recommendations, and next steps.
    """
    from app.agent.tools.reasoning_tool import ReasoningTool
    
    tool = ReasoningTool(state)
    result = tool.execute(
        context=state.get("context", {})
    )
    
    # Merge result into state
    return {**state, **result}


# ============================================================
# GRAPH ROUTING
# ============================================================

def route_after_intent(state: AgentState) -> str:
    """Route based on intent classification."""
    intent = state.get("intent", "question")
    query = state.get("query", "")
    
    # #region agent log
    try:
        import json
        with open("snode_debug.log", "a") as f:
            f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H1","location":"graph.py:756","message":"Route after intent","data":{"intent":intent,"query":query,"will_route_to_target_verification":intent=="security_task"},"timestamp":int(__import__("time").time()*1000)})+"\n")
    except: pass
    # #endregion
    
    if intent == "security_task":
        return "prompt_analysis"  # New: analyze prompt first, then verify target
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
        "target_verification": "target_verification",
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
    graph.add_node("prompt_analysis", prompt_analysis_node)  # NEW: Prompt analysis with General Model
    graph.add_node("task_breakdown", task_breakdown_node)  # Task breakdown for complex requests
    graph.add_node("target_verification", target_verification_node)
    graph.add_node("planner", planner_node)
    graph.add_node("confirm", confirm_node)
    graph.add_node("executor", executor_node)
    graph.add_node("analyzer", analyzer_node)
    graph.add_node("reasoning", reasoning_node)  # NEW: Comprehensive reasoning
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
            "prompt_analysis": "prompt_analysis",
            "task_breakdown": "task_breakdown",
            "target_verification": "target_verification",
            "planner": "planner",
            "confirm": "confirm",
            "memory_query": "memory_query",
            "question": "question"
        }
    )
    
    # Prompt analysis routes to target verification
    graph.add_conditional_edges(
        "prompt_analysis",
        route_after_action,
        {
            "target_verification": "target_verification",
            "planner": "planner",
            "respond": "respond",
            END: END
        }
    )
    
    # Task breakdown routes to planner
    graph.add_conditional_edges(
        "task_breakdown",
        route_after_action,
        {
            "planner": "planner",
            "respond": "respond",
            END: END
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
            "reasoning": "reasoning",  # NEW: Route to reasoning if checklist complete
            "confirm": "respond",
            "respond": "respond",
            "planner": "planner",
            "auto_chain": "auto_chain",  # NEW: Auto-chain for autonomous mode
            END: END
        }
    )
    
    # Reasoning routes to respond
    graph.add_conditional_edges(
        "reasoning",
        route_after_action,
        {
            "respond": "respond",
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
        
        # Mode management
        self.mode = "manual"  # "manual" or "autochain"
        self.autochain_iteration_count = 0
        self.autochain_results = []
        
        # Initialize session memory 
        try:
            from app.memory import get_session_memory
            self.memory = get_session_memory()
        except Exception as e:
            print(f"⚠️ Memory init failed: {e}")
            self.memory = None
    
    def set_mode(self, mode: str):
        """Switch between 'manual' and 'autochain' modes."""
        if mode not in ["manual", "autochain"]:
            raise ValueError(f"Invalid mode: {mode}. Must be 'manual' or 'autochain'")
        self.mode = mode
        if mode == "autochain":
            # Reset iteration count when switching to autochain
            self.autochain_iteration_count = 0
            self.autochain_results = []
        print(f"  🔄 Mode switched to: {mode.upper()}")
    
    def _run_autochain_iteration(self, query: str, context: Dict[str, Any]) -> tuple[str, Dict[str, Any], bool, bool]:
        """
        Run a single iteration in autochain mode.
        
        Enhanced with progress tracking and better visualization.
        
        Returns:
            (response, context, needs_confirmation, response_streamed)
        """
        # Show progress indicator
        iteration_num = self.autochain_iteration_count + 1
        print(f"\n{'='*70}")
        print(f"  🔄 AutoChain Mode - Iteration {iteration_num}/5")
        print(f"{'='*70}\n")
        
        # Load conversation history
        messages = []
        if self.memory:
            try:
                messages = self.memory.get_llm_context(max_messages=20)
            except Exception:
                pass
        
        messages.append({"role": "user", "content": query})
        
        # Initial state with autochain mode
        state = AgentState(
            query=query,
            messages=messages,
            intent="",
            suggested_tools=[],
            suggestion_message="",
            tool_params={},
            confirmed=True,  # Auto-confirm in autochain mode
            selected_tools=[],
            execution_results={},
            context=context,
            response="",
            next_action="",
            mode="autochain",
            autochain_iteration=self.autochain_iteration_count,
            autochain_results=self.autochain_results
        )
        
        # Config with thread
        config = {"configurable": {"thread_id": self.thread_id}}
        
        # Run graph for one iteration
        result = self.graph.invoke(state, config)
        
        # Update context and iteration count
        self.context = result.get("context", self.context)
        self.autochain_iteration_count = result.get("autochain_iteration", self.autochain_iteration_count)
        self.autochain_results = result.get("autochain_results", self.autochain_results)
        
        if result.get("execution_results"):
            self.last_results.update(result.get("execution_results", {}))
        
        response = result.get("response") or result.get("suggestion_message") or "No response"
        response_streamed = result.get("response_streamed", False)
        
        # Save conversation
        if self.memory:
            self.memory.add_message("user", query)
            self.memory.add_message("assistant", response)
        
        # Check if we need to continue to next iteration
        needs_confirmation = False
        if self.autochain_iteration_count < 5 and result.get("next_action") == "planner":
            # Continue to next iteration
            needs_confirmation = False
            try:
                from app.ui import get_logger
                logger = get_logger()
                logger.success(f"Iteration {iteration_num}/5 completed. Continuing to next iteration...")
            except ImportError:
                print(f"\n  ✅ Iteration {iteration_num}/5 completed. Continuing to next iteration...\n")
        elif self.autochain_iteration_count >= 5:
            # All iterations done, show comprehensive summary
            try:
                from app.ui import AutoChainProgress
                progress = AutoChainProgress()
                progress.render_completion()
            except ImportError:
                print(f"\n{'='*70}")
                print(f"  🎯 AutoChain Mode - All 5 iterations completed!")
                print(f"{'='*70}\n")
            self.mode = "manual"
        
        return response, self.context, needs_confirmation, response_streamed
    
    def run(self, query: str, context: Dict[str, Any] = None) -> tuple[str, Dict[str, Any], bool, bool]:
        """
        Process user input.
        
        Returns:
            (response, context, needs_confirmation, response_streamed)
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
        
        # Phase 2: Compress history if over limit (before LLM calls)
        try:
            from app.memory import get_memory_manager
            memory_manager = get_memory_manager()
            
            # Set agent for compression (if available)
            if hasattr(self, '_agent_for_compression'):
                memory_manager.set_agent(self._agent_for_compression)
            
            # Compress history if needed
            import asyncio
            compressed = asyncio.run(memory_manager.compress_history())
            if compressed:
                print("  📦 History compressed to fit context window")
            
            # Use topic-based history if available (Phase 1)
            history_messages = memory_manager.get_history_messages()
            if history_messages:
                # Convert to format expected by graph
                messages = [
                    {"role": "user" if not msg.get("ai") else "assistant", "content": msg.get("content", "")}
                    for msg in history_messages
                ]
        except Exception as e:
            # Fallback to old system if topic-based history fails
            pass
        
        # If no memory or empty, ensure current query is added to history view (state only)
        # Note: We don't save to memory yet, that happens after response
        messages.append({"role": "user", "content": query})
        
        # Check if AutoChain mode should be enabled (from "attack" command)
        if context and context.get("_enable_autochain"):
            self.set_mode("autochain")
            # Use original trigger query if available
            if context.get("_autochain_trigger"):
                query = context.get("_autochain_trigger")
            context.pop("_enable_autochain", None)
            context.pop("_autochain_trigger", None)
        
        # If we have a pending confirmation and user says yes/no
        suggested_tools = []
        tool_params = {}
        if self.pending_confirmation and self.last_suggestion:
            suggested_tools = self.last_suggestion.get("tools", [])
            tool_params = self.last_suggestion.get("params", {})
        
        # Handle autochain mode - check BEFORE normal flow
        # If mode is autochain and user just confirmed, use original trigger query
        if self.mode == "autochain" and self.autochain_iteration_count < 5:
            # If user just confirmed (query is "yes" or similar), use stored trigger query
            if query.lower() in ["yes", "y", "ok", "go", "run", "execute", "proceed"]:
                # Get original trigger from context if available
                original_query = self.context.get("_autochain_trigger") or self.context.get("last_autochain_query")
                if original_query:
                    query = original_query
                # Store for next iteration
                self.context["last_autochain_query"] = query
            # Run autochain loop
            return self._run_autochain_iteration(query, self.context)
        
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
            next_action="",
            mode=self.mode,
            autochain_iteration=self.autochain_iteration_count,
            autochain_results=self.autochain_results
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
        response_streamed = result.get("response_streamed", False)  # Check if response was already streamed
        
        # Save conversation to session memory
        if self.memory:
            self.memory.add_message("user", query)
            self.memory.add_message("assistant", response)
        
        # Phase 1: Also save to topic-based history
        try:
            from app.memory import get_memory_manager
            memory_manager = get_memory_manager()
            memory_manager.save_turn(
                user_message=query,
                assistant_message=response,
                tools_used=result.get("selected_tools", []),
                context=result.get("context", {})
            )
        except Exception as e:
            # Fallback if topic-based history fails
            pass
        
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
        
        return response, self.context, needs_confirmation, response_streamed
    
    def clear_history(self):
        """Clear conversation history."""
        self.messages = []
        self.context = {}


# Factory function
def create_langgraph_agent() -> LangGraphAgent:
    return LangGraphAgent()
