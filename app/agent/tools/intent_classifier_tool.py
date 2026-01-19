"""
Intent Classifier Tool - Clean Refactored Version

Classifies user intent using LLM and pattern matching.
Main purpose: Determine if user wants to run security tasks, query memory, ask questions, or confirm actions.

Focus: Clean code structure with helper functions.
"""
import re
import json
from typing import Dict, Any, Optional
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient
from app.ui import get_logger

logger = get_logger()


def _sanitize_query(query: str) -> str:
    """Sanitize input - remove box-drawing characters and extra whitespace."""
    if not query:
        return ""
    # Remove common terminal box-drawing and special characters
    query = re.sub(r'[│┌┐└┘├┤┬┴┼─═║╔╗╚╝╠╣╦╩╬]', '', query)
    query = re.sub(r'\s+', ' ', query)  # Collapse whitespace
    return query.strip()


def _check_target_verification_pending(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Check if target verification is pending."""
    if context.get("target_verification_pending"):
        logger.info("Target verification pending, routing back to target_verification")
        return {
            "intent": "security_task",
            "context": context
        }
    return None


def _check_autochain_mode(query_lower: str, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Check if query triggers AutoChain mode."""
    auto_mode_triggers = ["attack ", "autonomous ", "auto ", "pentest ", "pwn ", "hack "]
    if any(query_lower.startswith(trigger) for trigger in auto_mode_triggers):
        context["_enable_autochain"] = True
        context["_autochain_trigger"] = query_lower
        logger.info("AutoChain Mode will be enabled - 5 iterations with comprehensive analysis")
        return {
            "intent": "security_task",
            "context": context
        }
    return None


def _check_quick_confirmations(query: str) -> Optional[Dict[str, Any]]:
    """Check for quick confirmations (exact matches - no LLM needed)."""
    if query.lower() in ["yes", "y", "ok", "go", "run", "execute", "proceed"]:
        return {"intent": "confirm", "confirmed": True}
    if query.lower() in ["no", "n", "cancel", "stop", "abort"]:
        return {"intent": "confirm", "confirmed": False}
    return None


def _parse_modifications_fast(mod_text: str) -> Dict[str, Any]:
    """Fast path: Parse modifications using regex patterns (no LLM)."""
    modifications = {}
    
    fast_patterns = {
        r'\b(all\s*)?(sub)?domains?\b': ("scan_subdomains", True),
        r'\ball\s*(targets?|hosts?)\b': ("scan_all_targets", True),
        r'\bhistorical\s*(ips?|servers?)\b': ("scan_historical", True),
        r'\borigin\s*(ips?|servers?)\b': ("scan_historical", True),
        r'\bcloudflare\s*(ips?)\b': ("scan_cloudflare", True),
        r'\bcdn\s*(ips?)\b': ("scan_cloudflare", True),
        r'\ball\s*ips?\b': ("scan_all_ips", True),
        r'\btop\s*100\b': ("ports", "100"),
        r'\btop\s*1000\b': ("ports", "1000"),
        r'\b(all\s*ports?|full\s*scan|-p-)\b': ("ports", "1-65535"),
        r'\bquick\s*(scan)?\b': ("ports", "100"),
        r'\b(fast|quick|rapid)\b': ("speed", "fast"),
        r'\b(slow|thorough|deep)\b': ("speed", "thorough"),
    }
    
    for pattern, (key, value) in fast_patterns.items():
        if re.search(pattern, mod_text):
            modifications[key] = value
            logger.info(f"Fast path: {key}={value}")
    
    return modifications


def _parse_modifications_llm(mod_text: str) -> Dict[str, Any]:
    """LLM path: Parse complex modifications using LLM."""
    try:
        from app.llm.config import get_planner_model
        planner_model = get_planner_model()
        
        if "functiongemma" in planner_model.lower() or "nemotron" in planner_model.lower():
            llm = OllamaClient(model="planner")
        else:
            llm = OllamaClient()
        
        parse_prompt = f"""User confirmed a security scan with modifications: "{mod_text}"

Extract any modifications. Return JSON only:
{{
  "scan_subdomains": true/false,
  "ports": "100" or "1000" or "1-65535" or null,
  "speed": "fast" or "thorough" or null,
  "specific_target": "subdomain or IP if mentioned" or null
}}

If no clear modifications, return: {{"no_changes": true}}
JSON only, no explanation:"""
        
        response = llm.generate(parse_prompt, timeout=10, stream=False)
        
        # Parse LLM response
        json_match = re.search(r'\{[^{}]+\}', response)
        if json_match:
            parsed = json.loads(json_match.group())
            if not parsed.get("no_changes"):
                modifications = {}
                for k, v in parsed.items():
                    if v and k != "no_changes":
                        modifications[k] = v
                        logger.info(f"LLM parsed: {k}={v}", icon="")
                return modifications
    except Exception as e:
        logger.warning(f"LLM parse skipped: {e}")
    
    return {}


def _handle_confirmation_with_modifications(query: str, suggested_tools: list, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Handle confirmation with potential modifications."""
    if not suggested_tools or "yes" not in query.lower() and not query.endswith(" y"):
        return None
    
    logger.info(f"Confirming pending suggestion: {suggested_tools}")
    
    # Remove "yes" prefix to get the modification part
    mod_text = re.sub(r'^(yes|ok|go|y)\s*(but|and|with|,)?\s*', '', query.lower()).strip()
    
    # Fast path first
    modifications = _parse_modifications_fast(mod_text)
    
    # LLM path if needed
    if mod_text and len(mod_text) > 5 and not modifications:
        modifications = _parse_modifications_llm(mod_text)
    
    # Store modifications in context
    updated_context = context.copy()
    if modifications:
        updated_context["user_modifications"] = modifications
    
    return {"intent": "confirm", "confirmed": True, "context": updated_context}


def _check_target_correction(query: str, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Check if query is a target correction."""
    if query.startswith("no") and len(query) > 5:
        correction_indicators = ["its", "it's", "the one", "actually", "meant", "in ", "from ", ".za", ".co", ".com"]
        if any(ind in query for ind in correction_indicators):
            logger.info("Target correction detected: routing to verification", icon="")
            context["is_correction"] = True
            context["correction_query"] = query
            return {"intent": "security_task", "context": context}
    return None


def _check_simple_questions(query_lower: str) -> Optional[Dict[str, Any]]:
    """Check for simple identity questions (fast path, no LLM)."""
    action_verbs = ["attack", "scan", "assess", "pentest", "pwn", "hack", "enumerate", 
                   "check", "find", "lookup", "run", "use", "exploit", "test"]
    has_action_verb = any(verb in query_lower for verb in action_verbs)
    
    # Only check simple questions if NO action verbs present
    if not has_action_verb:
        simple_keywords = ["who are you", "what are you", "what is snode", "what can you do", 
                          "tell me about yourself", "who is snode", "what is this"]
        if any(keyword in query_lower for keyword in simple_keywords):
            logger.info("Fast path: Simple identity question detected, routing to question node")
            return {"intent": "question"}
    return None


def _detect_suggestion_command(query: str, context_summary: str, suggested_tools: list) -> bool:
    """Detect if query is a suggestion command."""
    try:
        from app.agent.prompt_loader import format_prompt
        from app.llm.config import get_planner_model
        
        planner_model = get_planner_model()
        if "functiongemma" in planner_model.lower() or "nemotron" in planner_model.lower():
            detector_llm = OllamaClient(model="planner")
        else:
            detector_llm = OllamaClient()
        
        suggested_tools_str = ', '.join(suggested_tools) if suggested_tools else "None"
        suggestion_prompt = format_prompt(
            "suggestion_command_detector",
            query=query,
            context_summary=context_summary if context_summary else "No prior context",
            suggested_tools=suggested_tools_str
        )
        
        suggestion_response = detector_llm.generate(suggestion_prompt, timeout=8, stream=False)
        response_upper = suggestion_response.strip().upper()
        return "SUGGESTION_COMMAND" in response_upper
    except Exception as e:
        logger.warning(f"Suggestion command detection failed: {e}")
        return False


def _detect_confirmation(query: str, query_lower: str, context_summary: str, 
                        suggested_tools: list) -> Optional[Dict[str, Any]]:
    """Detect if query is a confirmation."""
    try:
        from app.agent.prompt_loader import format_prompt
        from app.llm.config import get_planner_model
        
        planner_model = get_planner_model()
        if "functiongemma" in planner_model.lower() or "nemotron" in planner_model.lower():
            detector_llm = OllamaClient(model="planner")
        else:
            detector_llm = OllamaClient()
        
        suggested_tools_str = ', '.join(suggested_tools) if suggested_tools else "None"
        confirmation_prompt = format_prompt(
            "confirmation_detector",
            query=query,
            context_summary=context_summary if context_summary else "No prior context",
            suggested_tools=suggested_tools_str
        )
        
        confirmation_response = detector_llm.generate(confirmation_prompt, timeout=8, stream=False)
        response_upper = confirmation_response.strip().upper()
        is_confirmation = "CONFIRMATION" in response_upper
        
        if is_confirmation:
            # Extract selected tools if mentioned in query
            selected = []
            if suggested_tools:
                for tool in suggested_tools:
                    if tool.lower() in query_lower:
                        selected.append(tool)
            
            if selected:
                return {
                    "intent": "confirm",
                    "confirmed": True,
                    "selected_tools": selected
                }
            
            # General confirmation
            if suggested_tools:
                return {"intent": "confirm", "confirmed": True}
    except Exception as e:
        logger.warning(f"Confirmation detection failed: {e}")
    
    return None


def _classify_intent_intelligence(query: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """Classify intent using intelligence layer."""
    from app.agent.intelligence import get_intelligence
    
    intel = get_intelligence()
    
    logger.info("Intelligence layer analyzing...", icon="")
    
    try:
        # Get semantic understanding of query
        understanding = intel.understand_query(query, context)
        
        # Store understanding in state for later use
        understanding_dict = {"query_understanding": understanding}
        
        # Use intelligence layer for intent classification
        intent = intel.classify_intent(query, context)
        
        # Map intent
        intent_map = {
            "SECURITY_TASK": "security_task",
            "MEMORY_QUERY": "memory_query", 
            "QUESTION": "question"
        }
        mapped_intent = intent_map.get(intent, "security_task")
        
        # Log what we understood
        if understanding.get("detected_target"):
            logger.info(f"Target: {understanding['detected_target']}", icon="")
        
        logger.info(f"Intent: {intent.upper()}", icon="")
        
        return {
            **understanding_dict,
            "intent": mapped_intent
        }
    except Exception as e:
        logger.warning(f"Intelligence layer failed: {e}, defaulting to security_task")
        return {"intent": "security_task"}


def _handle_suggestion_command(context: Dict[str, Any]) -> None:
    """Handle suggestion command - get analyzer recommendation."""
    analyzer_next_tool = context.get("analyzer_next_tool")
    
    if not analyzer_next_tool:
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
        except Exception:
            pass
    
    if analyzer_next_tool:
        context["user_requested_tool"] = analyzer_next_tool
        context["user_requested_target"] = context.get("analyzer_next_target")


class IntentClassifierTool(AgentTool):
    """
    Tool for classifying user intent.
    
    Main purpose:
    - Determine if user wants to run security tasks (scan, exploit, etc.)
    - Detect memory queries (show stored data)
    - Identify questions (conceptual questions)
    - Handle confirmations (yes/no with modifications)
    - Enable AutoChain mode for autonomous attacks
    """
    
    def execute(self, query: str = None, context: Dict[str, Any] = None, suggested_tools: list = None, **kwargs) -> Dict[str, Any]:
        """
        Classify user intent.
        
        Args:
            query: User query string
            context: Current context dictionary
            suggested_tools: Previously suggested tools
            
        Returns:
            Dictionary with intent classification and context updates
        """
        if query is None and self.state:
            query = self.state.get("query", "")
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        if suggested_tools is None:
            suggested_tools = self.state.get("suggested_tools", []) if self.state else []
        
        # Sanitize input
        query = _sanitize_query(query or "")
        query_lower = query.lower()
        
        # Fast path checks (in order of priority)
        
        # 1. Check target verification pending
        result = _check_target_verification_pending(context)
        if result:
            return result
        
        # 2. Check AutoChain mode
        result = _check_autochain_mode(query_lower, context)
        if result:
            return result
        
        # 3. Check quick confirmations
        result = _check_quick_confirmations(query)
        if result:
            result["context"] = context
            return result
        
        # 4. Handle confirmation with modifications
        result = _handle_confirmation_with_modifications(query, suggested_tools, context)
        if result:
            return result
        
        # 5. Check target correction
        result = _check_target_correction(query, context)
        if result:
            return result
        
        # 6. Check simple questions (fast path)
        result = _check_simple_questions(query_lower)
        if result:
            result["context"] = context
            return result
        
        # Build context summary using intelligence layer
        from app.agent.intelligence import get_intelligence
        intel = get_intelligence()
        context_summary = intel._build_context_summary(context) if context else "No prior context"
        
        # Check if query contains a domain/IP
        detected_target = intel._extract_target(query)
        has_domain = detected_target is not None
        domain_note = "NOTE: Message contains a domain/IP address" if has_domain else ""
        
        # 7. Detect suggestion command
        if _detect_suggestion_command(query, context_summary, suggested_tools):
            _handle_suggestion_command(context)
        
        # 8. Detect confirmation
        result = _detect_confirmation(query, query_lower, context_summary, suggested_tools)
        if result:
            result["context"] = context
            return result
        
        # 9. Intelligent intent classification (main path)
        result = _classify_intent_intelligence(query, context)
        result["context"] = context
        return result
