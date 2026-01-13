"""
Intent Classifier Tool

Extracts and encapsulates logic from intent_node().
Classifies user intent using LLM and pattern matching.
"""
import re
import json
from typing import Dict, Any
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient
from app.ui import get_logger

logger = get_logger()


class IntentClassifierTool(AgentTool):
    """Tool for classifying user intent."""
    
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
        
        # Sanitize input - remove box-drawing characters and extra whitespace
        query = query or ""
        # Remove common terminal box-drawing and special characters
        query = re.sub(r'[│┌┐└┘├┤┬┴┼─═║╔╗╚╝╠╣╦╩╬]', '', query)
        query = re.sub(r'\s+', ' ', query)  # Collapse whitespace
        query = query.lower().strip()
        
        # ─────────────────────────────────────────────────────────
        # AUTOCHAIN MODE DETECTION (NEW - Integrated)
        # "attack" command enables AutoChain mode (replaces old auto_mode)
        # ─────────────────────────────────────────────────────────
        auto_mode_triggers = ["attack ", "autonomous ", "auto ", "pentest ", "pwn ", "hack "]
        if any(query.startswith(trigger) for trigger in auto_mode_triggers):
            # Set flag to enable AutoChain mode in LangGraphAgent
            context["_enable_autochain"] = True
            context["_autochain_trigger"] = query  # Store original query
            logger.info("AutoChain Mode will be enabled - 5 iterations with comprehensive analysis")
            # Don't modify the query, just set the flag
        
        # Quick confirmations (exact matches - no LLM needed)
        if query in ["yes", "y", "ok", "go", "run", "execute", "proceed"]:
            return {"intent": "confirm", "confirmed": True, "context": context}

        if suggested_tools and ("yes" in query or query.endswith(" y")):
            logger.info(f"Confirming pending suggestion: {suggested_tools}")
            
            # ============================================================
            # HYBRID APPROACH: Fast path + LLM fallback
            # ============================================================
            modifications = {}
            query_lower = query.lower()
            
            # Remove "yes" prefix to get the modification part
            mod_text = re.sub(r'^(yes|ok|go|y)\s*(but|and|with|,)?\s*', '', query_lower).strip()
            
            # FAST PATH: Common patterns (no LLM needed - ~80% of cases)
            fast_patterns = {
                # Subdomain patterns
                r'\b(all\s*)?(sub)?domains?\b': ("scan_subdomains", True),
                r'\ball\s*(targets?|hosts?)\b': ("scan_all_targets", True),
                # Category scan patterns
                r'\bhistorical\s*(ips?|servers?)\b': ("scan_historical", True),
                r'\borigin\s*(ips?|servers?)\b': ("scan_historical", True),
                r'\bcloudflare\s*(ips?)\b': ("scan_cloudflare", True),
                r'\bcdn\s*(ips?)\b': ("scan_cloudflare", True),
                r'\ball\s*ips?\b': ("scan_all_ips", True),
                # Port patterns
                r'\btop\s*100\b': ("ports", "100"),
                r'\btop\s*1000\b': ("ports", "1000"),
                r'\b(all\s*ports?|full\s*scan|-p-)\b': ("ports", "1-65535"),
                r'\bquick\s*(scan)?\b': ("ports", "100"),
                # Speed patterns
                r'\b(fast|quick|rapid)\b': ("speed", "fast"),
                r'\b(slow|thorough|deep)\b': ("speed", "thorough"),
            }
            
            for pattern, (key, value) in fast_patterns.items():
                if re.search(pattern, mod_text):
                    modifications[key] = value
                    logger.info(f"Fast path: {key}={value}")
            
            # LLM PATH: Complex modifications (if fast path didn't catch everything)
            # Only use LLM if: mod_text exists AND fast path found nothing
            if mod_text and len(mod_text) > 5 and not modifications:
                try:
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
                            for k, v in parsed.items():
                                if v and k != "no_changes":
                                    modifications[k] = v
                                    print(f"  🧠 LLM parsed: {k}={v}")
                except Exception as e:
                    logger.warning(f"LLM parse skipped: {e}")
            
            # Store modifications in context for executor
            updated_context = context.copy()
            if modifications:
                updated_context["user_modifications"] = modifications
            
            return {"intent": "confirm", "confirmed": True, "context": updated_context}
        
        if query in ["no", "n", "cancel", "stop", "abort"]:
            return {"intent": "confirm", "confirmed": False, "context": context}
        
        if query.startswith("no") and len(query) > 5:
            correction_indicators = ["its", "it's", "the one", "actually", "meant", "in ", "from ", ".za", ".co", ".com"]
            if any(ind in query for ind in correction_indicators):
                print(f"  🔄 Target correction detected: routing to verification")
                context["is_correction"] = True
                context["correction_query"] = query
                return {"intent": "security_task", "context": context}
        
        # Check for "do the next step" command and use analyzer recommendation
        # Match: "do the next step", "next step", "do the next suggest step", etc.
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
        if is_suggestion_command:
            # Check context first
            analyzer_next_tool = context.get("analyzer_next_tool")
            
            # If not in context, check session memory (for persistence across queries)
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
                # User wants to do the next step - pass analyzer recommendation directly
                context["user_requested_tool"] = analyzer_next_tool
                context["user_requested_target"] = context.get("analyzer_next_target")
        
        if query.startswith(("yes", "ok", "let's", "lets", "go with")):
            is_short_confirmation = len(query) < 20
            
            selected = []
            for tool in suggested_tools:
                if tool.lower() in query:
                    selected.append(tool)
            
            if selected:
                return {
                    "intent": "confirm",
                    "confirmed": True,
                    "selected_tools": selected,
                    "context": context
                }
            
            # Only confirm if we have pending tools AND query is short
            if suggested_tools and is_short_confirmation:
                return {"intent": "confirm", "confirmed": True, "context": context}
        
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
        has_domain = bool(re.search(domain_pattern, query))
        
        # Load intent prompt
        from app.agent.prompt_loader import format_prompt
        
        prompt = format_prompt("intent_classifier",
            query=query,
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
            understanding = intel.understand_query(query, context)
            
            # Store understanding in state for later use (will be merged)
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
                print(f"  📍 Target: {understanding['detected_target']}")
            
            # Don't suggest tools here - wait until target is verified in planner_node
            # Tools will be suggested by specialized agents after target verification
            
            print(f"  → Intent: {intent.upper()}")
            
            return {
                **understanding_dict,
                "intent": mapped_intent,
                "context": context
            }
            
        except Exception as e:
            logger.warning(f"Intelligence layer: {e}, using fallback")
            
            # Fallback to simple LLM classification
            try:
                response = llm.generate(prompt, timeout=30)
                response_clean = response.strip().upper()
                
                if "MEMORY" in response_clean:
                    return {"intent": "memory_query", "context": context}
                elif "QUESTION" in response_clean:
                    return {"intent": "question", "context": context}
                else:
                    return {"intent": "security_task", "context": context}
            except Exception:
                return {"intent": "security_task", "context": context}
