"""
Target Verification Tool

Extracts and encapsulates logic from target_verification_node().
Verifies and resolves target ambiguity using LLM intelligence.
"""
import re
import json
from typing import Dict, Any, Optional
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient
from app.ui import get_logger

logger = get_logger()


class TargetVerificationTool(AgentTool):
    """Tool for verifying and resolving target ambiguity."""
    
    def execute(self, query: str = None, context: Dict[str, Any] = None, intent: str = None, **kwargs) -> Dict[str, Any]:
        """
        Verify and resolve target ambiguity.
        
        Args:
            query: User query string
            context: Current context dictionary
            intent: Classified intent
            
        Returns:
            Dictionary with verification result and context updates
        """
        if query is None and self.state:
            query = self.state.get("query", "")
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        if intent is None:
            intent = self.state.get("intent", "") if self.state else ""
        
        # Only verify for security tasks
        # #region agent log
        try:
            import json
            with open("snode_debug.log", "a") as f:
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H2","location":"target_verification_tool.py:40","message":"Target verification entry check","data":{"query":query,"intent":intent,"will_proceed":intent=="security_task"},"timestamp":int(__import__("time").time()*1000)})+"\n")
        except: pass
        # #endregion
        if intent != "security_task":
            # #region agent log
            try:
                import json
                with open("snode_debug.log", "a") as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H2","location":"target_verification_tool.py:48","message":"Early return - intent not security_task","data":{"intent":intent,"query":query},"timestamp":int(__import__("time").time()*1000)})+"\n")
            except: pass
            # #endregion
            return {}
        
        # helper to proceed to planner
        def proceed_to_planner():
            return {"next_action": "planner"}
        
        # ============================================================
        # CORRECTION DETECTION: Check context flag (set by intent_node)
        # The LLM extraction will also detect corrections semantically
        # ============================================================
        is_correction_from_context = context.get("is_correction", False)
        
        # If correction flag is set, clear the old target BEFORE we check for existing targets
        if is_correction_from_context:
            old_target = context.get("target_domain")
            if old_target:
                logger.info(f"Correction mode: clearing previous target '{old_target}'")
                context.pop("target_domain", None)
                context["last_candidate"] = old_target.split(".")[0] if "." in old_target else old_target
            context["is_correction"] = False  
        

        if not is_correction_from_context:
            if context.get("target_domain") and "." in context.get("target_domain"):
                print(f"  📍 Using verified target: {context.get('target_domain')}")
                return {**proceed_to_planner(), "context": context}
            if context.get("last_domain") and "." in context.get("last_domain"):
                return {**proceed_to_planner(), "context": context}
            
            
            domain_match = re.search(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', query)
            # #region agent log
            try:
                import json
                with open("snode_debug.log", "a") as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H5","location":"target_verification_tool.py:78","message":"Domain regex check","data":{"query":query,"domain_match":domain_match.group() if domain_match else None},"timestamp":int(__import__("time").time()*1000)})+"\n")
            except: pass
            # #endregion
            if domain_match:
                potential_domain = domain_match.group()
                if not context.get("last_domain"):
                    context["last_domain"] = potential_domain
                    print(f"  📍 Domain found in query: {potential_domain}")
                return {"context": context, "next_action": "planner"}
            
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
            if ip_match:
                return proceed_to_planner()

        
        # 3. LLM-ONLY Target Extraction (NO KEYWORD LISTS)
        try:
            from app.agent.prompt_loader import format_prompt
            
            # Build conversation context from recent messages
            messages = self.state.get("messages", []) if self.state else []
            conversation_context = "None"
            if messages:
                recent = messages[-6:]  
                context_lines = []
                for msg in recent:
                    role = msg.get("role", "user").upper()
                    content = msg.get("content", "")[:200]
                    context_lines.append(f"{role}: {content}")
                conversation_context = "\n".join(context_lines) if context_lines else "None"
            
            if context.get("last_candidate"):
                conversation_context += f"\n(Previously discussed: {context.get('last_candidate')})"
            if context.get("target_domain"):
                conversation_context += f"\n(Resolved domain: {context.get('target_domain')})"
            
            extraction_prompt = format_prompt("target_extraction", query=query, conversation_context=conversation_context)
            # Use general model for target extraction (better at understanding intent and extracting entities)
            from app.llm.config import get_general_model
            general_model = get_general_model()
            llm = OllamaClient(model="general") if general_model else OllamaClient()
            extraction_response = llm.generate(extraction_prompt, timeout=20, stream=False, show_content=False).strip()
            
            # Parse extraction JSON
            extraction = {}
            try:
                json_match = re.search(r'\{.*\}', extraction_response, re.DOTALL)
                if json_match:
                    extraction = json.loads(json_match.group(), strict=False)
            except Exception as e:
                logger.warning(f"Extraction parse error: {e}")
            
            entity_name = extraction.get("entity_name", "").strip()
            user_context = extraction.get("user_context", "")
            search_query = extraction.get("search_query", "")
            is_followup = extraction.get("is_followup", False)
            is_correction = extraction.get("is_correction", False)
            resolved_domain = extraction.get("resolved_domain", "")
            corrected_from = extraction.get("corrected_from")
            confidence = extraction.get("confidence", "medium")
            interpretation = extraction.get("interpretation", "")
            
            # #region agent log
            try:
                import json
                with open("snode_debug.log", "a") as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H3","location":"target_verification_tool.py:137","message":"Entity extraction result","data":{"entity_name":entity_name,"entity_name_len":len(entity_name),"search_query":search_query,"resolved_domain":resolved_domain},"timestamp":int(__import__("time").time()*1000)})+"\n")
            except: pass
            # #endregion
            
            # Log typo corrections
            if corrected_from:
                logger.info(f"Corrected typo: '{corrected_from}' → '{entity_name or resolved_domain}'")
            
            # Only log interpretation if it's actually a correction AND we're clearing an old target
            # Don't log generic interpretations for normal queries
            if interpretation and is_correction and context.get("target_domain"):
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
                # IMPORTANT: When user corrects/clarifies, DO NOT auto-resolve domain
                # Must re-search web and ask user to confirm again
                # Clear resolved_domain to force re-verification
                if resolved_domain:
                    logger.info(f"Correction detected: ignoring auto-resolved domain '{resolved_domain}', will re-search and ask user")
                    resolved_domain = ""  # Force re-verification
            
            # Handle follow-up references (pronouns, "assess them", etc.)
            if is_followup and not is_correction:
                if context.get("last_candidate") and not entity_name:
                    entity_name = context.get("last_candidate")
                    print(f"  🧠 Follow-up detected, using: {entity_name}") 
                if context.get("target_domain") and not resolved_domain:
                    resolved_domain = context.get("target_domain")
            
            # If LLM extracted a domain directly (e.g., "no, its hellogroup.co.za" or corrected typo)
            # BUT: Only auto-resolve if NOT a correction/clarification
            # When user clarifies (e.g., "its hellogroup from South Africa"), we must re-search and ask
            if resolved_domain and "." in resolved_domain and not is_correction:
                logger.success(f"Direct domain resolved: {resolved_domain}")
                context["target_domain"] = resolved_domain
                context["last_candidate"] = entity_name or resolved_domain.split(".")[0]
                # Clear target verification pending flag since we resolved the target
                context.pop("target_verification_pending", None)
                context.pop("pending_entity_name", None)
                return {"context": context, "next_action": "planner"}
            
            if not entity_name or len(entity_name) < 2:
                # #region agent log
                try:
                    import json
                    with open("snode_debug.log", "a") as f:
                        f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H3","location":"target_verification_tool.py:176","message":"Entity name too short or empty","data":{"entity_name":entity_name,"entity_name_len":len(entity_name) if entity_name else 0,"has_stored_domain":bool(context.get("target_domain"))},"timestamp":int(__import__("time").time()*1000)})+"\n")
                except: pass
                # #endregion
                # Last resort: check if we have a stored domain to use
                if context.get("target_domain"):
                    logger.info(f"Using stored domain: {context.get('target_domain')}")
                    return {"next_action": "planner"}
                logger.warning("No entity extracted. Proceeding to planner.")
                return proceed_to_planner()
            
            logger.info(f"Target '{entity_name}' (context: {user_context or 'none'}) detected. Verifying...")
            
            # 4. Web Search with LLM-generated query
            from app.tools.custom.web_research import web_search
            
            if not search_query:
                search_query = f"{entity_name} {user_context} official website".strip()
            
            # #region agent log
            try:
                import json
                with open("snode_debug.log", "a") as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H4","location":"target_verification_tool.py:193","message":"Before web search call","data":{"search_query":search_query,"entity_name":entity_name},"timestamp":int(__import__("time").time()*1000)})+"\n")
            except: pass
            # #endregion
            
            logger.info(f"Researching: {search_query}...")
            research = web_search(search_query, max_results=5)
            
            # #region agent log
            try:
                import json
                with open("snode_debug.log", "a") as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H4","location":"target_verification_tool.py:197","message":"Web search result","data":{"success":research.get("success") if research else False,"has_snippets":bool(research.get("snippets")) if research else False,"snippet_count":len(research.get("snippets",[])) if research else 0,"error":research.get("error") if research else None},"timestamp":int(__import__("time").time()*1000)})+"\n")
            except: pass
            # #endregion
            
            if not research or not research.get("success"):
                # #region agent log
                try:
                    import json
                    with open("snode_debug.log", "a") as f:
                        f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H4","location":"target_verification_tool.py:200","message":"Web search failed or no results","data":{"research":research},"timestamp":int(__import__("time").time()*1000)})+"\n")
                except: pass
                # #endregion
                logger.warning("No search results. Proceeding to planner.")
                return proceed_to_planner()
            
            research_str = ""
            for i, (snip, src) in enumerate(zip(research.get("snippets", []), research.get("sources", []))):
                research_str += f"Source {i+1}: {src.get('title', 'N/A')} ({src.get('url', '')})\nSnippet: {snip}\n\n"
            
            # 4.5. Extract detailed company/entity information from research
            company_info = None
            try:
                info_extraction_prompt = f"""Extract detailed information about the entity "{entity_name}" from the following web search results.

Search Results:
{research_str}

Extract and return a JSON object with the following structure:
{{
    "name": "Full company/organization name",
    "location": "Location (city, country)",
    "industry": "Industry or business type",
    "description": "Brief description of what they do",
    "website": "Official website domain",
    "additional_info": "Any other relevant information (founded year, size, services, etc.)"
}}

If information is not available, use "N/A" for that field. Return ONLY the JSON object."""
                
                info_response = llm.generate(info_extraction_prompt, timeout=30, stream=False, show_content=False).strip()
                
                # Parse company info JSON
                try:
                    info_json_match = re.search(r'\{.*\}', info_response, re.DOTALL)
                    if info_json_match:
                        company_info = json.loads(info_json_match.group(), strict=False)
                except Exception as e:
                    logger.warning(f"Company info extraction error: {e}")
            except Exception as e:
                logger.warning(f"Failed to extract company info: {e}")
            
            # 5. LLM Analysis with Full Context
            # OPTIMIZATION: If we already have company_info with website domain, we can extract domain directly
            # and skip the expensive verification prompt (saves ~45s)
            # BUT: Only skip if domain is valid (has TLD and proper format)
            extracted_domain_from_company = None
            analysis = {}  # Initialize analysis dict
            
            if company_info and company_info.get("website") and company_info.get("website") != "N/A":
                website = company_info.get("website", "").strip()
                # Extract domain from website URL if it's a full URL
                domain_match = re.search(r'(?:https?://)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', website)
                if domain_match:
                    extracted_domain_from_company = domain_match.group(1) if domain_match.lastindex else domain_match.group(0)
            
            # Validate domain before skipping verification prompt
            if extracted_domain_from_company and "." in extracted_domain_from_company:
                # Clean domain - remove trailing dot if present
                extracted_domain_from_company = extracted_domain_from_company.rstrip(".")
                
                # Validate domain format - must have at least 2 parts (domain.tld)
                domain_parts = extracted_domain_from_company.split(".")
                is_valid_domain = (
                    extracted_domain_from_company and 
                    not extracted_domain_from_company.startswith(".") and 
                    len(domain_parts) >= 2 and
                    all(len(part) > 0 for part in domain_parts) and
                    len(extracted_domain_from_company) > 4  # Minimum: a.co
                )
                
                if is_valid_domain:
                    logger.info(f"Found valid domain from company info: {extracted_domain_from_company}, skipping verification prompt")
                    analysis = {
                        "status": "clear",
                        "primary_domain": extracted_domain_from_company
                    }
                else:
                    # Domain from company_info is not valid (missing TLD or invalid format)
                    # Must run verification prompt to resolve to correct domain
                    logger.info(f"Found domain from company info but invalid format: '{extracted_domain_from_company}', running verification prompt to resolve")
                    extracted_domain_from_company = None  # Reset to force verification prompt
            
            # Run verification prompt if we don't have a valid domain from company_info
            if not analysis.get("status") == "clear":
                # Fallback to verification prompt if no clear domain from company_info
                verification_prompt = format_prompt(
                    "target_verification",
                    entity_name=entity_name,
                    original_query=query,
                    user_context=user_context or "None provided",
                    research_str=research_str
                )
                
                response = llm.generate(verification_prompt, timeout=45, stream=False, show_content=False).strip()
                
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
                    logger.warning(f"Verification parse error: {e}")
            
            status = analysis.get("status", "unknown")
            
            # Store candidate for follow-up queries
            context["last_candidate"] = entity_name
            
            # IMPORTANT: When user corrects/clarifies, ALWAYS ask for confirmation
            # Even if verification prompt returns "clear", we must ask user to confirm
            # because user just corrected us, so we need to verify the new target
            if is_correction and status == "clear" and analysis.get("primary_domain"):
                # User corrected us, so treat as ambiguous to force confirmation
                logger.info(f"Correction detected: treating 'clear' status as 'ambiguous' to force user confirmation")
                status = "ambiguous"
                # Add the resolved domain as a candidate
                primary_domain = analysis.get("primary_domain").strip().rstrip(".")
                analysis["candidates"] = [{
                    "name": entity_name or primary_domain.split(".")[0],
                    "domain": primary_domain,
                    "location": user_context or "Unknown",
                    "desc": f"Found based on your clarification: {user_context or 'no additional context'}"
                }]
                analysis["clarification_question"] = f"Did you mean **{primary_domain}**? I found this based on your clarification: '{user_context or 'no additional context'}'. Please confirm."
            
            if status == "clear" and analysis.get("primary_domain"):
                real_domain = analysis.get("primary_domain").strip().rstrip(".")  # Remove trailing dot
                
                # Validate domain - must be a proper domain, not just TLD
                # Check: must have at least 2 parts (domain.tld), not start with dot, and have valid length
                domain_parts = real_domain.split(".")
                is_valid = (
                    real_domain and 
                    not real_domain.startswith(".") and 
                    len(domain_parts) >= 2 and
                    all(len(part) > 0 for part in domain_parts) and
                    len(real_domain) > 4  # Minimum: a.co
                )
                
                if not is_valid:
                    logger.warning(f"Invalid domain format: '{real_domain}', treating as ambiguous")
                    # Treat as ambiguous and ask user
                    return {
                        "response": f"Invalid domain format detected: '{real_domain}'. Could you provide the correct domain name?",
                        "context": context,
                        "next_action": "end"
                    }
                else:
                    logger.success(f"Resolved '{entity_name}' -> '{real_domain}'")
                    
                    # Clear target verification pending flag since we resolved the target
                    context.pop("target_verification_pending", None)
                    context.pop("pending_entity_name", None)
                    
                    # Build detailed response with company information using UI components
                    try:
                        from app.ui import format_target_info, format_company_info
                        from app.ui.console import get_console
                        
                        console = get_console()
                        
                        # Display target info with company details
                        if company_info:
                            format_target_info(real_domain, company_info, console)
                            # Store company info in context for later use
                            context["company_info"] = company_info
                        else:
                            format_target_info(real_domain, None, console)
                        
                        # Build text response for confirmation
                        response_parts = [f"Did you mean **{real_domain}**? I found this as the likely domain for '{entity_name}'."]
                        response_parts.append(f"\n\nType 'yes' to proceed with **{real_domain}**, or type the correct domain.")
                        
                        return {
                            "response": "\n".join(response_parts),
                            "suggested_tools": [],
                            "context": {**context, "target_domain": real_domain},
                            "next_action": "end"
                        }
                    except ImportError:
                        # Fallback if UI module not available
                        response_parts = [f"Did you mean **{real_domain}**? I found this as the likely domain for '{entity_name}'."]
                        
                        if company_info:
                            response_parts.append("\n## 📋 Information about the target:\n")
                            if company_info.get("name") and company_info.get("name") != "N/A":
                                response_parts.append(f"**Company/Organization:** {company_info.get('name')}")
                            if company_info.get("location") and company_info.get("location") != "N/A":
                                response_parts.append(f"**Location:** {company_info.get('location')}")
                            if company_info.get("industry") and company_info.get("industry") != "N/A":
                                response_parts.append(f"**Industry:** {company_info.get('industry')}")
                            if company_info.get("description") and company_info.get("description") != "N/A":
                                response_parts.append(f"**Description:** {company_info.get('description')}")
                            if company_info.get("additional_info") and company_info.get("additional_info") != "N/A":
                                response_parts.append(f"**Additional Info:** {company_info.get('additional_info')}")
                            context["company_info"] = company_info
                        
                        response_parts.append(f"\n\nType 'yes' to proceed with **{real_domain}**, or type the correct domain.")
                        
                        return {
                            "response": "\n".join(response_parts),
                            "suggested_tools": [],
                            "context": {**context, "target_domain": real_domain},
                            "next_action": "end"
                        }
                
            elif status == "ambiguous":
                logger.info(f"Ambiguous target '{entity_name}'. Asking user...")
                question = analysis.get("clarification_question", f"I found multiple entities for '{entity_name}'. Could you specify?")
                
                candidates_str = ""
                for c in analysis.get("candidates", [])[:3]:
                    loc = c.get('location', 'Global')
                    if isinstance(loc, list):
                        loc = ", ".join(loc[:2])
                    desc = c.get('desc', 'N/A')
                    domain = c.get('domain', 'N/A')
                    name = c.get('name', 'N/A')
                    
                    # Build detailed candidate info
                    candidate_info = f"**{name}**\n"
                    candidate_info += f"  - Domain: {domain}\n"
                    candidate_info += f"  - Location: {loc}\n"
                    if desc and desc != "N/A":
                        candidate_info += f"  - Description: {desc}\n"
                    candidates_str += f"{candidate_info}\n"
                
                # Set flag to indicate we're awaiting target clarification
                # This prevents AutoChain from starting before target is verified
                context["target_verification_pending"] = True
                context["pending_entity_name"] = entity_name
                
                return {
                    "response": f"{question}\n\n## 🔍 Potential matches found:\n\n{candidates_str}\n\nPlease specify which one you mean, or provide the domain directly.",
                    "context": context,
                    "next_action": "end"
                }
            else:
                return proceed_to_planner()
                
        except Exception as e:
            logger.error(f"Verification error: {e}")
            return proceed_to_planner()
