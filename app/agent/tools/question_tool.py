"""
Question Tool

Extracts and encapsulates logic from question_node().
Answers questions using LLM knowledge + scan context + web research.
"""
from typing import Dict, Any, Optional
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient
from app.ui import get_logger

logger = get_logger()


class QuestionTool(AgentTool):
    """Tool for answering general questions."""
    
    def execute(self, query: str = None, context: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """
        Answer using LLM knowledge + scan context + web research.
        
        Args:
            query: User query string
            context: Current context dictionary
            
        Returns:
            Dictionary with answer response
        """
        if query is None and self.state:
            query = self.state.get("query", "")
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        
        # Build base context string
        base_context = f"""Target: {context.get('last_domain', 'Not set')}
Technologies: {context.get('detected_tech', [])}
Tools Run: {', '.join(context.get('tools_run', []))}"""
        
        # FAST PATH: Skip customer query detection for simple identity questions
        # These are clearly NOT customer queries
        simple_identity_questions = [
            "who are you", "what are you", "what is snode", "what can you do",
            "tell me about yourself", "who is snode", "what is this"
        ]
        query_lower = query.lower().strip()
        is_simple_identity = any(keyword in query_lower for keyword in simple_identity_questions)
        
        if is_simple_identity:
            is_customer_query = False
            logger.debug("Fast path: Simple identity question, skipping customer query detection")
        else:
            # Check if this is a customer query using prompt file
            from app.agent.prompt_loader import format_prompt
            from app.llm.config import get_planner_model
            
            # Initialize lightweight LLM for detection
            planner_model = get_planner_model()
            if "functiongemma" in planner_model.lower() or "nemotron" in planner_model.lower():
                detector_llm = OllamaClient(model="planner")
            else:
                detector_llm = OllamaClient()
            
            try:
                customer_detection_prompt = format_prompt(
                    "customer_query_detector",
                    query=query,
                    context_str=base_context
                )
                
                customer_detection_response = detector_llm.generate(
                    customer_detection_prompt,
                    timeout=8,
                    stream=False
                )
                
                response_upper = customer_detection_response.strip().upper()
                is_customer_query = "CUSTOMER_QUERY" in response_upper
                
                logger.debug(f"Customer query detection: {'CUSTOMER_QUERY' if is_customer_query else 'NOT_CUSTOMER_QUERY'}")
                
            except Exception as e:
                logger.warning(f"Customer query detection failed: {e}, defaulting to NOT_CUSTOMER_QUERY")
                is_customer_query = False
        
        if is_customer_query:
            try:
                from app.agent.tools.customer_query_tool import CustomerQueryTool
                customer_tool = CustomerQueryTool(self.state)
                return customer_tool.execute(query=query, context=context)
            except Exception as e:
                logger.warning(f"Customer query tool failed: {e}")
                pass
        
        # Classify question complexity using prompt file
        try:
            classification_prompt = format_prompt(
                "question_complexity",
                query=query,
                context_str=base_context
            )
            
            # Reuse detector_llm for classification
            classification_response = detector_llm.generate(
                classification_prompt,
                timeout=10,
                stream=False
            )
            
            # Parse response
            response_upper = classification_response.strip().upper()
            is_simple_question = "SIMPLE" in response_upper
            
            logger.debug(f"Question complexity: {'SIMPLE' if is_simple_question else 'COMPLEX'}")
            
        except Exception as e:
            # Fallback: assume complex if classification fails
            logger.warning(f"Question complexity classification failed: {e}, defaulting to COMPLEX")
            is_simple_question = False
        
        # Initialize LLM for answering
        llm = OllamaClient()
        
        # Build detailed context string for answering (includes scan results if available)
        query_lower = query.lower()
        if any(phrase in query_lower for phrase in ["show nmap", "nmap results", "scan results", "port scan results", "show scan"]):
            scan_results = []
            tools_run = context.get("tools_run", [])
            if "nmap" in tools_run:
                # Get results from context
                results = context.get("tool_results", {})
                if results.get("nmap"):
                    scan_results.append(f"nmap results: {results['nmap'].get('output', 'No output available')[:2000]}")
            
            domain = context.get("last_domain") or context.get("target_domain")
            if domain:
                try:
                    from app.rag.unified_memory import get_unified_rag
                    rag = get_unified_rag()
                    scan_docs = rag.query_collection("findings", f"nmap scan results for {domain}", limit=5)
                    if scan_docs:
                        scan_results.append(f"Historical scan results from RAG: {len(scan_docs)} documents found")
                except Exception:
                    pass
            
            if scan_results:
                context_str = f"""{base_context}
Scan Results Available: Yes
{chr(10).join(scan_results)}"""
            else:
                context_str = f"""{base_context}
Scan Results: No scan results found. Run nmap first."""
        else:
            context_str = base_context
        
        # Detect if web research is needed using prompt file
        web_context = ""
        try:
            research_detection_prompt = format_prompt(
                "web_research_detector",
                query=query,
                context_str=context_str
            )
            
            # Use lightweight model for quick detection
            research_detection_response = detector_llm.generate(
                research_detection_prompt,
                timeout=8,
                stream=False
            )
            
            response_upper = research_detection_response.strip().upper()
            needs_research = "NEEDS_RESEARCH" in response_upper
            
            logger.debug(f"Web research detection: {'NEEDS_RESEARCH' if needs_research else 'NO_RESEARCH'}")
            
        except Exception as e:
            logger.warning(f"Web research detection failed: {e}, defaulting to NO_RESEARCH")
            needs_research = False
        
        if needs_research:
            try:
                from app.tools.custom.web_research import search_and_format
                research = search_and_format(query)
                if research:
                    web_context = f"\n\nWEB RESEARCH RESULTS:\n{research}"
                    logger.info(f"Searched web for: {query[:50]}...")
            except Exception:
                pass
        
        from app.agent.prompt_loader import format_prompt
        prompt = format_prompt("general_chat", query=query, context_str=context_str, web_context=web_context)
        

        if is_simple_question:
            # Simple questions: fast, no streaming, no thinking
            response = llm.generate(prompt, timeout=30, stream=False)
            return {
                "response": response or "Please rephrase.",
                "next_action": "end",
                "response_streamed": False 
            }
        else:
            # Complex questions: stream with thinking, but mark as streamed
            response = llm.generate(prompt, timeout=60, stream=True, show_thinking=True, show_content=True)
            # When streaming, response is already printed, so return empty to avoid duplicate
            return {
                "response": "",  # Empty because it was already streamed
                "next_action": "end",
                "response_streamed": True  # Flag to indicate response was already streamed
            }
