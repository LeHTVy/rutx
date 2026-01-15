"""
Question Tool - Clean Refactored Version

Answers questions using LLM knowledge + scan context + web research.
Main purpose: Answer user questions with appropriate context and complexity handling.

Focus: Clean code structure with helper functions.
"""
from typing import Dict, Any, Optional, Tuple
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient
from app.ui import get_logger

logger = get_logger()


def _build_base_context(context: Dict[str, Any]) -> str:
    """Build base context string from context."""
    return f"""Target: {context.get('last_domain', 'Not set')}
Technologies: {context.get('detected_tech', [])}
Tools Run: {', '.join(context.get('tools_run', []))}"""


def _get_detector_llm() -> OllamaClient:
    """Get lightweight LLM for detection tasks."""
    from app.llm.config import get_planner_model
    planner_model = get_planner_model()
    if "functiongemma" in planner_model.lower() or "nemotron" in planner_model.lower():
        return OllamaClient(model="planner")
    return OllamaClient()


def _check_simple_identity(query_lower: str) -> bool:
    """Check if query is a simple identity question."""
    simple_identity_questions = [
        "who are you", "what are you", "what is snode", "what can you do",
        "tell me about yourself", "who is snode", "what is this"
    ]
    return any(keyword in query_lower for keyword in simple_identity_questions)


def _detect_customer_query(query: str, base_context: str, detector_llm: OllamaClient) -> bool:
    """Detect if query is a customer query."""
    try:
        from app.agent.prompt_loader import format_prompt
        
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
        return is_customer_query
    except Exception as e:
        logger.warning(f"Customer query detection failed: {e}")
        return False


def _classify_question_complexity(query: str, base_context: str, detector_llm: OllamaClient) -> bool:
    """Classify question complexity (simple vs complex)."""
    try:
        from app.agent.prompt_loader import format_prompt
        
        classification_prompt = format_prompt(
            "question_complexity",
            query=query,
            context_str=base_context
        )
        
        classification_response = detector_llm.generate(
            classification_prompt,
            timeout=10,
            stream=False
        )
        
        response_upper = classification_response.strip().upper()
        is_simple_question = "SIMPLE" in response_upper
        
        logger.debug(f"Question complexity: {'SIMPLE' if is_simple_question else 'COMPLEX'}")
        return is_simple_question
    except Exception as e:
        logger.warning(f"Question complexity classification failed: {e}")
        return False  # Default to complex


def _build_detailed_context(query_lower: str, base_context: str, context: Dict[str, Any]) -> str:
    """Build detailed context string including scan results if needed."""
    # Check if query asks for scan results
    scan_phrases = ["show nmap", "nmap results", "scan results", "port scan results", "show scan"]
    if not any(phrase in query_lower for phrase in scan_phrases):
        return base_context
    
    scan_results = []
    tools_run = context.get("tools_run", [])
    
    # Get nmap results from context
    if "nmap" in tools_run:
        results = context.get("tool_results", {})
        if results.get("nmap"):
            scan_results.append(f"nmap results: {results['nmap'].get('output', 'No output available')[:2000]}")
    
    # Get historical scan results from RAG
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
        return f"""{base_context}
Scan Results Available: Yes
{chr(10).join(scan_results)}"""
    else:
        return f"""{base_context}
Scan Results: No scan results found. Run nmap first."""


def _detect_web_research(query: str, context_str: str, detector_llm: OllamaClient) -> bool:
    """Detect if web research is needed."""
    try:
        from app.agent.prompt_loader import format_prompt
        
        research_detection_prompt = format_prompt(
            "web_research_detector",
            query=query,
            context_str=context_str
        )
        
        research_detection_response = detector_llm.generate(
            research_detection_prompt,
            timeout=8,
            stream=False
        )
        
        response_upper = research_detection_response.strip().upper()
        needs_research = "NEEDS_RESEARCH" in response_upper
        
        logger.debug(f"Web research detection: {'NEEDS_RESEARCH' if needs_research else 'NO_RESEARCH'}")
        return needs_research
    except Exception as e:
        logger.warning(f"Web research detection failed: {e}")
        return False


def _perform_web_research(query: str) -> str:
    """Perform web research and return formatted results."""
    try:
        from app.tools.custom.web_research import search_and_format
        research = search_and_format(query)
        if research:
            logger.info(f"Searched web for: {query[:50]}...")
            return f"\n\nWEB RESEARCH RESULTS:\n{research}"
    except Exception:
        pass
    return ""


def _answer_question(query: str, context_str: str, web_context: str, is_simple: bool) -> Dict[str, Any]:
    """Answer question using LLM."""
    from app.agent.prompt_loader import format_prompt
    from app.llm.client import OllamaClient
    
    llm = OllamaClient()
    prompt = format_prompt("general_chat", query=query, context_str=context_str, web_context=web_context)
    
    if is_simple:
        # Simple questions: fast, no streaming, no thinking
        response = llm.generate(prompt, timeout=30, stream=False)
        return {
            "response": response or "Please rephrase.",
            "next_action": "end",
            "response_streamed": False
        }
    else:
        # Complex questions: stream with thinking
        response = llm.generate(prompt, timeout=60, stream=True, show_thinking=True, show_content=True)
        return {
            "response": "",  # Empty because it was already streamed
            "next_action": "end",
            "response_streamed": True
        }


class QuestionTool(AgentTool):
    """
    Tool for answering general questions.
    
    Main purpose:
    - Answer user questions using LLM knowledge
    - Include scan context when relevant
    - Perform web research if needed
    - Handle simple vs complex questions differently
    - Route customer queries to CustomerQueryTool
    """
    
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
        
        query_lower = query.lower().strip()
        
        # Build base context
        base_context = _build_base_context(context)
        
        # Initialize detector LLM
        detector_llm = _get_detector_llm()
        
        # Fast path: Check simple identity questions
        is_simple_identity = _check_simple_identity(query_lower)
        
        # Detect customer query (skip for simple identity questions)
        if not is_simple_identity:
            is_customer_query = _detect_customer_query(query, base_context, detector_llm)
            
            if is_customer_query:
                try:
                    from app.agent.tools.customer_query_tool import CustomerQueryTool
                    customer_tool = CustomerQueryTool(self.state)
                    return customer_tool.execute(query=query, context=context)
                except Exception as e:
                    logger.warning(f"Customer query tool failed: {e}")
        
        # Classify question complexity
        is_simple_question = _classify_question_complexity(query, base_context, detector_llm)
        
        # Build detailed context (includes scan results if needed)
        context_str = _build_detailed_context(query_lower, base_context, context)
        
        # Detect and perform web research if needed
        web_context = ""
        if _detect_web_research(query, context_str, detector_llm):
            web_context = _perform_web_research(query)
        
        # Answer question
        return _answer_question(query, context_str, web_context, is_simple_question)
