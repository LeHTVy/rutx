"""
Question Tool

Extracts and encapsulates logic from question_node().
Answers questions using LLM knowledge + scan context + web research.
"""
from typing import Dict, Any, Optional
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient


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
        
        # Check if this is a customer query
        customer_keywords = [
            "khách hàng", "customer", "client", "khách hàng của tôi",
            "trong số khách hàng", "customers", "clients",
            "ai đang sử dụng", "who is using", "which customer"
        ]
        query_lower = query.lower()
        is_customer_query = any(kw in query_lower for kw in customer_keywords)
        
        if is_customer_query:
            try:
                from app.agent.tools.customer_query_tool import CustomerQueryTool
                customer_tool = CustomerQueryTool(self.state)
                return customer_tool.execute(query=query, context=context)
            except Exception as e:
                # Fall through to regular question handling
                pass
        
        llm = OllamaClient()
        
        # Check if user wants to see scan results
        query_lower = query.lower()
        if any(phrase in query_lower for phrase in ["show nmap", "nmap results", "scan results", "port scan results", "show scan"]):
            # Try to get scan results from context or RAG
            scan_results = []
            tools_run = context.get("tools_run", [])
            if "nmap" in tools_run:
                # Get results from context
                results = context.get("tool_results", {})
                if results.get("nmap"):
                    scan_results.append(f"nmap results: {results['nmap'].get('output', 'No output available')[:2000]}")
            
            # Also try to get from RAG
            domain = context.get("last_domain") or context.get("target_domain")
            if domain:
                try:
                    from app.rag.unified_memory import get_unified_rag
                    rag = get_unified_rag()
                    # Query for scan results
                    scan_docs = rag.query_collection("findings", f"nmap scan results for {domain}", limit=5)
                    if scan_docs:
                        scan_results.append(f"Historical scan results from RAG: {len(scan_docs)} documents found")
                except Exception:
                    pass
            
            if scan_results:
                context_str = f"""Target: {context.get('last_domain', 'Not set')}
Technologies: {context.get('detected_tech', [])}
Scan Results Available: Yes
{chr(10).join(scan_results)}"""
            else:
                context_str = f"""Target: {context.get('last_domain', 'Not set')}
Technologies: {context.get('detected_tech', [])}
Scan Results: No scan results found. Run nmap first."""
        else:
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
                    logger.info(f"Searched web for: {query[:50]}...")
            except Exception:
                pass
        
        from app.agent.prompt_loader import format_prompt
        prompt = format_prompt("general_chat", query=query, context_str=context_str, web_context=web_context)
        
        # Stream with show_content=True to see thinking process
        response = llm.generate(prompt, timeout=90, stream=True, show_thinking=True, show_content=True)
        
        return {
            "response": response or "Please rephrase.",
            "next_action": "end",
            "response_streamed": True  # Flag to indicate response was already streamed
        }
