"""
User Prompt Analyzer
====================

Analyzes user prompt using General Model to:
1. Extract requirements and intent
2. Extract target with misspell/typo handling
3. Create checklist from analyzed prompt
"""
import re
from typing import Dict, Any, Optional
from app.llm.client import OllamaClient
from app.llm.config import get_general_model
from app.agent.analyzer.checklist_manager import get_checklist_manager, Task
from app.agent.analyzer.task_breakdown_tool import TaskBreakdownTool
from app.ui import get_logger

logger = get_logger()


class UserPromptAnalyzer:
    """
    Analyzes user prompt with General Model.
    
    Flow:
    1. Analyze prompt → extract requirements
    2. Extract target (with typo handling)
    3. Create checklist from analyzed prompt
    """
    
    def __init__(self):
        self._llm = None
        self._task_breakdown = None
    
    @property
    def llm(self):
        """Lazy-load General Model LLM."""
        if self._llm is None:
            general_model = get_general_model()
            if general_model:
                self._llm = OllamaClient(model="general")
            else:
                self._llm = OllamaClient()
        return self._llm
    
    @property
    def task_breakdown(self):
        """Lazy-load TaskBreakdownTool."""
        if self._task_breakdown is None:
            self._task_breakdown = TaskBreakdownTool(state=None)
        return self._task_breakdown
    
    def analyze_prompt(self, query: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze user prompt with General Model.
        
        Args:
            query: User query string
            context: Current context dictionary
            
        Returns:
            Dictionary with:
                - requirements: Extracted requirements
                - intent: User intent
                - target: Extracted target (if any)
                - needs_checklist: Whether checklist should be created
        """
        if context is None:
            context = {}
        
        # Use General Model to analyze prompt
        prompt = f"""Analyze this user prompt for security testing:

USER PROMPT: {query}

CONTEXT: {self._build_context_summary(context)}

Extract and return JSON:
{{
    "requirements": ["requirement1", "requirement2"],
    "intent": "intent description",
    "target_hint": "target if mentioned",
    "needs_checklist": true/false,
    "complexity": "simple" or "complex"
}}

Return ONLY the JSON object."""
        
        try:
            response = self.llm.generate(prompt, timeout=30, stream=False)
            
            # Parse JSON response
            import json
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group(), strict=False)
                return {
                    "requirements": analysis.get("requirements", []),
                    "intent": analysis.get("intent", ""),
                    "target_hint": analysis.get("target_hint", ""),
                    "needs_checklist": analysis.get("needs_checklist", True),
                    "complexity": analysis.get("complexity", "simple")
                }
        except Exception as e:
            logger.warning(f"Prompt analysis failed: {e}")
        
        # Fallback
        return {
            "requirements": [query],
            "intent": "security_testing",
            "target_hint": "",
            "needs_checklist": True,
            "complexity": "simple"
        }
    
    def extract_target(self, query: str, context: Dict[str, Any] = None) -> Optional[str]:
        """
        Extract target from query with misspell/typo handling.
        
        Reuses logic from target_verification_tool.
        """
        # Try regex first (fast path)
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        domain_match = re.search(domain_pattern, query)
        if domain_match:
            return domain_match.group()
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, query)
        if ip_match:
            return ip_match.group()
        
        # Use LLM for entity extraction (handles typos)
        try:
            from app.agent.prompt_loader import format_prompt
            
            extraction_prompt = format_prompt(
                "target_extraction",
                query=query,
                conversation_context=context.get("conversation_context", "None") if context else "None"
            )
            
            response = self.llm.generate(extraction_prompt, timeout=20, stream=False, show_content=False).strip()
            
            # Parse extraction JSON
            import json
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                extraction = json.loads(json_match.group(), strict=False)
                resolved_domain = extraction.get("resolved_domain", "")
                if resolved_domain and "." in resolved_domain:
                    return resolved_domain
                
                entity_name = extraction.get("entity_name", "").strip()
                if entity_name:
                    # Return entity name for further verification
                    return entity_name
        except Exception as e:
            logger.warning(f"Target extraction failed: {e}")
        
        return None
    
    def create_checklist(self, query: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Create checklist from analyzed prompt.
        
        Reuses TaskBreakdownTool.
        """
        if context is None:
            context = {}
        
        # Use TaskBreakdownTool to create checklist
        result = self.task_breakdown.execute(query=query, context=context)
        
        return {
            "checklist": result.get("checklist", []),
            "context": result.get("context", context)
        }
    
    def _build_context_summary(self, context: Dict[str, Any]) -> str:
        """Build context summary for prompt."""
        parts = []
        
        if context.get("target_domain") or context.get("last_domain"):
            target = context.get("target_domain") or context.get("last_domain")
            parts.append(f"Target: {target}")
        
        if context.get("tools_run"):
            parts.append(f"Tools already run: {', '.join(context.get('tools_run', []))}")
        
        if context.get("subdomain_count"):
            parts.append(f"Subdomains found: {context.get('subdomain_count')}")
        
        if context.get("has_ports"):
            parts.append("Port scan completed")
        
        return "\n".join(parts) if parts else "No prior context"


# Singleton instance
_user_prompt_analyzer: Optional[UserPromptAnalyzer] = None


def get_user_prompt_analyzer() -> UserPromptAnalyzer:
    """Get singleton UserPromptAnalyzer instance."""
    global _user_prompt_analyzer
    if _user_prompt_analyzer is None:
        _user_prompt_analyzer = UserPromptAnalyzer()
    return _user_prompt_analyzer
