"""Direct answer agent for answering questions without tools."""

import ollama
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from config import load_config
from models.deepseek_agent import DeepSeekAgent
from models.qwen3_agent import Qwen3Agent


class DirectAnswerAgent:
    """Agent for answering questions directly using available knowledge."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize direct answer agent.
        
        Args:
            config_path: Path to Ollama config file
        """
        self.config = load_config(config_path) if config_path else self._load_default_config()
        self.deepseek = DeepSeekAgent(config_path)
        self.qwen3 = Qwen3Agent(config_path)
        
        template_dir = Path(__file__).parent.parent / "prompts"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.answer_prompt_template = self.env.get_template("direct_answer.jinja2")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default config."""
        import yaml
        config_path = Path(__file__).parent.parent / "config" / "ollama_config.yaml"
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def answer_question(self,
                       question: str,
                       rag_results: Optional[List[Dict[str, Any]]] = None,
                       knowledge_results: Optional[Dict[str, Any]] = None,
                       search_results: Optional[Dict[str, Any]] = None,
                       conversation_history: Optional[List[Dict[str, Any]]] = None,
                       stream_callback: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        """Answer question using available knowledge sources.
        
        Args:
            question: User question
            rag_results: RAG retrieval results (conversation context)
            knowledge_results: Knowledge base results (CVE, exploits, IOC)
            search_results: Web search results
            conversation_history: Previous conversation
            stream_callback: Optional callback for streaming response
            
        Returns:
            Answer result with answer text, sufficiency flag, and tool needs
        """
        # Format context from various sources
        context_parts = []
        
        if rag_results:
            context_parts.append("Conversation Context:")
            for result in rag_results[:3]:  # Top 3 results
                context_parts.append(f"- {result.get('document', '')[:200]}")
        
        if knowledge_results:
            context_parts.append("\nKnowledge Base:")
            for kb_type, results in knowledge_results.items():
                if results:
                    context_parts.append(f"{kb_type.upper()}:")
                    for result in results[:2]:  # Top 2 per type
                        if isinstance(result, dict):
                            context_parts.append(f"- {result.get('response', str(result))[:200]}")
        
        if search_results and search_results.get("success"):
            context_parts.append("\nWeb Search Results:")
            for result in search_results.get("results", [])[:3]:  # Top 3
                title = result.get("title", "")
                snippet = result.get("snippet", "")
                context_parts.append(f"- {title}: {snippet[:200]}")
        
        context = "\n".join(context_parts) if context_parts else "No additional context available."
        
        # Build prompt
        prompt = self.answer_prompt_template.render(
            question=question,
            context=context,
            has_context=bool(context_parts)
        )
        
        # Use DeepSeek for synthesis (better for answering questions)
        answer_result = self.deepseek.synthesize_answer(
            user_question=question,
            search_results={"context": context, "rag": rag_results, "knowledge": knowledge_results},
            stream_callback=stream_callback
        )
        
        if not answer_result.get("success"):
            return {
                "success": False,
                "answer": "",
                "sufficient": False,
                "needs_tools": True,
                "error": answer_result.get("error", "Unknown error")
            }
        
        answer = answer_result.get("answer", "")
        
        # Evaluate if answer is sufficient
        sufficient = self._evaluate_answer_sufficiency(answer, question, context_parts)
        
        # Determine if tools are needed
        needs_tools = not sufficient and not context_parts
        
        return {
            "success": True,
            "answer": answer,
            "sufficient": sufficient,
            "needs_tools": needs_tools,
            "context_used": bool(context_parts),
            "reasoning": "Answer is sufficient" if sufficient else "Answer may need additional information from tools"
        }
    
    def _evaluate_answer_sufficiency(self, answer: str, question: str, context_parts: List[str]) -> bool:
        """Evaluate if answer is sufficient.
        
        Args:
            answer: Generated answer
            question: Original question
            context_parts: Context parts used
            
        Returns:
            True if answer is sufficient, False otherwise
        """
        # Check answer length (too short might be insufficient)
        if len(answer.strip()) < 50:
            return False
        
        # Check for indicators of insufficient answer
        insufficient_indicators = [
            "i don't know",
            "i cannot",
            "i need more",
            "requires additional",
            "not available",
            "unable to",
            "cannot determine",
            "insufficient information"
        ]
        
        answer_lower = answer.lower()
        if any(indicator in answer_lower for indicator in insufficient_indicators):
            return False
        
        # If we have context and a reasonable answer, it's likely sufficient
        if context_parts and len(answer) > 100:
            return True
        
        # Default: if answer exists and is reasonable length, consider sufficient
        return len(answer) > 100
