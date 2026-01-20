"""Intent classifier for distinguishing questions from requests.

Extracted from graph.py for modularity (firestarter pattern).
"""

import json
from typing import Dict, Any, Optional
from pathlib import Path

from app.llm.client import OllamaClient, get_current_model


class IntentClassifier:
    """Classifies user intent as question, request, confirmation, or memory query.
    
    This is a modular extraction of the intent classification logic
    from the monolithic graph.py, following the firestarter pattern.
    """
    
    # Intent types
    INTENT_QUESTION = "question"
    INTENT_SECURITY_TASK = "security_task"
    INTENT_MEMORY_QUERY = "memory_query"
    INTENT_CONFIRM = "confirm"
    
    def __init__(self, prompt_path: Optional[Path] = None):
        """Initialize intent classifier.
        
        Args:
            prompt_path: Path to intent classification prompt
        """
        self._client = None
        self.prompt_path = prompt_path or Path(__file__).parent / "prompts" / "intent_classifier.md"
        self._prompt_template = None
    
    @property
    def client(self) -> OllamaClient:
        """Lazy load Ollama client."""
        if self._client is None:
            self._client = OllamaClient()
        return self._client
    
    @property
    def prompt_template(self) -> str:
        """Load prompt template."""
        if self._prompt_template is None:
            if self.prompt_path.exists():
                self._prompt_template = self.prompt_path.read_text()
            else:
                # Default inline prompt
                self._prompt_template = """Classify the user's intent into one of these categories:

- **question**: User is asking for information (how, what, why, explain)
- **security_task**: User wants to perform a security action (scan, enumerate, exploit, recon)
- **memory_query**: User wants to see stored data ("show results", "what did we find")
- **confirm**: User is confirming/denying a previous suggestion ("yes", "no", "do it")

User query: {query}

Respond with ONLY the intent category name (question/security_task/memory_query/confirm):"""
        return self._prompt_template
    
    def classify(self, 
                 query: str,
                 conversation_context: Optional[str] = None) -> Dict[str, Any]:
        """Classify user intent.
        
        Args:
            query: User query to classify
            conversation_context: Optional previous conversation context
            
        Returns:
            Dict with:
            - intent: Intent category
            - confidence: Confidence score (0-1)
            - reasoning: Optional reasoning
        """
        # First try fast rule-based classification
        fast_result = self._fast_classify(query)
        if fast_result["confidence"] >= 0.9:
            return fast_result
        
        # Use LLM for ambiguous cases
        try:
            prompt = self.prompt_template.replace("{query}", query)
            if conversation_context:
                prompt = f"Context:\n{conversation_context}\n\n{prompt}"
            
            response = self.client.generate(prompt, timeout=10)
            intent = self._parse_intent(response)
            
            return {
                "intent": intent,
                "confidence": 0.8,
                "reasoning": f"LLM classified as {intent}",
                "raw_response": response
            }
        except Exception as e:
            # Fall back to rule-based
            return fast_result
    
    def _fast_classify(self, query: str) -> Dict[str, Any]:
        """Fast rule-based classification with fuzzy matching.
        
        Args:
            query: User query
            
        Returns:
            Classification result
        """
        query_lower = query.lower().strip()
        words = query_lower.split()
        first_word = words[0] if words else ""
        
        # Confirmation patterns (high confidence)
        confirm_patterns = [
            "yes", "yeah", "yep", "sure", "ok", "okay", "do it", "proceed",
            "go ahead", "run it", "execute", "confirmed", "approve"
        ]
        deny_patterns = ["no", "nope", "cancel", "stop", "abort", "don't"]
        
        for pattern in confirm_patterns + deny_patterns:
            if pattern in query_lower:
                return {
                    "intent": self.INTENT_CONFIRM,
                    "confidence": 0.95,
                    "reasoning": f"Matched confirmation pattern: {pattern}"
                }
        
        # Memory query patterns
        memory_patterns = [
            "show", "what did we find", "results", "findings", "summary",
            "what ports", "what subdomains", "what vulnerabilities",
            "list", "display"
        ]
        for pattern in memory_patterns:
            if pattern in query_lower:
                return {
                    "intent": self.INTENT_MEMORY_QUERY,
                    "confidence": 0.85,
                    "reasoning": f"Matched memory query pattern: {pattern}"
                }
        
        # Question patterns
        question_starters = ["what", "how", "why", "when", "where", "who", "which", "explain", "describe"]
        if first_word in question_starters:
            return {
                "intent": self.INTENT_QUESTION,
                "confidence": 0.85,
                "reasoning": f"Starts with question word: {first_word}"
            }
        
        # Security task patterns (with typo tolerance)
        security_patterns = [
            "scan", "scna", "skan",  # scan typos
            "enumerate", "enum",
            "exploit", "expoit", "exployt",  # exploit typos
            "recon", "reconnaissance",
            "attack", "attck", "attak",  # attack typos
            "test", "assess", "audit",
            "fuzz", "brute", "crack",
            "find", "discover", "identify"
        ]
        
        for pattern in security_patterns:
            if pattern in query_lower:
                return {
                    "intent": self.INTENT_SECURITY_TASK,
                    "confidence": 0.9,
                    "reasoning": f"Matched security pattern: {pattern}"
                }
        
        # Default to question with lower confidence
        return {
            "intent": self.INTENT_QUESTION,
            "confidence": 0.5,
            "reasoning": "Default classification"
        }
    
    def _parse_intent(self, response: str) -> str:
        """Parse intent from LLM response.
        
        Args:
            response: LLM response text
            
        Returns:
            Intent category
        """
        response_lower = response.lower().strip()
        
        if "security_task" in response_lower or "security task" in response_lower:
            return self.INTENT_SECURITY_TASK
        elif "memory_query" in response_lower or "memory query" in response_lower:
            return self.INTENT_MEMORY_QUERY
        elif "confirm" in response_lower:
            return self.INTENT_CONFIRM
        else:
            return self.INTENT_QUESTION


class StreamCallback:
    """Protocol for streaming callbacks during graph execution.
    
    Nodes can emit events during execution for real-time UI updates.
    """
    
    def __init__(self, callback=None):
        """Initialize with optional callback function.
        
        Args:
            callback: Function(event_type: str, event_name: str, data: Any)
        """
        self._callback = callback
    
    def emit(self, event_type: str, event_name: str, data: Any = None):
        """Emit an event.
        
        Args:
            event_type: Type of event (model_output, tool_output, node_complete, etc.)
            event_name: Name of the event (node name, tool name, etc.)
            data: Event data
        """
        if self._callback:
            try:
                self._callback(event_type, event_name, data)
            except Exception:
                pass  # Don't let callback errors break execution
    
    def model_output(self, node_name: str, chunk: str):
        """Emit model output chunk."""
        self.emit("model_output", node_name, {"chunk": chunk})
    
    def tool_output(self, tool_name: str, command: str, line: str):
        """Emit tool output line."""
        self.emit("tool_output", tool_name, {"command": command, "line": line})
    
    def node_start(self, node_name: str, state: Dict = None):
        """Emit node start event."""
        self.emit("node_start", node_name, {"state": state})
    
    def node_complete(self, node_name: str, result: Dict = None):
        """Emit node completion event."""
        self.emit("node_complete", node_name, {"result": result})


# Singleton instances
_intent_classifier: Optional[IntentClassifier] = None
_stream_callback: Optional[StreamCallback] = None


def get_intent_classifier() -> IntentClassifier:
    """Get or create intent classifier instance."""
    global _intent_classifier
    if _intent_classifier is None:
        _intent_classifier = IntentClassifier()
    return _intent_classifier


def get_stream_callback(callback=None) -> StreamCallback:
    """Get or create stream callback instance."""
    global _stream_callback
    if _stream_callback is None or callback is not None:
        _stream_callback = StreamCallback(callback)
    return _stream_callback
