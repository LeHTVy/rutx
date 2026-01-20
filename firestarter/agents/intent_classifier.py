"""Intent classifier for distinguishing questions from requests."""

import ollama
import json
from typing import Dict, Any, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from config import load_config


class IntentClassifier:
    """Classifies user intent as question or request."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize intent classifier.
        
        Args:
            config_path: Path to Ollama config file
        """
        self.config = load_config(config_path) if config_path else self._load_default_config()
        self.model_config = self.config['models']['qwen3']
        self.ollama_base_url = self.config['ollama']['base_url']
        
        template_dir = Path(__file__).parent.parent / "prompts"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.intent_prompt_template = self.env.get_template("intent_classification.jinja2")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default config."""
        import yaml
        config_path = Path(__file__).parent.parent / "config" / "ollama_config.yaml"
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def classify(self, user_prompt: str) -> Dict[str, Any]:
        """Classify user intent.
        
        Args:
            user_prompt: User prompt to classify
            
        Returns:
            Classification result with intent type, confidence, and reasoning
        """
        prompt = self.intent_prompt_template.render(user_prompt=user_prompt)
        
        messages = [
            {"role": "system", "content": "You are an intent classifier for a pentest agent. Classify user prompts as either 'question' (asking for information) or 'request' (requesting an action like scan, test, assess)."},
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = ollama.chat(
                model=self.model_config['model_name'],
                messages=messages,
                options={
                    "temperature": self.model_config.get('temperature', 0.3),  # Lower temp for classification
                    "top_p": self.model_config.get('top_p', 0.9),
                    "top_k": self.model_config.get('top_k', 40),
                    "num_predict": self.model_config.get('num_predict', 256)  # Shorter for classification
                }
            )
            
            content = response.get('message', {}).get('content', '')
            
            # Try to parse JSON from response
            try:
                # Extract JSON from markdown code blocks if present
                if "```json" in content:
                    json_start = content.find("```json") + 7
                    json_end = content.find("```", json_start)
                    content = content[json_start:json_end].strip()
                elif "```" in content:
                    json_start = content.find("```") + 3
                    json_end = content.find("```", json_start)
                    content = content[json_start:json_end].strip()
                
                classification = json.loads(content)
                
                # Validate and normalize intent
                intent = classification.get("intent", "").lower()
                if intent not in ["question", "request"]:
                    # Default based on keywords if parsing fails
                    intent = self._fallback_classify(user_prompt)
                
                return {
                    "success": True,
                    "intent": intent,
                    "confidence": float(classification.get("confidence", 0.5)),
                    "reasoning": classification.get("reasoning", ""),
                    "raw_response": content
                }
            except json.JSONDecodeError:
                # Fallback classification
                intent = self._fallback_classify(user_prompt)
                return {
                    "success": True,
                    "intent": intent,
                    "confidence": 0.6,
                    "reasoning": "Fallback classification based on keywords",
                    "raw_response": content
                }
                
        except Exception as e:
            # Fallback on error
            intent = self._fallback_classify(user_prompt)
            return {
                "success": False,
                "intent": intent,
                "confidence": 0.5,
                "reasoning": f"Error during classification: {str(e)}",
                "error": str(e)
            }
    
    def _fallback_classify(self, user_prompt: str) -> str:
        """Fallback classification based on keywords with fuzzy matching.
        
        Args:
            user_prompt: User prompt
            
        Returns:
            "question" or "request"
        """
        prompt_lower = user_prompt.lower()
        
        # Request keywords (action verbs) - with common typos
        request_keywords = [
            "scan", "test", "assess", "check", "run", "execute", "perform",
            "enumerate", "exploit", "attack", "attacj", "attak", "atack",  # Common typos
            "penetrate", "audit", "audit", "hack", "crack", "breach",
            "recon", "reconnaissance", "enum", "fuzz", "fuzzing"
        ]
        
        # Question keywords
        question_keywords = [
            "what", "how", "why", "when", "where", "who", "which",
            "explain", "describe", "tell me", "can you explain",
            "what is", "how does", "how to", "what are", "what are the"
        ]
        
        # Check for question patterns
        if any(keyword in prompt_lower for keyword in question_keywords):
            return "question"
        
        # Check for request patterns (with fuzzy matching for typos)
        for keyword in request_keywords:
            if keyword in prompt_lower:
                return "request"
        
        # Also check if prompt looks like a command (starts with action verb)
        words = prompt_lower.split()
        if words:
            first_word = words[0]
            # Common action verbs that indicate request
            action_verbs = ["scan", "test", "check", "run", "execute", "attack", 
                          "attacj", "attak", "atack", "exploit", "audit", "hack"]
            if first_word in action_verbs:
                return "request"
        
        # Default to question if ambiguous
        return "question"
