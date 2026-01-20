"""DeepSeek-R1 agent for web search and synthesis."""

import ollama
from typing import Dict, Any, Optional, List, Callable
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from config import load_config


class DeepSeekAgent:
    """DeepSeek-R1 agent for web search orchestration and synthesis."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize DeepSeek-R1 agent."""
        self.config = load_config(config_path) if config_path else self._load_default_config()
        self.model_config = self.config['models']['deepseek_r1']
        self.ollama_base_url = self.config['ollama']['base_url']
        
        template_dir = Path(__file__).parent.parent / "prompts"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.system_prompt_template = self.env.get_template("deepseek_system.jinja2")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default config."""
        import yaml
        config_path = Path(__file__).parent.parent / "config" / "ollama_config.yaml"
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def synthesize_answer(self,
                         user_question: str,
                         search_results: Optional[List[Dict]] = None,
                         search_query: Optional[str] = None,
                         stream_callback: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        """Synthesize answer from search results.
        
        Args:
            user_question: User question
            search_results: Web search results
            search_query: Original search query
            stream_callback: Optional callback for streaming response chunks
            
        Returns:
            Synthesized answer
        """
        system_prompt = self.system_prompt_template.render(
            search_query=search_query,
            search_results=search_results,
            user_question=user_question
        )
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_question}
        ]
        
        try:
            if stream_callback:
                # Streaming mode
                content = ""
                response = ollama.chat(
                    model=self.model_config['model_name'],
                    messages=messages,
                    stream=True,
                    options={
                        "temperature": self.model_config.get('temperature', 0.7),
                        "top_p": self.model_config.get('top_p', 0.9),
                        "top_k": self.model_config.get('top_k', 40),
                        "num_predict": self.model_config.get('num_predict', 4096)
                    }
                )
                
                for chunk in response:
                    chunk_content = chunk.get('message', {}).get('content', '')
                    if chunk_content:
                        content += chunk_content
                        stream_callback(chunk_content)
                
                return {
                    "success": True,
                    "answer": content,
                    "message": {"content": content}
                }
            else:
                # Non-streaming mode
                response = ollama.chat(
                    model=self.model_config['model_name'],
                    messages=messages,
                    options={
                        "temperature": self.model_config.get('temperature', 0.7),
                        "top_p": self.model_config.get('top_p', 0.9),
                        "top_k": self.model_config.get('top_k', 40),
                        "num_predict": self.model_config.get('num_predict', 4096)
                    }
                )
                
                content = response.get('message', {}).get('content', '')
                
                return {
                    "success": True,
                    "answer": content,
                    "message": response.get('message', {})
                }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "answer": None
            }
