"""Nemotron-3-Nano agent for embedding generation."""

import ollama
from typing import Dict, Any, List, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from config import load_config


class NemotronAgent:
    """Nemotron-3-Nano agent for embedding generation."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize Nemotron agent."""
        self.config = load_config(config_path) if config_path else self._load_default_config()
        self.model_config = self.config['models']['nemotron_3_nano']
        self.ollama_base_url = self.config['ollama']['base_url']
        
        template_dir = Path(__file__).parent.parent / "prompts"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.system_prompt_template = self.env.get_template("nemotron_system.jinja2")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default config."""
        import yaml
        config_path = Path(__file__).parent.parent / "config" / "ollama_config.yaml"
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def generate_embeddings(self, texts: List[str]) -> Dict[str, Any]:
        """Generate embeddings for texts.
        
        Args:
            texts: List of texts to embed
            
        Returns:
            Embeddings dictionary
        """
        try:
            # Use Ollama embeddings API
            # Note: Nemotron-3-Nano might need a different approach
            # This is a placeholder - actual implementation depends on Ollama's embedding support
            
            embeddings = []
            # Use model name from config, fallback to nomic-embed-text
            model_name = self.model_config.get('model_name', 'nomic-embed-text')
            for text in texts:
                try:
                    result = ollama.embeddings(
                        model=model_name,
                        prompt=text
                    )
                    embeddings.append(result.get('embedding', []))
                except Exception:
                    # Fallback to nomic-embed-text if model doesn't support embeddings
                    result = ollama.embeddings(
                        model="nomic-embed-text",
                        prompt=text
                    )
                    embeddings.append(result.get('embedding', []))
            
            return {
                "success": True,
                "embeddings": embeddings,
                "model": self.model_config.get('model_name', "nemotron-3-nano:30b")
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "embeddings": None
            }
    
    def embed_text(self, text: str) -> Dict[str, Any]:
        """Embed single text.
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding result
        """
        result = self.generate_embeddings([text])
        if result.get('success') and result.get('embeddings'):
            return {
                "success": True,
                "embedding": result['embeddings'][0],
                "model": result.get('model')
            }
        return result
