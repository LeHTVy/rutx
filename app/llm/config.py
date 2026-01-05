"""
LLM Configuration Manager for SNODE AI
Handles model selection and configuration
"""
import os
import json
from pathlib import Path


class LLMConfig:
    """Manages LLM model configuration for SNODE"""
    
    CONFIG_FILE = Path(__file__).parent / "config.json"
    
    DEFAULT_CONFIG = {
        "provider": "ollama",
        "model": "mistral:latest",  # Supports native tool calling
        "temperature": 0,
        "endpoint": "http://localhost:11434"
    }
    
    def __init__(self):
        self.config = self.load_config()
    
    def load_config(self) -> dict:
        """Load configuration from file or return defaults"""
        if self.CONFIG_FILE.exists():
            try:
                with open(self.CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return self.DEFAULT_CONFIG.copy()
    
    def save_config(self, config: dict):
        """Save configuration to file"""
        with open(self.CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        self.config = config
    
    def get_config(self) -> dict:
        """Get current configuration"""
        return self.config
    
    def get_model(self) -> str:
        """Get current model name"""
        return self.config.get("model", self.DEFAULT_CONFIG["model"])
    
    def set_model(self, model: str):
        """Set model name"""
        self.config["model"] = model
        self.save_config(self.config)
    
    def detect_ollama_models(self) -> list:
        """Detect available Ollama models"""
        import requests
        try:
            response = requests.get(f"{self.config.get('endpoint', 'http://localhost:11434')}/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return [m.get('name', '') for m in data.get('models', [])]
        except:
            pass
        return []
    
    def interactive_setup(self) -> dict:
        """Interactive model selection"""
        print("\n🔧 LLM Configuration")
        print("=" * 40)
        
        models = self.detect_ollama_models()
        
        if models:
            print("\nAvailable Ollama models:")
            for i, model in enumerate(models, 1):
                marker = "▶" if model == self.get_model() else " "
                print(f"  {marker} [{i}] {model}")
            
            print(f"\n  [0] Enter custom model name")
            
            try:
                choice = input("\nSelect model (number): ").strip()
                if choice == "0":
                    model = input("Enter model name: ").strip()
                elif choice.isdigit() and 1 <= int(choice) <= len(models):
                    model = models[int(choice) - 1]
                else:
                    print("Invalid choice, keeping current model.")
                    return self.config
                
                self.set_model(model)
                print(f"\n✓ Model set to: {model}")
            except:
                print("Cancelled.")
        else:
            print("\n⚠️  No Ollama models found.")
            print("Run: ollama pull <model-name>")
        
        return self.config


# Singleton instance
_config_instance = None

def get_llm_config() -> LLMConfig:
    """Get singleton LLM config instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = LLMConfig()
    return _config_instance
