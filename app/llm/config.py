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
        "model": "qwen3:8b",  # Default model for general tasks
        "planner_model": None,  # Model for tool selection (FunctionGemma, nemotron-mini)
        "analyzer_model": None,  # Model for analyzing tool outputs (deepseek-r1, qwen3, nemotron-3-nano)
        "executor_model": None,  # Model for code/command generation (qwen2.5-coder, codellama, starcoder2)
        "reasoning_model": None,  # Model for complex reasoning tasks (deepseek-r1, qwen3, llama3)
        "temperature": 0,
        "endpoint": "http://localhost:11434"
    }
    
    def __init__(self):
        self.config = self.load_config()
        self._auto_detect_model()
        self._auto_detect_models()
    
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
    
    def get_planner_model(self) -> str:
        """Get model for tool selection/planning. Falls back to default model if not set."""
        planner_model = self.config.get("planner_model")
        if planner_model:
            return planner_model
        return self.get_model()
    
    def set_planner_model(self, model: str):
        """Set model for tool selection/planning"""
        self.config["planner_model"] = model
        self.save_config(self.config)
    
    def get_analyzer_model(self) -> str:
        """Get model for analyzing tool outputs. Falls back to default model if not set."""
        analyzer_model = self.config.get("analyzer_model")
        if analyzer_model:
            return analyzer_model
        return self.get_model()
    
    def set_analyzer_model(self, model: str):
        """Set model for analyzing tool outputs"""
        self.config["analyzer_model"] = model
        self.save_config(self.config)
    
    def get_executor_model(self) -> str:
        """Get model for code/command generation. Falls back to default model if not set."""
        executor_model = self.config.get("executor_model")
        if executor_model:
            return executor_model
        return self.get_model()
    
    def set_executor_model(self, model: str):
        """Set model for code/command generation"""
        self.config["executor_model"] = model
        self.save_config(self.config)
    
    def get_reasoning_model(self) -> str:
        """Get model for complex reasoning tasks. Falls back to default model if not set."""
        reasoning_model = self.config.get("reasoning_model")
        if reasoning_model:
            return reasoning_model
        return self.get_model()
    
    def set_reasoning_model(self, model: str):
        """Set model for complex reasoning tasks"""
        self.config["reasoning_model"] = model
        self.save_config(self.config)
    
    def detect_ollama_models(self) -> list:
        """Detect available Ollama models"""
        import requests
        try:
            endpoint = self.config.get('endpoint', 'http://localhost:11434')
            if '/api/' in endpoint:
                endpoint = endpoint.split('/api/')[0]
            response = requests.get(f"{endpoint}/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return [m.get('name', '') for m in data.get('models', [])]
        except:
            pass
        return []
    
    def _auto_detect_model(self):
        """Auto-detect and switch to available model if current model doesn't exist"""
        current_model = self.config.get("model", "")
        available_models = self.detect_ollama_models()
        
        if not available_models:
            return 

        model_exists = False
        for model in available_models:
            if current_model == model or current_model in model or model.startswith(current_model.split(':')[0]):
                model_exists = True
                # Update to exact model name if partial match
                if current_model != model:
                    self.config["model"] = model
                    self.save_config(self.config)
                break
        
        if not model_exists and available_models:
            qwen3_8b = [m for m in available_models if "qwen3:8b" in m.lower() or ("qwen3" in m.lower() and "8b" in m.lower())]
            if qwen3_8b:
                new_model = qwen3_8b[0]
                self.config["model"] = new_model
                self.save_config(self.config)
                print(f"  🔄 Auto-switched default model to qwen3:8b: {new_model}")
            else:
                # Fallback: other lightweight models (fast for simple tasks)
                lightweight_models = [m for m in available_models if any(x in m.lower() for x in [
                    "qwen3", "mistral", "nemotron", "functiongemma", "qwen2.5", "llama3.2", "phi", "gemma"
                ]) and "deepseek-r1" not in m.lower() and "llama3" not in m.lower()]
                
                if lightweight_models:
                    new_model = lightweight_models[0]
                    self.config["model"] = new_model
                    self.save_config(self.config)
                    print(f"  🔄 Auto-switched default model to lightweight: {new_model}")
                else:
                    new_model = available_models[0]
                    if "deepseek-r1" in new_model.lower():
                        print(f"  ⚠️ Warning: Default model is slow ({new_model}). Consider setting qwen3:8b or another lightweight model.")
                    self.config["model"] = new_model
                    self.save_config(self.config)
                    print(f"  🔄 Auto-switched to available model: {new_model}")
    
    def _auto_detect_models(self):
        """Auto-detect and set planner/analyzer models if not configured."""
        available_models = self.detect_ollama_models()
        if not available_models:
            return

        if not self.config.get("planner_model"):
            functiongemma_models = [m for m in available_models if "functiongemma" in m.lower() or "function-gemma" in m.lower()]
            if functiongemma_models:
                self.config["planner_model"] = functiongemma_models[0]
                self.save_config(self.config)
                print(f"  🔄 Auto-detected planner model: {functiongemma_models[0]}")
        
        # Auto-detect nemotron or deepseek for analyzer if available
        if not self.config.get("analyzer_model"):
            analyzer_candidates = []
            for m in available_models:
                m_lower = m.lower()
                if "nemotron" in m_lower or "deepseek" in m_lower or "qwen3" in m_lower:
                    analyzer_candidates.append(m)
            
            if analyzer_candidates:
                # Prefer nemotron-3-nano, then deepseek-r1, then qwen3
                preferred = [m for m in analyzer_candidates if "nemotron" in m.lower()]
                if not preferred:
                    preferred = [m for m in analyzer_candidates if "deepseek" in m.lower()]
                if not preferred:
                    preferred = analyzer_candidates
                
                if preferred:
                    self.config["analyzer_model"] = preferred[0]
                    self.save_config(self.config)
                    print(f"  🔄 Auto-detected analyzer model: {preferred[0]}")
        
        # Auto-detect coder models for executor if available
        if not self.config.get("executor_model"):
            executor_candidates = []
            for m in available_models:
                m_lower = m.lower()
                if "coder" in m_lower or "codellama" in m_lower or "starcoder" in m_lower or "qwen2.5-coder" in m_lower:
                    executor_candidates.append(m)
            
            if executor_candidates:
                # Prefer qwen2.5-coder, then codellama, then starcoder
                preferred = [m for m in executor_candidates if "qwen2.5-coder" in m.lower()]
                if not preferred:
                    preferred = [m for m in executor_candidates if "codellama" in m.lower()]
                if not preferred:
                    preferred = executor_candidates
                
                if preferred:
                    self.config["executor_model"] = preferred[0]
                    self.save_config(self.config)
                    print(f"  🔄 Auto-detected executor model: {preferred[0]}")
        
        # Auto-detect reasoning models if available
        if not self.config.get("reasoning_model"):
            reasoning_candidates = []
            for m in available_models:
                m_lower = m.lower()
                if "deepseek-r1" in m_lower or "qwen3" in m_lower or "llama3" in m_lower:
                    reasoning_candidates.append(m)
            
            if reasoning_candidates:
                # Prefer deepseek-r1, then qwen3, then llama3
                preferred = [m for m in reasoning_candidates if "deepseek-r1" in m.lower()]
                if not preferred:
                    preferred = [m for m in reasoning_candidates if "qwen3" in m.lower()]
                if not preferred:
                    preferred = reasoning_candidates
                
                if preferred:
                    self.config["reasoning_model"] = preferred[0]
                    self.save_config(self.config)
                    print(f"  🔄 Auto-detected reasoning model: {preferred[0]}")
    
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


def get_planner_model() -> str:
    """Get model for tool selection/planning tasks."""
    config = get_llm_config()
    return config.get_planner_model()


def get_analyzer_model() -> str:
    """Get model for analyzing tool outputs."""
    config = get_llm_config()
    return config.get_analyzer_model()


def get_executor_model() -> str:
    """Get model for code/command generation."""
    config = get_llm_config()
    return config.get_executor_model()


def get_reasoning_model() -> str:
    """Get model for complex reasoning tasks."""
    config = get_llm_config()
    return config.get_reasoning_model()
