"""
SNODE AI - Interactive LLM Configuration System
Allows users to choose and configure their LLM provider at startup
Supports: Ollama (local), OpenAI, Anthropic Claude, Google Gemini, and more
"""

import os
import json
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class LLMConfig:
    """Manages LLM configuration with auto-detection and interactive setup"""

    CONFIG_FILE = Path(__file__).parent / "data" / "llm_config.json"

    PROVIDERS = {
        "ollama": {
            "name": "Ollama (Local)",
            "endpoint": "http://localhost:11434/api/chat",
            "list_endpoint": "http://localhost:11434/api/tags",
            "requires_api_key": False,
            "default_model": "llama3.2:latest",
            "description": "Run LLMs locally on your machine (FREE, PRIVATE)"
        },
        "openai": {
            "name": "OpenAI",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "requires_api_key": True,
            "default_model": "gpt-4",
            "description": "OpenAI GPT models (PAID, requires API key)"
        },
        "anthropic": {
            "name": "Anthropic Claude",
            "endpoint": "https://api.anthropic.com/v1/messages",
            "requires_api_key": True,
            "default_model": "claude-3-5-sonnet-20241022",
            "description": "Anthropic Claude models (PAID, requires API key)"
        },
        "google": {
            "name": "Google Gemini",
            "endpoint": "https://generativelanguage.googleapis.com/v1/models",
            "requires_api_key": True,
            "default_model": "gemini-pro",
            "description": "Google Gemini models (FREE tier available)"
        },
        "groq": {
            "name": "Groq",
            "endpoint": "https://api.groq.com/openai/v1/chat/completions",
            "requires_api_key": True,
            "default_model": "llama3-70b-8192",
            "description": "Ultra-fast LLM inference (FREE tier available)"
        }
    }

    def __init__(self):
        self.config_file = self.CONFIG_FILE
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load existing configuration or return empty dict"""
        from utils.config_loader import ConfigLoader
        return ConfigLoader.load_json(str(self.config_file), defaults={})

    def _save_config(self, config: Dict) -> None:
        """Save configuration to disk"""
        from utils.config_loader import ConfigLoader
        try:
            ConfigLoader.save_json(str(self.config_file), config, atomic=True)
        except Exception as e:
            print(f"Error saving config: {e}")

    def detect_available_providers(self) -> List[str]:
        """Auto-detect which LLM providers are available"""
        available = []

        # Check Ollama (local)
        try:
            response = requests.get(
                "http://localhost:11434/api/tags",
                timeout=2
            )
            if response.status_code == 200:
                available.append("ollama")
        except:
            pass

        # Check for API keys in environment variables
        if os.getenv("OPENAI_API_KEY"):
            available.append("openai")

        if os.getenv("ANTHROPIC_API_KEY"):
            available.append("anthropic")

        if os.getenv("GOOGLE_API_KEY"):
            available.append("google")

        if os.getenv("GROQ_API_KEY"):
            available.append("groq")

        return available

    def detect_ollama_models(self) -> List[str]:
        """Detect available Ollama models on local system"""
        try:
            response = requests.get(
                "http://localhost:11434/api/tags",
                timeout=3
            )
            if response.status_code == 200:
                data = response.json()
                models = [model["name"] for model in data.get("models", [])]
                return models
        except Exception as e:
            print(f"  ⚠️  Failed to detect Ollama models: {e}")
            return []

    def interactive_setup(self) -> Dict:
        """Interactive setup wizard for LLM configuration"""
        print("\n" + "="*60)
        print("🤖 SNODE AI - LLM Configuration Setup")
        print("="*60)

        # Auto-detect available providers
        print("\n🔍 Detecting available LLM providers...")
        available = self.detect_available_providers()

        if available:
            print(f"✅ Found {len(available)} available provider(s):")
            for provider in available:
                print(f"   • {self.PROVIDERS[provider]['name']}")
        else:
            print("⚠️  No providers auto-detected. You can still configure manually.")

        # Show all providers
        print("\n📋 Available LLM Providers:")
        providers_list = list(self.PROVIDERS.keys())
        for i, provider_id in enumerate(providers_list, 1):
            provider = self.PROVIDERS[provider_id]
            status = "✅ AVAILABLE" if provider_id in available else "⚠️  Not detected"
            print(f"   {i}. {provider['name']} - {provider['description']}")
            print(f"      Status: {status}")

        # Get user choice
        print("\n" + "-"*60)
        while True:
            try:
                choice = input(f"Choose provider (1-{len(providers_list)}) [default: 1 for Ollama]: ").strip()
                if not choice:
                    choice = "1"
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(providers_list):
                    break
                print(f"❌ Invalid choice. Please enter 1-{len(providers_list)}")
            except ValueError:
                print(f"❌ Invalid input. Please enter a number 1-{len(providers_list)}")

        provider_id = providers_list[choice_idx]
        provider = self.PROVIDERS[provider_id]

        print(f"\n✅ Selected: {provider['name']}")

        config = {
            "provider": provider_id,
            "endpoint": provider["endpoint"]
        }

        # Handle Ollama model selection
        if provider_id == "ollama":
            print("\n🔍 Detecting Ollama models...")
            models = self.detect_ollama_models()

            if models:
                print(f"\n✅ Found {len(models)} Ollama model(s):")
                for i, model in enumerate(models, 1):
                    print(f"   {i}. {model}")

                while True:
                    try:
                        model_choice = input(f"\nChoose model (1-{len(models)}) [default: 1]: ").strip()
                        if not model_choice:
                            model_choice = "1"
                        model_idx = int(model_choice) - 1
                        if 0 <= model_idx < len(models):
                            config["model"] = models[model_idx]
                            break
                        print(f"❌ Invalid choice. Please enter 1-{len(models)}")
                    except ValueError:
                        print(f"❌ Invalid input. Please enter a number 1-{len(models)}")
            else:
                print("\n⚠️  No Ollama models detected. Using default: llama3.2:latest")
                print("   You may need to run: ollama pull llama3.2")
                config["model"] = "llama3.2:latest"

                custom_model = input("\nEnter custom model name (or press Enter to use default): ").strip()
                if custom_model:
                    config["model"] = custom_model

        else:
            # For cloud providers, ask for model name
            default_model = provider["default_model"]
            model_name = input(f"\nEnter model name [default: {default_model}]: ").strip()
            config["model"] = model_name if model_name else default_model

        # Handle API key if required
        if provider.get("requires_api_key"):
            env_var_name = f"{provider_id.upper()}_API_KEY"
            existing_key = os.getenv(env_var_name)

            if existing_key:
                print(f"\n✅ API key found in environment variable: {env_var_name}")
                use_existing = input("Use existing API key? (Y/n): ").strip().lower()
                if use_existing != 'n':
                    config["api_key_env"] = env_var_name
                else:
                    api_key = input(f"Enter {provider['name']} API key: ").strip()
                    if api_key:
                        config["api_key"] = api_key
            else:
                print(f"\n⚠️  {provider['name']} requires an API key")
                api_key = input(f"Enter API key (or press Enter to set {env_var_name} later): ").strip()
                if api_key:
                    config["api_key"] = api_key
                else:
                    print(f"   Remember to set environment variable: export {env_var_name}=your_key")
                    config["api_key_env"] = env_var_name

        # Additional settings
        print("\n⚙️  Additional Settings:")
        timeout = input("LLM timeout in seconds [default: 1800]: ").strip()
        config["timeout"] = int(timeout) if timeout.isdigit() else 1800

        # Save configuration
        self._save_config(config)

        print("\n" + "="*60)
        print("✅ LLM Configuration Saved!")
        print("="*60)
        print(f"   Provider: {provider['name']}")
        print(f"   Model: {config['model']}")
        print(f"   Endpoint: {config['endpoint']}")
        print(f"   Config file: {self.config_file}")
        print("="*60 + "\n")

        return config

    def get_config(self) -> Dict:
        """Get current configuration (run interactive setup if not configured)"""
        if not self.config or "provider" not in self.config:
            print("\n⚠️  LLM not configured. Running setup wizard...")
            return self.interactive_setup()
        return self.config

    def reconfigure(self) -> Dict:
        """Force reconfiguration"""
        return self.interactive_setup()

    def get_api_key(self, config: Dict) -> Optional[str]:
        """Get API key from config or environment"""
        if "api_key" in config:
            return config["api_key"]
        elif "api_key_env" in config:
            return os.getenv(config["api_key_env"])
        return None


def load_llm_config() -> Dict:
    """Load LLM configuration (convenience function)"""
    llm_config = LLMConfig()
    return llm_config.get_config()


def setup_llm_config() -> Dict:
    """Run interactive LLM setup (convenience function)"""
    llm_config = LLMConfig()
    return llm_config.interactive_setup()


if __name__ == "__main__":
    # Test the configuration system
    config = setup_llm_config()
    print("\n✅ Configuration test successful!")
    print(f"Provider: {config['provider']}")
    print(f"Model: {config['model']}")
