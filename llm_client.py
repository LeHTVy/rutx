"""
SNODE AI - Unified LLM Client
Provides a single interface for multiple LLM providers
Supports: Ollama, OpenAI, Anthropic, Google Gemini, Groq
"""

import requests
import json
from typing import Dict, List, Optional
from llm_config import LLMConfig


class LLMClient:
    """Unified client for multiple LLM providers"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize LLM client with configuration

        Args:
            config: LLM configuration dict (if None, loads from llm_config.json)
        """
        if config is None:
            llm_config = LLMConfig()
            config = llm_config.get_config()

        self.provider = config.get("provider", "ollama")
        self.model = config.get("model", "llama3.2:latest")
        self.endpoint = config.get("endpoint", "http://localhost:11434/api/chat")
        self.timeout = config.get("timeout", 1800)

        # Get API key if required
        self.api_key = None
        if config.get("api_key"):
            self.api_key = config["api_key"]
        elif config.get("api_key_env"):
            import os
            self.api_key = os.getenv(config["api_key_env"])

    def chat(self, messages: List[Dict], timeout: Optional[int] = None) -> Dict:
        """
        Send chat request to LLM (unified interface for all providers)

        Args:
            messages: List of message dicts with 'role' and 'content'
                     Example: [{"role": "user", "content": "Hello"}]
            timeout: Optional timeout override

        Returns:
            Response dict with 'message' containing 'content'
        """
        timeout = timeout or self.timeout

        if self.provider == "ollama":
            return self._call_ollama(messages, timeout)
        elif self.provider == "openai":
            return self._call_openai(messages, timeout)
        elif self.provider == "anthropic":
            return self._call_anthropic(messages, timeout)
        elif self.provider == "google":
            return self._call_google(messages, timeout)
        elif self.provider == "groq":
            return self._call_groq(messages, timeout)
        else:
            return {"error": f"Unsupported provider: {self.provider}"}

    def _call_ollama(self, messages: List[Dict], timeout: int) -> Dict:
        """Call Ollama local LLM"""
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False
            }

            response = requests.post(
                self.endpoint,
                json=payload,
                timeout=timeout
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "error": f"Ollama request failed with status {response.status_code}",
                    "details": response.text
                }

        except requests.exceptions.Timeout:
            return {"error": f"Ollama request timed out after {timeout} seconds"}
        except requests.exceptions.ConnectionError:
            return {
                "error": "Cannot connect to Ollama. Is it running?",
                "hint": "Start Ollama with: ollama serve"
            }
        except Exception as e:
            return {"error": f"Ollama request failed: {str(e)}"}

    def _call_openai(self, messages: List[Dict], timeout: int) -> Dict:
        """Call OpenAI API"""
        if not self.api_key:
            return {"error": "OpenAI API key not configured"}

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": self.model,
                "messages": messages
            }

            response = requests.post(
                self.endpoint,
                headers=headers,
                json=payload,
                timeout=timeout
            )

            if response.status_code == 200:
                data = response.json()
                # Convert OpenAI format to Ollama-like format
                return {
                    "message": {
                        "role": "assistant",
                        "content": data["choices"][0]["message"]["content"]
                    }
                }
            else:
                return {
                    "error": f"OpenAI request failed with status {response.status_code}",
                    "details": response.text
                }

        except Exception as e:
            return {"error": f"OpenAI request failed: {str(e)}"}

    def _call_anthropic(self, messages: List[Dict], timeout: int) -> Dict:
        """Call Anthropic Claude API"""
        if not self.api_key:
            return {"error": "Anthropic API key not configured"}

        try:
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }

            # Extract system message if present
            system_message = None
            anthropic_messages = []
            for msg in messages:
                if msg["role"] == "system":
                    system_message = msg["content"]
                else:
                    anthropic_messages.append(msg)

            payload = {
                "model": self.model,
                "messages": anthropic_messages,
                "max_tokens": 4096
            }

            if system_message:
                payload["system"] = system_message

            response = requests.post(
                self.endpoint,
                headers=headers,
                json=payload,
                timeout=timeout
            )

            if response.status_code == 200:
                data = response.json()
                # Convert Anthropic format to Ollama-like format
                return {
                    "message": {
                        "role": "assistant",
                        "content": data["content"][0]["text"]
                    }
                }
            else:
                return {
                    "error": f"Anthropic request failed with status {response.status_code}",
                    "details": response.text
                }

        except Exception as e:
            return {"error": f"Anthropic request failed: {str(e)}"}

    def _call_google(self, messages: List[Dict], timeout: int) -> Dict:
        """Call Google Gemini API"""
        if not self.api_key:
            return {"error": "Google API key not configured"}

        try:
            # Google Gemini uses a different format
            endpoint = f"https://generativelanguage.googleapis.com/v1/models/{self.model}:generateContent?key={self.api_key}"

            # Convert messages to Google format
            contents = []
            for msg in messages:
                role = "user" if msg["role"] in ["user", "system"] else "model"
                contents.append({
                    "role": role,
                    "parts": [{"text": msg["content"]}]
                })

            payload = {
                "contents": contents
            }

            response = requests.post(
                endpoint,
                json=payload,
                timeout=timeout
            )

            if response.status_code == 200:
                data = response.json()
                # Convert Google format to Ollama-like format
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return {
                    "message": {
                        "role": "assistant",
                        "content": text
                    }
                }
            else:
                return {
                    "error": f"Google request failed with status {response.status_code}",
                    "details": response.text
                }

        except Exception as e:
            return {"error": f"Google request failed: {str(e)}"}

    def _call_groq(self, messages: List[Dict], timeout: int) -> Dict:
        """Call Groq API (OpenAI-compatible)"""
        if not self.api_key:
            return {"error": "Groq API key not configured"}

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": self.model,
                "messages": messages
            }

            response = requests.post(
                self.endpoint,
                headers=headers,
                json=payload,
                timeout=timeout
            )

            if response.status_code == 200:
                data = response.json()
                # Convert Groq format to Ollama-like format
                return {
                    "message": {
                        "role": "assistant",
                        "content": data["choices"][0]["message"]["content"]
                    }
                }
            else:
                return {
                    "error": f"Groq request failed with status {response.status_code}",
                    "details": response.text
                }

        except Exception as e:
            return {"error": f"Groq request failed: {str(e)}"}

    def get_provider_info(self) -> Dict:
        """Get information about current LLM configuration"""
        return {
            "provider": self.provider,
            "model": self.model,
            "endpoint": self.endpoint,
            "has_api_key": self.api_key is not None,
            "timeout": self.timeout
        }


# Convenience function to get a client instance
def get_llm_client(config: Optional[Dict] = None) -> LLMClient:
    """Get an LLM client instance"""
    return LLMClient(config)


if __name__ == "__main__":
    # Test the client
    client = get_llm_client()
    print(f"✅ LLM Client initialized")
    print(f"   Provider: {client.provider}")
    print(f"   Model: {client.model}")

    # Test chat
    print("\n🧪 Testing chat...")
    response = client.chat([
        {"role": "user", "content": "Say hello in one sentence"}
    ])

    if "error" in response:
        print(f"❌ Error: {response['error']}")
    else:
        print(f"✅ Response: {response['message']['content']}")
