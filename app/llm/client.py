"""
SNODE LLM Client
================

Centralized LangChain-Ollama client with STREAMING support.
Shows spinner while waiting for first token, then streams response.
"""
import re
import sys
import threading
import time
from typing import Optional, Callable, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from app.llm import get_llm_config


# Global model setting for switching
_current_model: Optional[str] = None


def get_current_model() -> str:
    """Get current model, defaulting to config."""
    global _current_model
    if _current_model:
        return _current_model
    config = get_llm_config()
    return config.get_model()


def set_current_model(model: str):
    """Set the global model for all LLM calls."""
    global _current_model
    _current_model = model
    print(f"  🔄 Model switched to: {model}")


class OllamaClient:
    """LangChain-Ollama client with STREAMING and waiting spinner."""
    
    DEFAULT_TIMEOUT = 120
    MAX_TIMEOUT = 600  # Increased for deepseek-r1 and other slow models
    
    def __init__(self, model: str = None):
        """
        Initialize OllamaClient.
        
        Args:
            model: Model name to use. If None, uses get_current_model().
                   Can also use special values:
                   - "planner" - uses planner_model from config
                   - "analyzer" - uses analyzer_model from config
        """
        if model == "planner":
            from app.llm.config import get_planner_model
            self.model = get_planner_model()
        elif model == "analyzer":
            from app.llm.config import get_analyzer_model
            self.model = get_analyzer_model()
        elif model == "executor":
            from app.llm.config import get_executor_model
            self.model = get_executor_model()
        elif model == "reasoning":
            from app.llm.config import get_reasoning_model
            self.model = get_reasoning_model()
        else:
            self.model = model or get_current_model()
        self._llm = None
        self._executor = ThreadPoolExecutor(max_workers=2)
    
    def _get_llm(self):
        """Lazy initialization of ChatOllama."""
        if self._llm is None:
            from langchain_ollama import ChatOllama
            self._llm = ChatOllama(
                model=self.model,
                temperature=0.3,
                num_ctx=4096,
            )
        return self._llm
    
    def generate_with_tools(self, prompt: str, tools: List[Dict[str, Any]], 
                           system: str = None, timeout: int = 90) -> Dict[str, Any]:
        """
        Generate response using function calling (for FunctionGemma).
        
        Args:
            prompt: User prompt
            tools: List of tool definitions in OpenAI function calling format
            system: Optional system message
            timeout: Max seconds to wait
            
        Returns:
            Dict with:
                - "content": str - Text response (if any)
                - "tool_calls": List[Dict] - Tool calls to execute
                - "message": str - Full response message
        """
        import requests
        import json
        
        # Check if this is FunctionGemma
        is_functiongemma = "functiongemma" in self.model.lower()
        if not is_functiongemma:
            # Fallback to regular generate
            response_text = self.generate(prompt, system, timeout, stream=False)
            return {
                "content": response_text,
                "tool_calls": [],
                "message": response_text
            }
        
        # Get endpoint
        config = get_llm_config()
        endpoint = config.get_config().get("endpoint", "http://localhost:11434")
        if "/api/" in endpoint:
            endpoint = endpoint.split("/api/")[0]
        
        # Prepare messages
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        # Prepare request
        request_data = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "stream": False
        }
        
        try:
            response = requests.post(
                f"{endpoint}/api/chat",
                json=request_data,
                timeout=timeout
            )
            response.raise_for_status()
            data = response.json()
            
            # Parse response
            message = data.get("message", {})
            content = message.get("content", "")
            tool_calls = message.get("tool_calls", [])
            
            return {
                "content": content,
                "tool_calls": tool_calls,
                "message": message
            }
        except Exception as e:
            # Fallback to regular generate on error
            print(f"  ⚠️ Function calling failed: {e}. Falling back to regular generation.")
            response_text = self.generate(prompt, system, timeout, stream=False)
            return {
                "content": response_text,
                "tool_calls": [],
                "message": response_text
            }
    
    def generate_with_tools(self, prompt: str, tools: List[Dict[str, Any]], 
                           system: str = None, timeout: int = 90) -> Dict[str, Any]:
        """
        Generate response using function calling (for FunctionGemma).
        
        Args:
            prompt: User prompt
            tools: List of tool definitions in OpenAI function calling format
            system: Optional system message
            timeout: Max seconds to wait
            
        Returns:
            Dict with:
                - "content": str - Text response (if any)
                - "tool_calls": List[Dict] - Tool calls to execute
                - "message": str - Full response message
        """
        import requests
        import json
        
        # Check if this is FunctionGemma
        is_functiongemma = "functiongemma" in self.model.lower()
        if not is_functiongemma:
            # Fallback to regular generate
            response_text = self.generate(prompt, system, timeout, stream=False)
            return {
                "content": response_text,
                "tool_calls": [],
                "message": response_text
            }
        
        # Get endpoint
        config = get_llm_config()
        endpoint = config.get_config().get("endpoint", "http://localhost:11434")
        if "/api/" in endpoint:
            endpoint = endpoint.split("/api/")[0]
        
        # Prepare messages
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        # Prepare request
        request_data = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "stream": False
        }
        
        try:
            response = requests.post(
                f"{endpoint}/api/chat",
                json=request_data,
                timeout=timeout
            )
            response.raise_for_status()
            data = response.json()
            
            # Parse response
            message = data.get("message", {})
            content = message.get("content", "")
            tool_calls = message.get("tool_calls", [])
            
            return {
                "content": content,
                "tool_calls": tool_calls,
                "message": message
            }
        except Exception as e:
            # Fallback to regular generate on error
            print(f"  ⚠️ Function calling failed: {e}. Falling back to regular generation.")
            response_text = self.generate(prompt, system, timeout, stream=False)
            return {
                "content": response_text,
                "tool_calls": [],
                "message": response_text
            }
    
    def generate(self, prompt: str, system: str = None, timeout: int = 90, 
                 stream: bool = True, show_thinking: bool = False,
                 verbose: bool = False, show_content: bool = True) -> str:
        """
        Generate response with streaming and spinner while waiting.
        
        Args:
            prompt: The prompt to send
            system: Optional system message
            timeout: Max seconds to wait
            stream: If True, show output in real-time
            show_thinking: If True, display <think> tags live
            verbose: If True, show detailed timing/debug info
            show_content: If True, show streaming content live
        """
        # Auto-adjust timeout for slow models (deepseek-r1, etc.)
        timeout = self._adjust_timeout_for_model(timeout)
        
        if stream:
            return self._generate_stream_with_spinner(prompt, system, timeout, show_thinking, verbose, show_content)
        else:
            return self._generate_blocking(prompt, system, timeout, verbose, show_content)
    
    def _adjust_timeout_for_model(self, timeout: int) -> int:
        """Adjust timeout based on model type. Slow models need more time."""
        # Models that are known to be slow
        slow_models = ["deepseek-r1", "deepseek", "qwen", "yi"]
        
        model_lower = self.model.lower()
        is_slow_model = any(slow in model_lower for slow in slow_models)
        
        if is_slow_model:
            # For slow models, multiply timeout by 2-3x, but cap at MAX_TIMEOUT
            adjusted = min(timeout * 3, self.MAX_TIMEOUT)
            # Minimum 300s for slow models
            return max(adjusted, 300)
        
        return timeout
    
    def _generate_stream_with_spinner(self, prompt: str, system: str, 
                                       timeout: int, show_thinking: bool,
                                       verbose: bool = False, show_content: bool = True) -> str:
        """Stream with spinner while waiting for first token."""
        try:
            llm = self._get_llm()
            
            from langchain_core.messages import HumanMessage, SystemMessage
            messages = []
            if system:
                messages.append(SystemMessage(content=system))
            messages.append(HumanMessage(content=prompt))
            
            result = ""
            thinking_buffer = ""
            in_thinking = False
            start_time = time.time()
            first_token_received = False
            spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            
            # Start spinner in background
            stop_spinner = threading.Event()
            
            def show_spinner():
                i = 0
                while not stop_spinner.is_set():
                    elapsed = int(time.time() - start_time)
                    remaining = timeout - elapsed
                    if remaining > 0:
                        sys.stdout.write(f"\r  {spinner_chars[i % len(spinner_chars)]} Waiting for LLM ({self.model})... [{remaining}s]  ")
                        sys.stdout.flush()
                    i += 1
                    time.sleep(0.1)
            
            spinner_thread = threading.Thread(target=show_spinner, daemon=True)
            spinner_thread.start()
            
            # Stream with timeout per-chunk
            for chunk in llm.stream(messages):
                # Check total timeout
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    stop_spinner.set()
                    print(f"\r  ⏱️ Timeout after {int(elapsed)}s                    ")
                    break
                
                if chunk.content:
                    text = chunk.content
                    result += text
                    
                    # First token - stop spinner and clear line
                    if not first_token_received:
                        first_token_received = True
                        stop_spinner.set()
                        spinner_thread.join(timeout=0.2)
                        elapsed_first = int(time.time() - start_time)
                        if verbose:
                            sys.stdout.write(f"\r  ⚡ First token in {elapsed_first}s                    \n")
                            sys.stdout.flush()
                        else:
                            # Clean up spinner line
                            sys.stdout.write(f"\r                                                      \r")
                            sys.stdout.flush()
                    
                    # Handle <think> tags
                    if "<think>" in text:
                        in_thinking = True
                        if show_thinking:
                            sys.stdout.write("\n  💭 ")
                        continue
                    
                    if "</think>" in text:
                        in_thinking = False
                        if show_thinking and thinking_buffer:
                            pass  # Already showed thinking
                        thinking_buffer = ""
                        sys.stdout.write("\n  💬 ")
                        sys.stdout.flush()
                        continue
                    
                    if in_thinking:
                        thinking_buffer += text
                        if show_thinking:
                            # Show thinking (abbreviated to avoid spam)
                            clean = text.replace('\n', ' ')[:80]
                            sys.stdout.write(clean)
                            sys.stdout.flush()
                    else:
                        # Show response tokens (only if show_content enabled)
                        if show_content:
                            sys.stdout.write(text)
                            sys.stdout.flush()
            
            # Stop spinner if still running
            stop_spinner.set()
            
            elapsed = int(time.time() - start_time)
            
            # Clean result
            clean_result = re.sub(r'<think>.*?</think>', '', result, flags=re.DOTALL).strip()
            
            if clean_result:
                if verbose:
                    print(f"\n  ✅ Done ({len(clean_result)} chars, {elapsed}s)")
            elif not first_token_received:
                print(f"\r  ⚠️ No response after {elapsed}s                    ")
            
            return clean_result
            
        except KeyboardInterrupt:
            print(f"\n  ⛔ Cancelled")
            return ""
        except Exception as e:
            print(f"\n  ❌ Error: {e}")
            return ""
    
    def _generate_blocking(self, prompt: str, system: str, timeout: int, verbose: bool = False, show_content: bool = True) -> str:
        """Non-streaming with spinner (for quick calls)."""
        timeout = min(max(timeout, 10), self.MAX_TIMEOUT)
        
        try:
            spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            stop_spinner = threading.Event()
            start_time = time.time()
            
            def spin():
                i = 0
                while not stop_spinner.is_set():
                    elapsed = int(time.time() - start_time)
                    remaining = timeout - elapsed
                    if remaining > 0 and show_content:  # Only show spinner if show_content is True
                        sys.stdout.write(f"\r  {spinner_chars[i % len(spinner_chars)]} Thinking ({self.model})... [{remaining}s]  ")
                        sys.stdout.flush()
                    time.sleep(0.1)
                    i += 1
            
            spinner_thread = threading.Thread(target=spin, daemon=True)
            if show_content:  # Only start spinner if show_content is True
                spinner_thread.start()
            
            llm = self._get_llm()
            from langchain_core.messages import HumanMessage, SystemMessage
            messages = []
            if system:
                messages.append(SystemMessage(content=system))
            messages.append(HumanMessage(content=prompt))
            
            # Run with real timeout
            def invoke():
                return llm.invoke(messages)
            
            future = self._executor.submit(invoke)
            try:
                response = future.result(timeout=timeout)
                result = response.content if response else ""
            except FuturesTimeoutError:
                stop_spinner.set()
                if show_content:
                    spinner_thread.join(timeout=0.3)
                    sys.stdout.write(f"\r                                                      \r")
                    sys.stdout.flush()
                print(f"  ⏱️ Timeout after {timeout}s")
                return ""
            
            stop_spinner.set()
            if show_content:
                spinner_thread.join(timeout=0.3)
            
            if result:
                result = re.sub(r'<think>.*?</think>', '', result, flags=re.DOTALL).strip()
                elapsed = int(time.time() - start_time)
                if verbose:
                    if show_content:
                        print(f"\r  ✅ ({len(result)} chars, {elapsed}s)                    ")
                    else:
                        pass  # Silent mode
                else:
                    # Just clear spinner line if it was shown
                    if show_content:
                        sys.stdout.write(f"\r                                                      \r")
                        sys.stdout.flush()
            
            return result
            
        except Exception as e:
            stop_spinner.set()
            if show_content:
                spinner_thread.join(timeout=0.3)
                sys.stdout.write(f"\r                                                      \r")
                sys.stdout.flush()
            print(f"  ❌ Error: {e}")
            return ""
    
    def __del__(self):
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)
