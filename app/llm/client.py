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
from typing import Optional, Callable
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
    MAX_TIMEOUT = 300
    
    def __init__(self, model: str = None):
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
        if stream:
            return self._generate_stream_with_spinner(prompt, system, timeout, show_thinking, verbose, show_content)
        else:
            return self._generate_blocking(prompt, system, timeout, verbose)
    
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
    
    def _generate_blocking(self, prompt: str, system: str, timeout: int, verbose: bool = False) -> str:
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
                    if remaining > 0:
                        sys.stdout.write(f"\r  {spinner_chars[i % len(spinner_chars)]} Thinking ({self.model})... [{remaining}s]  ")
                    sys.stdout.flush()
                    time.sleep(0.1)
                    i += 1
            
            spinner_thread = threading.Thread(target=spin, daemon=True)
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
                print(f"\r  ⏱️ Timeout after {timeout}s                    ")
                return ""
            
            stop_spinner.set()
            spinner_thread.join(timeout=0.3)
            
            if result:
                result = re.sub(r'<think>.*?</think>', '', result, flags=re.DOTALL).strip()
                elapsed = int(time.time() - start_time)
                if verbose:
                    print(f"\r  ✅ ({len(result)} chars, {elapsed}s)                    ")
                else:
                    # Just clear spinner line
                    sys.stdout.write(f"\r                                                      \r")
                    sys.stdout.flush()
            
            return result
            
        except Exception as e:
            print(f"\r  ❌ Error: {e}")
            return ""
    
    def __del__(self):
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)
