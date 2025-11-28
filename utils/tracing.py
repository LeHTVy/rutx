"""
Phoenix Tracing Integration for SNODE AI
Provides OpenTelemetry-based observability for agent interactions
Works with LOCAL OLLAMA LLM (no OpenAI dependencies)
"""

import os
import warnings
from typing import Optional

# Suppress SQLAlchemy warnings from Phoenix
warnings.filterwarnings("ignore", category=Warning, module="sqlalchemy")
warnings.filterwarnings("ignore", message=".*SAWarning.*")

try:
    import phoenix as px
    from phoenix.otel import register
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    PHOENIX_AVAILABLE = True
except ImportError:
    PHOENIX_AVAILABLE = False
    print("⚠️  Phoenix not installed. Tracing will be disabled.")
    print("   Install with: pip install arize-phoenix opentelemetry-api opentelemetry-sdk")


class TracingManager:
    """Manages Phoenix tracing and OpenTelemetry instrumentation for LOCAL Ollama"""
    
    def __init__(self, project_name: str = "snode-wireless-pentest"):
        self.project_name = project_name
        self.session: Optional = None
        self.tracer_provider: Optional[TracerProvider] = None
        self.enabled = False
    
    def start(self, host: str = "127.0.0.1", port: int = 6006) -> bool:
        """
        Start Phoenix tracing server
        
        Args:
            host: Phoenix server host
            port: Phoenix server port
        
        Returns:
            bool: True if successfully started
        """
        if not PHOENIX_AVAILABLE:
            return False
        
        try:
            # Set env vars to avoid deprecation warnings
            os.environ["PHOENIX_HOST"] = host
            os.environ["PHOENIX_PORT"] = str(port)
            
            print(f"🔍 Starting Phoenix tracing...")
            
            # Suppress ALL warnings and Phoenix verbose output
            import sys
            from io import StringIO
            
            # Capture stdout/stderr during Phoenix startup
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = StringIO()
            sys.stderr = StringIO()
            
            try:
                # Launch Phoenix server (using env vars) - ALL OUTPUT SUPPRESSED
                self.session = px.launch_app()
                
                # Register OpenTelemetry - ALL OUTPUT SUPPRESSED
                self.tracer_provider = register(
                    project_name=self.project_name,
                    endpoint=f"http://{host}:{port}/v1/traces",
                    set_global_tracer_provider=True
                )
            finally:
                # Restore stdout/stderr
                sys.stdout = old_stdout
                sys.stderr = old_stderr
            
            # NOTE: We do NOT instrument OpenAI since we use Ollama
            # Ollama calls will be traced manually via custom spans
            
            self.enabled = True
            print(f"   ✅ Dashboard: http://{host}:{port}")
            
            return True
            
        except Exception as e:
            print(f"⚠️  Phoenix tracing failed: {e}")
            print("   Continuing without tracing...")
            return False
    
    def stop(self):
        """Stop Phoenix tracing"""
        if self.session:
            try:
                print("🛑 Tracing session ended")
                self.enabled = False
            except Exception as e:
                print(f"⚠️  Error stopping tracing: {e}")
    
    def create_span(self, name: str, attributes: dict = None):
        """
        Create a custom trace span
        
        Args:
            name: Span name
            attributes: Optional span attributes
        
        Returns:
            Span context manager
        """
        if not self.enabled or not PHOENIX_AVAILABLE:
            # Return a no-op context manager
            from contextlib import contextmanager
            @contextmanager
            def noop():
                yield
            return noop()
        
        tracer = trace.get_tracer(__name__)
        return tracer.start_as_current_span(name, attributes=attributes or {})
    
    def add_event(self, name: str, attributes: dict = None):
        """Add an event to the current span"""
        if not self.enabled or not PHOENIX_AVAILABLE:
            return
        
        span = trace.get_current_span()
        if span:
            span.add_event(name, attributes=attributes or {})
    
    def set_attribute(self, key: str, value):
        """Set an attribute on the current span"""
        if not self.enabled or not PHOENIX_AVAILABLE:
            return
        
        span = trace.get_current_span()
        if span:
            span.set_attribute(key, value)


# Global tracing manager instance
_tracing_manager: Optional[TracingManager] = None


def setup_tracing(project_name: str = "snode-wireless-pentest", 
                  host: str = "127.0.0.1", 
                  port: int = 6006) -> Optional[TracingManager]:
    """
    Initialize global tracing manager
    
    Args:
        project_name: Project name for traces
        host: Phoenix server host
        port: Phoenix server port
    
    Returns:
        TracingManager instance or None if Phoenix not available
    """
    global _tracing_manager
    
    if _tracing_manager is None:
        _tracing_manager = TracingManager(project_name)
        _tracing_manager.start(host, port)
    
    return _tracing_manager


def get_tracing_manager() -> Optional[TracingManager]:
    """Get the global tracing manager"""
    return _tracing_manager


def trace_tool_execution(tool_name: str):
    """
    Decorator to trace tool execution
    
    Usage:
        @trace_tool_execution("nmap_scan")
        def nmap_quick_scan(target):
            ...
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            manager = get_tracing_manager()
            if manager and manager.enabled:
                with manager.create_span(
                    f"tool.{tool_name}",
                    attributes={
                        "tool.name": tool_name,
                        "tool.args": str(args),
                        "tool.kwargs": str(kwargs)
                    }
                ):
                    result = func(*args, **kwargs)
                    manager.set_attribute("tool.success", result.get("success", False))
                    return result
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator


def trace_agent_interaction(agent_name: str, phase: str):
    """
    Decorator to trace agent interactions
    
    Usage:
        @trace_agent_interaction("snode_agent", "phase_1")
        def phase_1_tool_selection(prompt):
            ...
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            manager = get_tracing_manager()
            if manager and manager.enabled:
                with manager.create_span(
                    f"agent.{agent_name}.{phase}",
                    attributes={
                        "agent.name": agent_name,
                        "agent.phase": phase
                    }
                ):
                    result = func(*args, **kwargs)
                    return result
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator


def trace_ollama_call(model: str, prompt: str):
    """
    Manually trace Ollama LLM call
    
    Usage:
        with trace_ollama_call(model="llama3.2", prompt="Scan this target"):
            response = ollama.chat(...)
    """
    manager = get_tracing_manager()
    if manager and manager.enabled:
        return manager.create_span(
            "llm.ollama",
            attributes={
                "llm.model": model,
                "llm.prompt_length": len(prompt),
                "llm.provider": "ollama"
            }
        )
    else:
        from contextlib import contextmanager
        @contextmanager
        def noop():
            yield
        return noop()


if __name__ == "__main__":
    # Test tracing setup
    if PHOENIX_AVAILABLE:
        manager = setup_tracing()
        
        # Test custom span
        with manager.create_span("test.operation"):
            manager.add_event("test.started")
            manager.set_attribute("test.value", 42)
            print("Test span created")
        
        # Test Ollama call tracing
        with trace_ollama_call("llama3.2", "Test prompt"):
            print("Ollama call traced")
        
        print("\nOpen http://127.0.0.1:6006 to view traces")
    else:
        print("Phoenix not available - install dependencies first")
