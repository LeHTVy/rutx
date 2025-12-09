# SNODE LangChain Package
"""
AI-Powered Security Scanner using LangChain
"""

__version__ = "1.0.0"

# Lazy imports to avoid circular dependencies
def create_agent(model: str = "deepseek-r1:latest", verbose: bool = True):
    """Factory function to create SNODE agent"""
    from .agent import SNODEAgent
    return SNODEAgent(model=model, verbose=verbose)

__all__ = ["create_agent"]
