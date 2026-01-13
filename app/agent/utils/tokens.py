"""
Token Counting Utilities

Simple token estimation for context window management.
"""
import re


def approximate_tokens(text: str) -> int:
    """
    Approximate token count from text.
    
    Uses simple heuristic: ~4 characters per token for English text.
    For more accuracy, could use tiktoken or similar.
    """
    if not text:
        return 0
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text.strip())
    
    # Rough estimate: 4 chars per token
    return len(text) // 4


def get_context_limit() -> int:
    """
    Get context window limit from settings.
    
    Returns:
        Context window size in tokens
    """
    try:
        # Try to get from config
        from app.llm import get_llm_config
        config = get_llm_config()
        
        # Get model context length
        model = config.get_model()
        ctx_length = config.get_context_length(model) if hasattr(config, 'get_context_length') else 8192
        
        # Apply history ratio (80% for history, 20% for system)
        ctx_history = 0.8
        
        return int(ctx_length * ctx_history)
    except Exception:
        # Default fallback
        return 8192  # 80% of 10k context
