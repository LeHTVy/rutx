"""
Gemini CLI Style UI Components
===============================

Clean, minimal UI inspired by Google Gemini CLI.
Features:
- Thinking indicators
- Clean markdown rendering
- Minimal borders
- Smooth animations
"""

from typing import Optional, List
from rich.console import Console
from rich.markdown import Markdown
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.spinner import Spinner
from rich.align import Align
from rich.layout import Layout
from rich.syntax import Syntax
from .console import get_console
from .themes import get_theme


class GeminiStyleUI:
    """
    Gemini CLI style UI components.
    
    Features:
    - Clean, minimal design
    - Thinking indicators
    - Smooth markdown rendering
    - No heavy borders
    """
    
    def __init__(self, console: Console = None):
        self.console = console or get_console()
        self.theme = get_theme()
    
    def render_thinking(self, message: str = "Thinking..."):
        """Render thinking indicator (minimal spinner)."""
        self.console.print(f"[dim]💭 {message}[/]")
    
    def render_response(self, content: str, thinking: bool = False):
        """
        Render response in Gemini style.
        
        Clean markdown with minimal formatting.
        """
        if thinking:
            self.render_thinking()
        
        # Clean markdown rendering
        self.console.print()
        self.console.print(Markdown(content))
        self.console.print()
    
    def render_code_block(self, code: str, language: str = "text"):
        """Render code block with syntax highlighting."""
        syntax = Syntax(code, language, theme="monokai", line_numbers=False)
        self.console.print(syntax)
    
    def render_suggestion(self, title: str, items: List[str]):
        """Render suggestion list (minimal style)."""
        self.console.print(f"\n[bold]{title}[/]")
        for item in items:
            self.console.print(f"  • {item}")
        self.console.print()
    
    def render_info_card(self, title: str, content: str, border_style: str = "dim"):
        """Render info card with minimal border (Gemini style - clean and simple)."""
        from rich.box import SQUARE
        # Use SQUARE box for clean Gemini-style appearance (minimal but visible)
        # Remove title to make it cleaner
        panel = Panel(
            Markdown(content),
            border_style=border_style,
            padding=(0, 1),  # Minimal padding
            box=SQUARE  # Simple square box
        )
        # Print title separately for cleaner look
        self.console.print(f"\n[bold {border_style}]{title}[/]")
        self.console.print(panel)
        self.console.print()  # Add spacing
    
    def render_progress(self, current: int, total: int, label: str = ""):
        """Render minimal progress indicator."""
        percentage = int((current / total) * 100) if total > 0 else 0
        bar = "█" * int(percentage / 2) + "░" * (50 - int(percentage / 2))
        self.console.print(f"[dim]{label}[/] [{self.theme.primary}]{bar}[/] {percentage}%")
    
    def render_streaming_text(self, text: str, prefix: str = ""):
        """Render streaming text (for LLM responses)."""
        if prefix:
            self.console.print(f"[dim]{prefix}[/]", end="")
        self.console.print(text, end="", style="default")


# Global instance
_gemini_ui: Optional[GeminiStyleUI] = None


def get_gemini_ui() -> GeminiStyleUI:
    """Get global GeminiStyleUI instance."""
    global _gemini_ui
    if _gemini_ui is None:
        _gemini_ui = GeminiStyleUI()
    return _gemini_ui
