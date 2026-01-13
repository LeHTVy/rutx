"""
AutoChain UI Components
=======================

Specialized UI components for AutoChain mode display.
"""

from typing import Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.box import ROUNDED
from .console import get_console
from .themes import get_theme


class AutoChainProgress:
    """Display AutoChain mode progress."""
    
    def __init__(self, console: Console = None):
        self.console = console or get_console()
        self.theme = get_theme()
    
    def render_header(self, iteration: int, total: int = 5):
        """Render AutoChain header with progress."""
        self.console.print()
        self.console.print("=" * 70)
        self.console.print(f"  🔄 [bold {self.theme.primary}]AutoChain Mode[/] - Iteration {iteration}/{total}")
        self.console.print("=" * 70)
        self.console.print()
    
    def render_iteration_summary(self, iteration: int, summary: str, tools: List[str] = None, failed: List[str] = None):
        """Render iteration summary."""
        self.console.print(f"\n  [bold {self.theme.info}]📊 Iteration {iteration}/5 Summary:[/]")
        self.console.print(f"     {summary}")
        if tools:
            self.console.print(f"     [green]✅ Tools executed:[/] {', '.join(tools)}")
        if failed:
            self.console.print(f"     [red]❌ Failed tools:[/] {', '.join(failed)}")
    
    def render_completion(self):
        """Render completion message."""
        self.console.print()
        self.console.print("=" * 70)
        self.console.print(f"  [bold {self.theme.success}]🎯 AutoChain Mode - All 5 iterations completed![/]")
        self.console.print("=" * 70)
        self.console.print()


class IterationCard:
    """Display a single iteration result."""
    
    def __init__(self, console: Console = None):
        self.console = console or get_console()
        self.theme = get_theme()
    
    def render(self, iteration: int, summary: str, tools: List[str] = None, failed: List[str] = None) -> Panel:
        """Render iteration card."""
        content_parts = [f"[bold]{summary}[/]"]
        
        if tools:
            content_parts.append("")
            content_parts.append(f"[green]✅ Tools:[/] {', '.join(tools)}")
        
        if failed:
            content_parts.append(f"[red]❌ Failed:[/] {', '.join(failed)}")
        
        content = "\n".join(content_parts)
        
        return Panel(
            content,
            title=f"🔄 Iteration {iteration}/5",
            border_style=self.theme.info,
            box=ROUNDED
        )
