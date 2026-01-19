"""
UI Logger - Replaces print() statements with UI components
==========================================================

Provides clean logging functions that use UI components instead of raw print().
"""

from typing import Optional
from .console import get_console, ConsoleManager
from .themes import get_theme


class UILogger:
    """Logger that uses UI components for consistent output."""
    
    def __init__(self, console=None):
        self.console = console or get_console()
        self.manager = ConsoleManager(self.console)
        self.theme = get_theme()
    
    def info(self, message: str, icon: str = None):
        """Print info message."""
        if icon is None:
            icon = self.theme.icons.get("info", "")
        self.manager.print_info(f"{icon} {message}" if icon else message)
    
    def success(self, message: str, icon: str = None):
        """Print success message."""
        if icon is None:
            icon = self.theme.icons.get("success", "")
        self.manager.print_success(f"{icon} {message}" if icon else message)
    
    def error(self, message: str, icon: str = None):
        """Print error message."""
        if icon is None:
            icon = self.theme.icons.get("error", "")
        self.manager.print_error(f"{icon} {message}" if icon else message)
    
    def warning(self, message: str, icon: str = None):
        """Print warning message."""
        if icon is None:
            icon = self.theme.icons.get("warning", "")
        self.manager.print_warning(f"{icon} {message}" if icon else message)
    
    def debug(self, message: str):
        """Print debug message (dimmed, only shown in debug mode)."""
        # Only show debug messages if DEBUG env var is set
        import os
        if os.getenv("DEBUG", "").lower() in ("1", "true", "yes"):
            self.console.print(f"[dim]DEBUG: {message}[/]")
    
    def dim(self, message: str):
        """Print dim message."""
        self.console.print(f"[dim]{message}[/]")
    
    def section(self, title: str, content: str = ""):
        """Print section header."""
        self.manager.print_section(title, content)


# Global logger instance
_logger: Optional[UILogger] = None


def get_logger() -> UILogger:
    """Get global UI logger instance."""
    global _logger
    if _logger is None:
        _logger = UILogger()
    return _logger
