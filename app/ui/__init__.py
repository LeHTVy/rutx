"""
UI Module - Beautiful Interface Components
==========================================

Centralized UI components for SNODE.
Provides consistent, beautiful formatting for all output.
"""

from .console import get_console, ConsoleManager
from .components import (
    TargetInfoCard,
    FindingCard,
    ToolResultCard,
    AnalysisCard,
    ProgressIndicator,
    StatusBadge,
    CompanyInfoCard,
)
from .formatters import (
    format_target_info,
    format_findings,
    format_tool_results,
    format_analysis,
    format_company_info,
)
from .themes import Theme, get_theme, set_theme
from .autochain import AutoChainProgress, IterationCard
from .logger import UILogger, get_logger
from .gemini_style import GeminiStyleUI, get_gemini_ui

__all__ = [
    # Console
    "get_console",
    "ConsoleManager",
    
    # Components
    "TargetInfoCard",
    "FindingCard",
    "ToolResultCard",
    "AnalysisCard",
    "ProgressIndicator",
    "StatusBadge",
    "CompanyInfoCard",
    
    # Formatters
    "format_target_info",
    "format_findings",
    "format_tool_results",
    "format_analysis",
    "format_company_info",
    
    # Themes
    "Theme",
    "get_theme",
    "set_theme",
    
    # AutoChain
    "AutoChainProgress",
    "IterationCard",
    
    # Logger
    "UILogger",
    "get_logger",
    
    # Gemini Style
    "GeminiStyleUI",
    "get_gemini_ui",
]
