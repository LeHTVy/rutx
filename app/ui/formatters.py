"""
UI Formatters - High-level Formatting Functions
===============================================

Convenience functions for formatting different types of data.
"""

from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.table import Table
from rich.columns import Columns
from rich.panel import Panel
from rich.markdown import Markdown
from .console import get_console
from .components import (
    TargetInfoCard,
    CompanyInfoCard,
    FindingCard,
    ToolResultCard,
    AnalysisCard,
    ProgressIndicator,
)
from .themes import get_theme


def format_target_info(domain: str, company_info: Dict[str, Any] = None, console: Console = None) -> None:
    """Format and display target information."""
    console = console or get_console()
    card = TargetInfoCard(console)
    console.print(card.render(domain, company_info))


def format_company_info(company_info: Dict[str, Any], console: Console = None) -> None:
    """Format and display company information."""
    console = console or get_console()
    card = CompanyInfoCard(console)
    console.print(card.render(company_info))


def format_findings(findings: List[Dict[str, Any]], finding_type: str = "Finding", console: Console = None) -> None:
    """Format and display findings."""
    console = console or get_console()
    theme = get_theme()
    
    if not findings:
        console.print(f"[dim]No {finding_type.lower()}s found[/]")
        return
    
    # Group by severity if applicable
    if any("severity" in f for f in findings):
        table = Table(title=f"{theme.icons.get('vulnerability', '🛡️')} {finding_type}s", show_header=True, header_style="bold")
        table.add_column("Severity", style="bold")
        table.add_column("Issue", style="bold")
        table.add_column("Target")
        table.add_column("Details")
        
        for finding in findings:
            severity = finding.get("severity", "Unknown")
            color = theme.severity_colors.get(severity.lower(), "white")
            table.add_row(
                f"[{color}]{severity}[/]",
                finding.get("issue", "N/A"),
                finding.get("target", "N/A"),
                finding.get("details", "N/A")[:100]
            )
        console.print(table)
    else:
        # Simple list
        console.print(f"\n[bold {theme.primary}]{theme.icons.get('info', 'ℹ️')} {finding_type}s ({len(findings)}):[/]")
        for finding in findings[:20]:
            console.print(f"  • {finding}")
        if len(findings) > 20:
            console.print(f"  [dim]... and {len(findings) - 20} more[/]")


def format_tool_results(results: Dict[str, Any], console: Console = None) -> None:
    """Format and display tool execution results."""
    console = console or get_console()
    
    for tool_name, result in results.items():
        if isinstance(result, dict):
            success = result.get("success", True)
            output = result.get("output", "")
            metadata = result.get("metadata", {})
        else:
            success = True
            output = str(result)
            metadata = {}
        
        card = ToolResultCard(console)
        console.print(card.render(tool_name, output, success, metadata))


def format_analysis(analysis: Dict[str, Any], console: Console = None) -> None:
    """Format and display analysis results."""
    console = console or get_console()
    card = AnalysisCard(console)
    console.print(card.render(analysis))


def format_progress(current: int, total: int, label: str = "Progress", console: Console = None) -> None:
    """Format and display progress indicator."""
    console = console or get_console()
    indicator = ProgressIndicator(console)
    console.print(indicator.render(current, total, label))
