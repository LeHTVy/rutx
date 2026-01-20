"""Streaming manager for coordinating live updates.

Adapted from firestarter for SNODE's more natural response flow.
"""

from typing import Dict, Optional, Callable, Any
from rich.console import Console, Group as RichGroup
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel

from app.ui.panels import ToolExecutionPanel, ModelResponsePanel, ProgressPanel


class StreamingManager:
    """Manages streaming events and panel updates.
    
    This provides a coordinated UI for:
    - Model response streaming (character by character)
    - Tool output streaming (line by line)
    - Progress tracking
    
    The result is a more "alive" feeling compared to batch output.
    """
    
    def __init__(self, console: Optional[Console] = None):
        """Initialize streaming manager.
        
        Args:
            console: Rich console instance. Creates new if None.
        """
        self.console = console or Console()
        self.tool_panels: Dict[str, ToolExecutionPanel] = {}
        self.model_panels: Dict[str, ModelResponsePanel] = {}
        self.progress_panel = ProgressPanel()
        self.live: Optional[Live] = None
        self.layout: Optional[Layout] = None
    
    def start(self):
        """Start live display."""
        self.layout = Layout()
        # Give models section more space for long responses
        self.layout.split_column(
            Layout(name="progress", size=5),
            Layout(name="tools", ratio=1),
            Layout(name="models", ratio=3)
        )
        
        self.live = Live(self.layout, console=self.console, refresh_per_second=10)
        self.live.start()
        self._update_display()
    
    def stop(self):
        """Stop live display."""
        if self.live:
            self.live.stop()
            self.live = None
    
    def create_tool_panel(self, 
                         tool_name: str, 
                         command_name: Optional[str] = None,
                         target: Optional[str] = None) -> str:
        """Create a tool execution panel.
        
        Args:
            tool_name: Tool name
            command_name: Optional command name
            target: Optional target
            
        Returns:
            Panel ID
        """
        panel_id = f"{tool_name}:{command_name}" if command_name else tool_name
        self.tool_panels[panel_id] = ToolExecutionPanel(
            tool_name=tool_name,
            command_name=command_name,
            target=target
        )
        self._update_display()
        return panel_id
    
    def update_tool_output(self, panel_id: str, line: str):
        """Update tool output with a new line.
        
        Args:
            panel_id: Panel ID
            line: Output line
        """
        if panel_id in self.tool_panels:
            self.tool_panels[panel_id].add_output(line)
            self._update_display()
    
    def update_tool_status(self, panel_id: str, status: str):
        """Update tool status.
        
        Args:
            panel_id: Panel ID
            status: Status message
        """
        if panel_id in self.tool_panels:
            self.tool_panels[panel_id].update_status(status)
            self._update_display()
    
    def complete_tool_panel(self, panel_id: str, success: bool = True):
        """Mark tool panel as complete.
        
        Args:
            panel_id: Panel ID
            success: Whether execution was successful
        """
        if panel_id in self.tool_panels:
            status = "✓ Completed" if success else "✗ Failed"
            self.tool_panels[panel_id].update_status(status)
            self._update_display()
    
    def create_model_panel(self, model_name: str) -> str:
        """Create a model response panel.
        
        Args:
            model_name: Model name
            
        Returns:
            Panel ID
        """
        panel_id = model_name
        if panel_id not in self.model_panels:
            self.model_panels[panel_id] = ModelResponsePanel(model_name=model_name)
        self._update_display()
        return panel_id
    
    def stream_model_response(self, panel_id: str, chunk: str):
        """Stream model response chunk.
        
        This is the key method for natural-feeling responses.
        Each chunk is displayed immediately as the model generates it.
        
        Args:
            panel_id: Panel ID
            chunk: Response chunk (can be a single character or word)
        """
        if panel_id in self.model_panels:
            self.model_panels[panel_id].add_chunk(chunk)
            self._update_display()
    
    def update_model_status(self, panel_id: str, status: str):
        """Update model status.
        
        Args:
            panel_id: Panel ID
            status: Status message
        """
        if panel_id in self.model_panels:
            self.model_panels[panel_id].update_status(status)
            self._update_display()
    
    def complete_model_panel(self, panel_id: str):
        """Mark model panel as complete.
        
        Args:
            panel_id: Panel ID
        """
        if panel_id in self.model_panels:
            self.model_panels[panel_id].update_status("✓ Complete")
            self._update_display()
    
    def update_progress(self, step: str):
        """Update progress step.
        
        Args:
            step: Current step name
        """
        self.progress_panel.update_step(step)
        self._update_display()
    
    def complete_progress_step(self, step: str):
        """Mark progress step as complete.
        
        Args:
            step: Step name
        """
        self.progress_panel.complete_step(step)
        self._update_display()
    
    def set_total_steps(self, total: int):
        """Set total number of progress steps.
        
        Args:
            total: Total steps
        """
        self.progress_panel.set_total_steps(total)
        self._update_display()
    
    def _update_display(self):
        """Update the live display."""
        if not self.live or not self.layout:
            return
        
        # Build tools section
        tool_panels_list = [panel.render() for panel in self.tool_panels.values()]
        if tool_panels_list:
            tools_content = RichGroup(*tool_panels_list)
        else:
            tools_content = Panel("[dim]No tools running...[/dim]", title="[cyan]Tools[/cyan]")
        
        # Build models section
        model_panels_list = [panel.render() for panel in self.model_panels.values()]
        if model_panels_list:
            models_content = RichGroup(*model_panels_list)
        else:
            models_content = Panel("[dim]No models active...[/dim]", title="[blue]Models[/blue]")
        
        # Update layout
        self.layout["progress"].update(self.progress_panel.render())
        self.layout["tools"].update(tools_content)
        self.layout["models"].update(models_content)
    
    def clear(self):
        """Clear all panels."""
        self.tool_panels.clear()
        self.model_panels.clear()
        self.progress_panel = ProgressPanel()
        self._update_display()
    
    def get_tool_callback(self, panel_id: str) -> Callable[[str], None]:
        """Get a callback function for tool output streaming.
        
        Args:
            panel_id: Panel ID
            
        Returns:
            Callback function that accepts output lines
        """
        def callback(line: str):
            self.update_tool_output(panel_id, line)
        return callback
    
    def get_model_callback(self, panel_id: str) -> Callable[[str], None]:
        """Get a callback function for model response streaming.
        
        Args:
            panel_id: Panel ID
            
        Returns:
            Callback function that accepts response chunks
        """
        def callback(chunk: str):
            self.stream_model_response(panel_id, chunk)
        return callback


# Singleton instance
_streaming_manager: Optional[StreamingManager] = None


def get_streaming_manager(console: Optional[Console] = None) -> StreamingManager:
    """Get or create streaming manager instance.
    
    Args:
        console: Optional Rich console
        
    Returns:
        StreamingManager instance
    """
    global _streaming_manager
    if _streaming_manager is None:
        _streaming_manager = StreamingManager(console=console)
    return _streaming_manager
