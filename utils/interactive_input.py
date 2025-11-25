"""
Interactive Input Handler with Command History
Provides readline-like functionality with arrow key navigation and command history
"""

import os
import sys
import pickle
from pathlib import Path
from typing import List, Optional


class HistoryManager:
    """Manage command history with persistence"""

    def __init__(self, history_file: str = ".snode_history", max_history: int = 1000):
        """
        Initialize history manager

        Args:
            history_file: Path to history file (relative to home directory)
            max_history: Maximum number of commands to store
        """
        self.history_file = Path.home() / history_file
        self.max_history = max_history
        self.history: List[str] = []
        self.load_history()

    def load_history(self):
        """Load command history from file"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'rb') as f:
                    self.history = pickle.load(f)
                    # Ensure we don't exceed max history
                    if len(self.history) > self.max_history:
                        self.history = self.history[-self.max_history:]
            except Exception as e:
                print(f"Warning: Could not load history: {e}")
                self.history = []

    def save_history(self):
        """Save command history to file"""
        try:
            # Ensure we don't exceed max history before saving
            if len(self.history) > self.max_history:
                self.history = self.history[-self.max_history:]

            with open(self.history_file, 'wb') as f:
                pickle.dump(self.history, f)
        except Exception as e:
            print(f"Warning: Could not save history: {e}")

    def add(self, command: str):
        """Add command to history"""
        if command and command.strip():
            # Don't add duplicate consecutive commands
            if not self.history or self.history[-1] != command:
                self.history.append(command)
                # Trim if exceeds max
                if len(self.history) > self.max_history:
                    self.history.pop(0)
                self.save_history()

    def get(self, index: int) -> Optional[str]:
        """Get command at index (0 = oldest, -1 = newest)"""
        try:
            return self.history[index]
        except IndexError:
            return None

    def get_all(self) -> List[str]:
        """Get all history"""
        return self.history.copy()

    def clear(self):
        """Clear all history"""
        self.history = []
        if self.history_file.exists():
            self.history_file.unlink()

    def __len__(self):
        return len(self.history)


class InteractiveInput:
    """
    Interactive input handler with readline-like features
    Supports arrow keys for history navigation and line editing
    """

    def __init__(self, prompt: str = "> ", history_manager: Optional[HistoryManager] = None):
        """
        Initialize interactive input

        Args:
            prompt: Input prompt string
            history_manager: Optional history manager (creates default if None)
        """
        self.prompt = prompt
        self.history_manager = history_manager or HistoryManager()
        self.history_position = len(self.history_manager)
        self.current_line = ""
        self.cursor_position = 0

        # Check if readline is available (Unix-like systems)
        self.use_readline = self._setup_readline()

    def _setup_readline(self) -> bool:
        """Setup readline if available"""
        try:
            import readline

            # Set up completion and history
            readline.parse_and_bind('tab: complete')
            readline.parse_and_bind('set editing-mode emacs')

            # Load history into readline
            for cmd in self.history_manager.get_all():
                readline.add_history(cmd)

            return True
        except ImportError:
            # readline not available (Windows or limited environment)
            return False

    def input(self, prompt: Optional[str] = None) -> str:
        """
        Get input with history support

        Args:
            prompt: Optional prompt override

        Returns:
            User input string
        """
        display_prompt = prompt or self.prompt

        if self.use_readline:
            # Use readline for full featured input
            try:
                line = input(display_prompt)
                if line and line.strip():
                    self.history_manager.add(line)
                return line
            except EOFError:
                return ""
            except KeyboardInterrupt:
                print()
                raise
        else:
            # Fallback to basic input for systems without readline
            # (Windows or limited environments)
            return self._basic_input(display_prompt)

    def _basic_input(self, prompt: str) -> str:
        """
        Basic input fallback for systems without readline
        Still better than raw input() with some enhancements
        """
        try:
            # Check if we can use msvcrt for Windows arrow key support
            if sys.platform == 'win32':
                return self._windows_input(prompt)
            else:
                # Simple fallback
                line = input(prompt)
                if line and line.strip():
                    self.history_manager.add(line)
                return line
        except EOFError:
            return ""
        except KeyboardInterrupt:
            print()
            raise

    def _windows_input(self, prompt: str) -> str:
        """
        Windows-specific input with arrow key support using msvcrt
        """
        try:
            import msvcrt
        except ImportError:
            # If msvcrt not available, fall back to basic input
            line = input(prompt)
            if line and line.strip():
                self.history_manager.add(line)
            return line

        sys.stdout.write(prompt)
        sys.stdout.flush()

        buffer = []
        cursor_pos = 0
        history_pos = len(self.history_manager)
        temp_buffer = ""

        while True:
            char = msvcrt.getwch()

            # Enter key
            if char in ('\r', '\n'):
                sys.stdout.write('\n')
                sys.stdout.flush()
                line = ''.join(buffer)
                if line and line.strip():
                    self.history_manager.add(line)
                return line

            # Backspace
            elif char == '\b':
                if cursor_pos > 0:
                    buffer.pop(cursor_pos - 1)
                    cursor_pos -= 1
                    self._redraw_line(prompt, buffer, cursor_pos)

            # Arrow keys (special keys)
            elif char == '\x00' or char == '\xe0':
                arrow = msvcrt.getwch()

                # Up arrow - previous command
                if arrow == 'H':
                    if history_pos > 0:
                        if history_pos == len(self.history_manager):
                            temp_buffer = ''.join(buffer)
                        history_pos -= 1
                        buffer = list(self.history_manager.get(history_pos) or "")
                        cursor_pos = len(buffer)
                        self._redraw_line(prompt, buffer, cursor_pos)

                # Down arrow - next command
                elif arrow == 'P':
                    if history_pos < len(self.history_manager):
                        history_pos += 1
                        if history_pos == len(self.history_manager):
                            buffer = list(temp_buffer)
                        else:
                            buffer = list(self.history_manager.get(history_pos) or "")
                        cursor_pos = len(buffer)
                        self._redraw_line(prompt, buffer, cursor_pos)

                # Left arrow
                elif arrow == 'K':
                    if cursor_pos > 0:
                        cursor_pos -= 1
                        sys.stdout.write('\b')
                        sys.stdout.flush()

                # Right arrow
                elif arrow == 'M':
                    if cursor_pos < len(buffer):
                        sys.stdout.write(buffer[cursor_pos])
                        sys.stdout.flush()
                        cursor_pos += 1

            # Ctrl+C
            elif char == '\x03':
                print()
                raise KeyboardInterrupt()

            # Ctrl+D (EOF)
            elif char == '\x04':
                if not buffer:
                    return ""

            # Regular character
            elif char.isprintable():
                buffer.insert(cursor_pos, char)
                cursor_pos += 1
                self._redraw_line(prompt, buffer, cursor_pos)

    def _redraw_line(self, prompt: str, buffer: List[str], cursor_pos: int):
        """Redraw the input line (Windows)"""
        # Clear line
        sys.stdout.write('\r' + ' ' * (len(prompt) + len(buffer) + 10) + '\r')
        # Redraw
        sys.stdout.write(prompt + ''.join(buffer))
        # Position cursor
        sys.stdout.write('\r' + prompt + ''.join(buffer[:cursor_pos]))
        sys.stdout.flush()

    def get_history(self) -> List[str]:
        """Get command history"""
        return self.history_manager.get_all()

    def clear_history(self):
        """Clear command history"""
        self.history_manager.clear()
        if self.use_readline:
            import readline
            readline.clear_history()


# Convenience function
def create_input_handler(prompt: str = "> ", history_file: str = ".snode_history") -> InteractiveInput:
    """
    Create an interactive input handler with history

    Args:
        prompt: Input prompt string
        history_file: Path to history file (relative to home)

    Returns:
        InteractiveInput instance
    """
    history = HistoryManager(history_file=history_file)
    return InteractiveInput(prompt=prompt, history_manager=history)
