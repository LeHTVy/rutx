"""
Command Runner - Subprocess wrapper for tool execution
========================================================

Provides a clean interface for running shell commands with:
- Timeout handling
- Error capture
- Progress indication
"""
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class CommandResult:
    """Result from a command execution."""
    success: bool
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    exit_code: int = 0
    elapsed_time: float = 0.0


class CommandRunner:
    """
    Static utility for running shell commands.
    
    All methods are class methods for ease of use.
    """
    
    @classmethod
    def run(
        cls,
        cmd: List[str],
        timeout: int = 300,
        show_progress: bool = False,
        cwd: str = None
    ) -> CommandResult:
        """
        Run a command with timeout and capture output.
        
        Args:
            cmd: Command as list of strings
            timeout: Timeout in seconds
            show_progress: If True, show a spinner
            cwd: Working directory
            
        Returns:
            CommandResult with output and status
        """
        start_time = time.time()
        
        try:
            if show_progress:
                print(f"    Running: {cmd[0]}...", end="", flush=True)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd
            )
            
            elapsed = time.time() - start_time
            
            if show_progress:
                print(f" done ({elapsed:.1f}s)")
            
            return CommandResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                elapsed_time=elapsed
            )
            
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            if show_progress:
                print(f" timeout ({timeout}s)")
            return CommandResult(
                success=False,
                error=f"Command timed out after {timeout} seconds",
                elapsed_time=elapsed
            )
            
        except FileNotFoundError:
            if show_progress:
                print(" not found")
            return CommandResult(
                success=False,
                error=f"Command not found: {cmd[0]}"
            )
            
        except Exception as e:
            if show_progress:
                print(f" error")
            return CommandResult(
                success=False,
                error=str(e)
            )
    
    @classmethod
    def run_async(
        cls,
        cmd: List[str],
        cwd: str = None
    ) -> subprocess.Popen:
        """
        Start a command asynchronously.
        
        Returns Popen object for monitoring.
        """
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd
        )
    
    @classmethod
    def check_installed(cls, command: str) -> bool:
        """Check if a command is installed."""
        import shutil
        return shutil.which(command) is not None
