"""
Unified Command Runner for Security Tools

This module provides a centralized, consistent way to execute subprocess commands
across all security tools (nmap, masscan, amass, etc.).

Benefits:
- Eliminates 200+ lines of duplicate subprocess.run() code
- Consistent error handling and timeout behavior
- Standardized result format
- Easier to add logging, metrics, and security checks
"""

import subprocess
import time
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class CommandExecutionResult:
    """Standardized result object for command execution"""

    def __init__(
        self,
        success: bool,
        returncode: int,
        stdout: str,
        stderr: str,
        elapsed_time: float,
        command: List[str],
        error: Optional[str] = None
    ):
        self.success = success
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.elapsed_time = elapsed_time
        self.command = command
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility"""
        result = {
            "success": self.success,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "elapsed_time": self.elapsed_time,
            "command": " ".join(self.command)
        }
        if self.error:
            result["error"] = self.error
        return result


class CommandRunner:
    """
    Unified command execution utility for all security tools.

    This class consolidates the duplicate subprocess.run() patterns found across
    9+ tool files in the codebase.
    """

    @staticmethod
    def run(
        command: List[str],
        timeout: int = 300,
        capture_output: bool = True,
        text: bool = True,
        check: bool = False,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> CommandExecutionResult:
        """
        Execute a command with consistent timeout and error handling.

        Args:
            command: List of command arguments (e.g., ['nmap', '-sV', 'target.com'])
            timeout: Maximum execution time in seconds (default: 300)
            capture_output: Whether to capture stdout/stderr (default: True)
            text: Whether to decode output as text (default: True)
            check: Whether to raise exception on non-zero exit (default: False)
            cwd: Working directory for command execution
            env: Environment variables for the command

        Returns:
            CommandExecutionResult with success status, output, and timing

        Example:
            >>> result = CommandRunner.run(['nmap', '-sV', '192.168.1.1'], timeout=600)
            >>> if result.success:
            >>>     print(f"Scan completed in {result.elapsed_time:.2f}s")
            >>>     print(result.stdout)
        """
        logger.debug(f"Executing command: {' '.join(command)}")

        start_time = time.time()
        error_message = None

        try:
            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=text,
                timeout=timeout,
                check=check,
                cwd=cwd,
                env=env
            )
            elapsed = time.time() - start_time

            # Determine success based on return code
            success = result.returncode == 0

            if not success:
                error_message = f"Command returned exit code {result.returncode}"
                logger.warning(f"Command failed: {error_message}")
            else:
                logger.debug(f"Command completed successfully in {elapsed:.2f}s")

            return CommandExecutionResult(
                success=success,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                elapsed_time=elapsed,
                command=command,
                error=error_message
            )

        except subprocess.TimeoutExpired as e:
            elapsed = time.time() - start_time
            error_message = f"Command timed out after {timeout} seconds"
            logger.error(error_message)

            return CommandExecutionResult(
                success=False,
                returncode=-1,
                stdout=e.stdout.decode() if e.stdout else "",
                stderr=e.stderr.decode() if e.stderr else "",
                elapsed_time=elapsed,
                command=command,
                error=error_message
            )

        except FileNotFoundError as e:
            elapsed = time.time() - start_time
            error_message = f"Command not found: {command[0]}"
            logger.error(f"{error_message} - {e}")

            return CommandExecutionResult(
                success=False,
                returncode=-2,
                stdout="",
                stderr=str(e),
                elapsed_time=elapsed,
                command=command,
                error=error_message
            )

        except Exception as e:
            elapsed = time.time() - start_time
            error_message = f"Unexpected error: {type(e).__name__}: {str(e)}"
            logger.error(f"Command execution failed: {error_message}")

            return CommandExecutionResult(
                success=False,
                returncode=-3,
                stdout="",
                stderr=str(e),
                elapsed_time=elapsed,
                command=command,
                error=error_message
            )

    @staticmethod
    def run_with_retries(
        command: List[str],
        timeout: int = 300,
        max_retries: int = 3,
        retry_delay: float = 2.0
    ) -> CommandExecutionResult:
        """
        Execute a command with automatic retry on failure.

        Useful for network-dependent tools that may have transient failures.

        Args:
            command: Command to execute
            timeout: Timeout per attempt
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds

        Returns:
            CommandExecutionResult from the last attempt
        """
        last_result = None

        for attempt in range(max_retries):
            if attempt > 0:
                logger.info(f"Retry attempt {attempt}/{max_retries - 1} after {retry_delay}s")
                time.sleep(retry_delay)

            last_result = CommandRunner.run(command, timeout=timeout)

            if last_result.success:
                return last_result

            logger.warning(f"Attempt {attempt + 1} failed: {last_result.error}")

        logger.error(f"All {max_retries} attempts failed")
        return last_result


# Convenience function for backward compatibility
def run_command(
    command: List[str],
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Backward-compatible wrapper that returns a dictionary.

    This allows existing tool code to migrate gradually.
    """
    result = CommandRunner.run(command, timeout=timeout)
    return result.to_dict()
