"""
Command Validators
Combined validation logic for guardrails

DEPRECATED: Use InputGuardrail and OutputGuardrail directly instead.
This module is kept for backward compatibility but should not be used in new code.
"""

from typing import Tuple
from .input_filter import InputGuardrail
from .output_filter import OutputGuardrail, SafeCommandList


# The CommandValidator wrapper class has been removed.
# Use InputGuardrail and OutputGuardrail directly instead:
#
# Example:
#   input_guard = InputGuardrail(strict_mode=True)
#   output_guard = OutputGuardrail(allow_destructive=False)
#
#   # Validate user input
#   is_valid, reason = input_guard.validate(user_input)
#
#   # Validate command
#   is_safe, reason, _ = output_guard.validate(command)


if __name__ == "__main__":
    # Example usage with direct guardrail usage
    input_guard = InputGuardrail(strict_mode=True)
    output_guard = OutputGuardrail(allow_destructive=False)

    # Test input validation
    print("Testing input validation:")
    is_valid, reason = input_guard.validate("Scan snode.com")
    print(f"  Valid: {is_valid}, Reason: {reason}")

    # Test command validation
    print("\nTesting command validation:")
    is_safe, reason, _ = output_guard.validate("nmap -sV 192.168.1.1")
    print(f"  Safe: {is_safe}, Reason: {reason}")
