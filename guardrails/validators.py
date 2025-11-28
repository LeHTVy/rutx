"""
Command Validators
Combined validation logic for guardrails
"""

from typing import Tuple
from .input_filter import InputGuardrail
from .output_filter import OutputGuardrail, SafeCommandList


class CommandValidator:
    """Unified command validation with both input and output guardrails"""
    
    def __init__(self, strict_input: bool = True, allow_destructive: bool =  False):
        """
        Initialize validator
        
        Args:
            strict_input: Use strict mode for input validation
            allow_destructive: Allow potentially destructive commands
        """
        self.input_guardrail = InputGuardrail(strict_mode=strict_input)
        self.output_guardrail = OutputGuardrail(allow_destructive=allow_destructive)
    
    def validate_user_input(self, user_input: str) -> Tuple[bool, str]:
        """Validate user input for prompt injection"""
        return self.input_guardrail.validate(user_input)
    
    def validate_command(self, command: str) -> Tuple[bool, str]:
        """Validate command for dangerous operations"""
        is_safe, reason, _ = self.output_guardrail.validate(command)
        return is_safe, reason
    
    def is_whitelisted(self, command: str) -> bool:
        """Check if command is in whitelist"""
        return SafeCommandList.is_safe_command(command)


if __name__ == "__main__":
    validator = CommandValidator()
    
    # Test input validation
    print("Testing input validation:")
    is_valid, reason = validator.validate_user_input("Scan snode.com")
    print(f"  Valid: {is_valid}, Reason: {reason}")
    
    # Test command validation
    print("\nTesting command validation:")
    is_safe, reason = validator.validate_command("nmap -sV 192.168.1.1")
    print(f"  Safe: {is_safe}, Reason: {reason}")
