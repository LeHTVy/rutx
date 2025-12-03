"""
Snode Security Framework - Prompt Management System

Features:
- Template variable interpolation ({{VAR}})
- @include() directives for modular components
- Session-specific context injection
- Prompt snapshot saving for reproducibility
"""

import re
import os
from pathlib import Path
from typing import Dict, Optional


class PromptManager:
    """Manages prompt templates with modular includes and variable interpolation"""

    def __init__(self, prompts_dir: str = "prompt_templates"):
        self.prompts_dir = Path(prompts_dir)
        self.shared_dir = self.prompts_dir / "shared"

        # Ensure directories exist
        self.prompts_dir.mkdir(exist_ok=True)
        self.shared_dir.mkdir(exist_ok=True)

    def load_prompt(self, prompt_name: str, variables: Optional[Dict[str, str]] = None) -> str:
        """
        Load a prompt template and process includes + variable interpolation

        Args:
            prompt_name: Name of the prompt file (without .txt extension)
            variables: Dictionary of variables to interpolate

        Returns:
            Fully processed prompt string
        """
        # Load main prompt file
        prompt_path = self.prompts_dir / f"{prompt_name}.txt"

        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt not found: {prompt_path}")

        with open(prompt_path, 'r', encoding='utf-8') as f:
            template = f.read()

        # Process @include() directives
        template = self._process_includes(template)

        # Interpolate variables
        if variables:
            template = self._interpolate_variables(template, variables)

        return template

    def _process_includes(self, template: str) -> str:
        """
        Process @include() directives to inline shared components

        Example:
            @include(shared/_target_info.txt)
            -> Loads and inlines content from prompts/shared/_target_info.txt
        """
        include_pattern = r'@include\((.*?)\)'

        def replace_include(match):
            include_path = match.group(1).strip()

            # Remove 'shared/' prefix if present (we already know the dir)
            if include_path.startswith('shared/'):
                include_path = include_path[7:]

            full_path = self.shared_dir / include_path

            if not full_path.exists():
                print(f"Warning: Include file not found: {full_path}")
                return f"[MISSING: {include_path}]"

            with open(full_path, 'r', encoding='utf-8') as f:
                return f.read()

        return re.sub(include_pattern, replace_include, template)

    def _interpolate_variables(self, template: str, variables: Dict[str, str]) -> str:
        """
        Replace {{VARIABLE}} placeholders with actual values

        Example:
            {{TARGET}} -> "example.com"
            {{SCAN_TYPE}} -> "port_scan"
        """
        for key, value in variables.items():
            # Support both {{KEY}} and {{key}} (case-insensitive)
            pattern = r'\{\{' + re.escape(key) + r'\}\}'
            template = re.sub(pattern, str(value), template, flags=re.IGNORECASE)

        return template

    def save_prompt_snapshot(
        self,
        session_id: str,
        phase_name: str,
        prompt_content: str,
        output_dir: str = "audit_logs"
    ) -> str:
        """
        Save a snapshot of the exact prompt used (for reproducibility)

        Args:
            session_id: Unique session identifier
            phase_name: Name of the phase/agent
            prompt_content: The fully interpolated prompt
            output_dir: Directory to save snapshots

        Returns:
            Path to saved snapshot file
        """
        snapshot_dir = Path(output_dir) / session_id / "prompts"
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        snapshot_path = snapshot_dir / f"{phase_name}.md"

        with open(snapshot_path, 'w', encoding='utf-8') as f:
            f.write(prompt_content)

        return str(snapshot_path)

    def build_scan_context(
        self,
        scan_type: str,
        target: str,
        session_id: str,
        scan_results: Optional[Dict] = None,
        additional_vars: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Build standard variable dictionary for scan prompts

        Args:
            scan_type: Type of scan (port_scan, subdomain_enum, etc.)
            target: Target being scanned
            session_id: Session identifier
            scan_results: Optional scan results to include
            additional_vars: Additional custom variables

        Returns:
            Dictionary of variables ready for interpolation
        """
        variables = {
            'TARGET': target,
            'SESSION_ID': session_id,
            'SCAN_TYPE': scan_type,
        }

        # Add scan results if provided
        if scan_results:
            import json
            variables['SCAN_RESULTS'] = json.dumps(scan_results, indent=2)

        # Add any additional custom variables
        if additional_vars:
            variables.update(additional_vars)

        return variables


# Singleton instance
_prompt_manager = None

def get_prompt_manager() -> PromptManager:
    """Get or create the global PromptManager instance"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager()
    return _prompt_manager


# Convenience functions
def load_prompt(prompt_name: str, variables: Optional[Dict[str, str]] = None) -> str:
    """Load and process a prompt template"""
    return get_prompt_manager().load_prompt(prompt_name, variables)


def save_prompt_snapshot(session_id: str, phase_name: str, prompt_content: str) -> str:
    """Save prompt snapshot for reproducibility"""
    return get_prompt_manager().save_prompt_snapshot(session_id, phase_name, prompt_content)


# Example usage
if __name__ == "__main__":
    # Test the prompt manager
    pm = PromptManager()

    # Test variables
    test_vars = {
        'TARGET': 'example.com',
        'SESSION_ID': 'test-123',
        'SCAN_TYPE': 'port_scan'
    }

    print("Prompt Manager Test")
    print("=" * 60)

    # Test loading a prompt (will work once you create phase1_tool_selection.txt)
    try:
        prompt = pm.load_prompt('phase1_tool_selection', test_vars)
        print("✅ Loaded prompt successfully")
        print(f"Length: {len(prompt)} characters")
    except FileNotFoundError as e:
        print(f"⚠️  {e}")
        print("Create prompts/phase1_tool_selection.txt to test")
