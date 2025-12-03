"""
Snode Security Framework - Phase Validation System

Enforces "No Exploit, No Report" principle by validating phase outputs.
"""

from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import json
import re


class ValidationError(Exception):
    """Raised when phase validation fails"""
    pass


class PhaseValidator:
    """Validates that each phase produces required deliverables with proof"""

    @staticmethod
    def validate_phase1_tool_selection(output: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate Phase 1: Tool Selection

        Requirements:
        - At least 1 tool selected
        - Each tool has clear justification
        - Target is specified
        """
        errors = []

        # Check tools selected
        tools = output.get('selected_tools', [])
        if not tools:
            errors.append("No tools selected")

        # Check each tool has justification
        for tool in tools:
            if 'name' not in tool:
                errors.append(f"Tool missing 'name' field: {tool}")
            if 'justification' not in tool or not tool['justification'].strip():
                errors.append(f"Tool '{tool.get('name', 'unknown')}' missing justification")

        # Check reasoning exists
        if 'reasoning' not in output or not output['reasoning'].strip():
            errors.append("Missing overall reasoning for tool selection")

        return (len(errors) == 0, errors)

    @staticmethod
    def validate_phase2_execution(output: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate Phase 2: Tool Execution

        Requirements:
        - All selected tools were executed
        - Each execution has results
        - At least one tool succeeded
        """
        errors = []

        execution_results = output.get('execution_results', [])
        if not execution_results:
            errors.append("No execution results found")
            return (False, errors)

        # Check at least one tool succeeded
        successful_tools = [r for r in execution_results if r.get('result', {}).get('success')]
        if not successful_tools:
            errors.append("No tools executed successfully")

        # Validate each execution has required fields
        for result in execution_results:
            tool_name = result.get('tool', 'unknown')

            if 'result' not in result:
                errors.append(f"Tool '{tool_name}' missing result data")
                continue

            tool_result = result['result']

            # Check for success field
            if 'success' not in tool_result:
                errors.append(f"Tool '{tool_name}' missing success flag")

            # If successful, check for data using tool-specific fields
            if tool_result.get('success'):
                has_data = False
                
                # Check for various data fields depending on tool type
                data_fields = [
                    'output',           # Generic output
                    'subdomains',       # Subdomain tools (amass, bbot)
                    'results',          # Port scanners (masscan, naabu)
                    'data',             # OSINT tools (shodan)
                    'hosts',            # Nmap
                    'ports',            # Port lists
                    'open_ports',       # Open ports
                ]
                
                for field in data_fields:
                    if field in tool_result and tool_result[field]:
                        # Check if it's actually populated (not empty list/dict/string)
                        value = tool_result[field]
                        if isinstance(value, (list, dict)):
                            if len(value) > 0:
                                has_data = True
                                break
                        elif isinstance(value, str):
                            if value.strip():
                                has_data = True
                                break
                        else:
                            # Other types (int, bool, etc.)
                            has_data = True
                            break
                
                if not has_data:
                    errors.append(f"Tool '{tool_name}' succeeded but has no output")

        return (len(errors) == 0, errors)

    @staticmethod
    def validate_phase3_analysis(output: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate Phase 3: Analysis

        Requirements:
        - Analysis summary exists
        - Risk assessment provided
        - Findings have proof (commands + outputs)
        - No fabricated CVEs or vulnerabilities
        """
        errors = []

        # Check summary exists
        summary = output.get('summary', '')
        if not summary or len(summary.strip()) < 50:
            errors.append("Analysis summary missing or too short (min 50 chars)")

        # Check risk assessment
        if 'risk_score' not in output:
            errors.append("Missing risk_score")
        else:
            risk_score = output['risk_score']
            if not isinstance(risk_score, (int, float)) or risk_score < 0 or risk_score > 100:
                errors.append(f"Invalid risk_score: {risk_score} (must be 0-100)")

        if 'risk_level' not in output:
            errors.append("Missing risk_level")

        # Validate findings have proof
        findings = output.get('findings', [])
        if findings:
            for idx, finding in enumerate(findings):
                finding_name = finding.get('title', f'Finding {idx+1}')

                # Check for proof command
                if 'proof_command' not in finding or not finding['proof_command']:
                    errors.append(f"Finding '{finding_name}' missing proof_command")

                # Check for actual output
                if 'proof_output' not in finding or not finding['proof_output']:
                    errors.append(f"Finding '{finding_name}' missing proof_output")

                # Validate CVE format if present
                if 'cve_id' in finding and finding['cve_id']:
                    cve = finding['cve_id']
                    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve):
                        errors.append(f"Finding '{finding_name}' has invalid CVE format: {cve}")

        # Check for hallucination indicators
        hallucination_keywords = [
            'theoretical',
            'may be vulnerable',
            'could potentially',
            'might have',
            'appears to suggest'
        ]

        summary_lower = summary.lower()
        for keyword in hallucination_keywords:
            if keyword in summary_lower:
                errors.append(f"Analysis contains uncertain language: '{keyword}' (provide proof, not speculation)")

        return (len(errors) == 0, errors)

    @staticmethod
    def validate_phase4_exploitation(output: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate Phase 4: Exploitation (Optional)

        Requirements:
        - Exploit queue processed
        - Each exploit attempt documented with proof
        - Success/failure clearly indicated
        """
        errors = []

        # Check exploit results
        exploit_results = output.get('exploit_results', [])

        if not exploit_results:
            # Exploitation phase is optional, but if present must have results
            if 'exploit_queue' in output and output['exploit_queue']:
                errors.append("Exploit queue exists but no results documented")

        # Validate each exploit result
        for result in exploit_results:
            target = result.get('target', 'unknown')

            # Check required fields
            if 'success' not in result:
                errors.append(f"Exploit against '{target}' missing success flag")

            if 'method' not in result:
                errors.append(f"Exploit against '{target}' missing method description")

            # If successful, must have proof
            if result.get('success'):
                if 'proof_of_exploit' not in result or not result['proof_of_exploit']:
                    errors.append(f"Successful exploit against '{target}' missing proof")

        return (len(errors) == 0, errors)

    @staticmethod
    def validate_final_report(output: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate Final Report

        Requirements:
        - Executive summary exists
        - All findings have proof
        - Recommendations are actionable
        - No theoretical vulnerabilities reported
        """
        errors = []

        # Check executive summary
        exec_summary = output.get('executive_summary', '')
        if not exec_summary or len(exec_summary.strip()) < 100:
            errors.append("Executive summary missing or too short (min 100 chars)")

        # Check findings
        findings = output.get('findings', [])
        if not findings:
            errors.append("Report has no findings")
        else:
            for finding in findings:
                # Each finding must have proof
                if not finding.get('proof_command') or not finding.get('proof_output'):
                    errors.append(f"Finding '{finding.get('title')}' lacks proof (command + output)")

                # Each finding must have remediation
                if not finding.get('remediation'):
                    errors.append(f"Finding '{finding.get('title')}' missing remediation steps")

        # Check recommendations exist
        recommendations = output.get('recommendations', [])
        if not recommendations:
            errors.append("Report missing recommendations")

        return (len(errors) == 0, errors)


def validate_phase_output(phase_name: str, output: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate output from any phase

    Args:
        phase_name: Name of phase (phase1_tool_selection, phase2_execution, etc.)
        output: The phase output dictionary

    Returns:
        Tuple of (is_valid, error_messages)
    """
    validator = PhaseValidator()

    if phase_name == 'phase1_tool_selection':
        return validator.validate_phase1_tool_selection(output)
    elif phase_name == 'phase2_execution':
        return validator.validate_phase2_execution(output)
    elif phase_name == 'phase3_analysis':
        return validator.validate_phase3_analysis(output)
    elif phase_name == 'phase4_exploitation':
        return validator.validate_phase4_exploitation(output)
    elif phase_name == 'final_report':
        return validator.validate_final_report(output)
    else:
        return (False, [f"Unknown phase: {phase_name}"])


class AgentValidator:
    """Validates that agents produce required deliverables"""

    @staticmethod
    def check_deliverables_exist(session_dir: Path, phase_name: str) -> Tuple[bool, List[str]]:
        """
        Check that required deliverable files exist

        Args:
            session_dir: Path to session audit directory
            phase_name: Name of the phase

        Returns:
            Tuple of (all_exist, missing_files)
        """
        missing = []

        # Common deliverables
        prompts_dir = session_dir / "prompts"
        if not (prompts_dir / f"{phase_name}.md").exists():
            missing.append(f"prompts/{phase_name}.md")

        events_dir = session_dir / "events"
        if not events_dir.exists():
            missing.append("events/")

        # Phase-specific deliverables
        if phase_name == 'phase3_analysis':
            # Analysis should produce findings
            findings_file = session_dir / "findings.json"
            if not findings_file.exists():
                missing.append("findings.json")

        if phase_name == 'phase4_exploitation':
            # Exploitation should update queue
            queue_dir = session_dir / "exploit_queue"
            if not queue_dir.exists():
                missing.append("exploit_queue/")

        return (len(missing) == 0, missing)

    @staticmethod
    def verify_proof_based_findings(findings: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
        """
        Verify all findings have actual proof (not theoretical)

        Args:
            findings: List of finding dictionaries

        Returns:
            Tuple of (all_have_proof, findings_without_proof)
        """
        without_proof = []

        for finding in findings:
            title = finding.get('title', 'Untitled')

            # Must have both command and output
            has_command = bool(finding.get('proof_command'))
            has_output = bool(finding.get('proof_output'))

            if not (has_command and has_output):
                without_proof.append(title)

        return (len(without_proof) == 0, without_proof)


# Example usage
if __name__ == "__main__":
    print("Phase Validator Test")
    print("=" * 60)

    # Test Phase 3 validation
    test_output = {
        'summary': 'Found critical RCE vulnerability in Apache server on port 80. Confirmed exploitable via path traversal.',
        'risk_score': 95,
        'risk_level': 'CRITICAL',
        'findings': [
            {
                'title': 'Apache Path Traversal RCE',
                'cve_id': 'CVE-2021-41773',
                'severity': 'critical',
                'proof_command': 'curl http://target/cgi-bin/.%2e/.%2e/bin/sh',
                'proof_output': 'HTTP/1.1 200 OK\nContent-Type: text/plain\n\n[shell output]'
            }
        ]
    }

    is_valid, errors = validate_phase_output('phase3_analysis', test_output)

    if is_valid:
        print("\n[SUCCESS] Phase 3 output is valid")
    else:
        print("\n[ERROR] Phase 3 validation failed:")
        for error in errors:
            print(f"  - {error}")

    # Test invalid output
    invalid_output = {
        'summary': 'Short',  # Too short
        'risk_score': 150,  # Invalid score
        'findings': [
            {
                'title': 'Theoretical XSS',
                # Missing proof_command and proof_output
            }
        ]
    }

    is_valid, errors = validate_phase_output('phase3_analysis', invalid_output)

    print("\n\nTesting invalid output:")
    if not is_valid:
        print("[SUCCESS] Correctly rejected invalid output:")
        for error in errors:
            print(f"  - {error}")
