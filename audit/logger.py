"""
Snode Security Framework - Crash-Safe Audit Logging System

Provides append-only event logging and atomic session state management
for crash recovery and audit trails.
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Any


class AuditLogger:
    """
    Crash-safe audit logger with append-only events and atomic state updates

    Architecture:
    - Events logged immediately to disk (append-only)
    - Session state updated atomically (temp file + rename)
    - Survives process crashes and can resume from last known state
    """

    def __init__(self, session_id: str, target: str, output_dir: str = "audit_logs"):
        """
        Initialize audit logger for a scan session

        Args:
            session_id: Unique session identifier
            target: Target being scanned (hostname or IP)
            output_dir: Base directory for audit logs
        """
        self.session_id = session_id
        self.target = self._sanitize_filename(target)
        self.output_dir = Path(output_dir)

        # Create session directory: audit_logs/{target}_{session_id}/
        self.session_dir = self.output_dir / f"{self.target}_{session_id}"
        self.session_dir.mkdir(parents=True, exist_ok=True)

        # Subdirectories
        self.events_dir = self.session_dir / "events"
        self.prompts_dir = self.session_dir / "prompts"
        self.events_dir.mkdir(exist_ok=True)
        self.prompts_dir.mkdir(exist_ok=True)

        # Session state file
        self.session_file = self.session_dir / "session.json"

    def _sanitize_filename(self, name: str) -> str:
        """Remove characters that aren't safe for filenames"""
        return "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)

    def log_event(self, event_type: str, data: Dict[str, Any], flush: bool = True):
        """
        Log an event with immediate disk write (append-only)

        Args:
            event_type: Type of event (tool_start, tool_end, phase_start, etc.)
            data: Event data dictionary
            flush: Force immediate disk write (default: True for crash safety)
        """
        timestamp = datetime.now().isoformat()

        # Create event record
        event = {
            "timestamp": timestamp,
            "type": event_type,
            "session_id": self.session_id,
            "target": self.target,
            "data": data
        }

        # Generate unique event filename
        event_filename = f"{timestamp.replace(':', '-')}_{event_type}.log"
        event_path = self.events_dir / event_filename

        # Write to disk immediately
        with open(event_path, 'w', encoding='utf-8') as f:
            json.dump(event, f, indent=2)
            if flush:
                f.flush()
                os.fsync(f.fileno())  # Force OS to write to disk

    def update_session_state(self, state: Dict[str, Any]):
        """
        Atomically update session state (crash-safe)

        Uses temp file + atomic rename pattern to prevent partial writes

        Args:
            state: Complete session state dictionary
        """
        temp_file = self.session_file.with_suffix('.tmp')

        # Add metadata
        state['session_id'] = self.session_id
        state['target'] = self.target
        state['last_updated'] = datetime.now().isoformat()

        # Write to temporary file
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())  # Force disk write

        # Atomic rename (overwrites old session.json)
        temp_file.replace(self.session_file)

    def load_session_state(self) -> Optional[Dict[str, Any]]:
        """
        Load current session state from disk

        Returns:
            Session state dictionary or None if doesn't exist
        """
        if not self.session_file.exists():
            return None

        with open(self.session_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def save_prompt(self, phase_name: str, prompt_content: str):
        """
        Save prompt snapshot for reproducibility

        Args:
            phase_name: Name of the phase (phase1_tool_selection, etc.)
            prompt_content: The exact prompt sent to LLM
        """
        prompt_file = self.prompts_dir / f"{phase_name}.md"

        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(f"# {phase_name}\n\n")
            f.write(f"**Session**: {self.session_id}\n")
            f.write(f"**Target**: {self.target}\n")
            f.write(f"**Timestamp**: {datetime.now().isoformat()}\n\n")
            f.write("---\n\n")
            f.write(prompt_content)

    def get_event_history(self) -> list:
        """
        Load all events in chronological order

        Returns:
            List of event dictionaries
        """
        events = []

        if not self.events_dir.exists():
            return events

        event_files = sorted(self.events_dir.glob("*.log"))

        for event_file in event_files:
            try:
                with open(event_file, 'r', encoding='utf-8') as f:
                    events.append(json.load(f))
            except Exception as e:
                print(f"Warning: Failed to load event {event_file}: {e}")

        return events

    def reconcile_state(self) -> Dict[str, Any]:
        """
        Reconcile session state from event history (crash recovery)

        Rebuilds session state by replaying all events. Useful after crash.

        Returns:
            Reconstructed session state
        """
        events = self.get_event_history()

        # Initialize state
        state = {
            'session_id': self.session_id,
            'target': self.target,
            'status': 'unknown',
            'completed_phases': [],
            'failed_phases': [],
            'completed_tools': [],
            'failed_tools': [],
            'timestamps': {}
        }

        # Replay events
        for event in events:
            event_type = event['type']
            event_data = event['data']
            timestamp = event['timestamp']

            if event_type == 'session_start':
                state['status'] = 'in-progress'
                state['timestamps']['started'] = timestamp

            elif event_type == 'phase_start':
                phase = event_data.get('phase')
                state['timestamps'][f'{phase}_start'] = timestamp

            elif event_type == 'phase_end':
                phase = event_data.get('phase')
                success = event_data.get('success', False)
                state['timestamps'][f'{phase}_end'] = timestamp

                if success:
                    if phase not in state['completed_phases']:
                        state['completed_phases'].append(phase)
                else:
                    if phase not in state['failed_phases']:
                        state['failed_phases'].append(phase)

            elif event_type == 'tool_start':
                tool = event_data.get('tool')
                state['timestamps'][f'{tool}_start'] = timestamp

            elif event_type == 'tool_end':
                tool = event_data.get('tool')
                success = event_data.get('success', False)
                state['timestamps'][f'{tool}_end'] = timestamp

                if success:
                    if tool not in state['completed_tools']:
                        state['completed_tools'].append(tool)
                else:
                    if tool not in state['failed_tools']:
                        state['failed_tools'].append(tool)

            elif event_type == 'session_end':
                state['status'] = event_data.get('status', 'completed')
                state['timestamps']['ended'] = timestamp

        # Update session file with reconciled state
        self.update_session_state(state)

        return state


class SessionMetrics:
    """Track timing and cost metrics for a session"""

    def __init__(self, audit_logger: AuditLogger):
        self.logger = audit_logger
        self.start_times = {}

    def start_timer(self, label: str):
        """Start a timer for a specific operation"""
        self.start_times[label] = datetime.now()

    def end_timer(self, label: str) -> float:
        """
        End a timer and return elapsed seconds

        Returns:
            Elapsed time in seconds
        """
        if label not in self.start_times:
            return 0.0

        elapsed = (datetime.now() - self.start_times[label]).total_seconds()

        # Log timing event
        self.logger.log_event('timing', {
            'label': label,
            'elapsed_seconds': elapsed
        })

        return elapsed

    def log_cost(self, operation: str, cost: float, currency: str = 'USD'):
        """Log cost for an operation (e.g., LLM API calls)"""
        self.logger.log_event('cost', {
            'operation': operation,
            'cost': cost,
            'currency': currency
        })


# Convenience function to create audit logger for current session
def create_audit_logger(session_id: str, target: str, output_dir: str = None) -> AuditLogger:
    """
    Create and initialize an audit logger for a scan session

    Args:
        session_id: Unique session identifier
        target: Target being scanned
        output_dir: Custom output directory (defaults to config.AUDIT_LOG_DIR)
    """
    # Use centralized config if no custom directory specified
    if output_dir is None:
        try:
            from config import AUDIT_LOG_DIR
            output_dir = str(AUDIT_LOG_DIR)
        except ImportError:
            output_dir = "audit_logs"  # Fallback

    logger = AuditLogger(session_id, target, output_dir)

    # Log session start
    logger.log_event('session_start', {
        'session_id': session_id,
        'target': target
    })

    # Initialize session state
    logger.update_session_state({
        'status': 'initializing',
        'completed_phases': [],
        'failed_phases': [],
        'completed_tools': [],
        'failed_tools': [],
        'timestamps': {
            'created': datetime.now().isoformat()
        }
    })

    return logger


if __name__ == "__main__":
    # Test the audit logger
    print("Testing Audit Logger")
    print("=" * 60)

    # Create test session
    logger = create_audit_logger('test-123', 'example.com')

    # Simulate some events
    logger.log_event('phase_start', {'phase': 'phase1_tool_selection'})
    logger.log_event('tool_start', {'tool': 'nmap_quick_scan', 'target': 'example.com'})
    logger.log_event('tool_end', {'tool': 'nmap_quick_scan', 'success': True, 'duration': 45.2})
    logger.log_event('phase_end', {'phase': 'phase1_tool_selection', 'success': True})

    # Update session state
    logger.update_session_state({
        'status': 'in-progress',
        'completed_phases': ['phase1_tool_selection'],
        'completed_tools': ['nmap_quick_scan']
    })

    # Save a prompt
    logger.save_prompt('phase1_tool_selection', 'This is a test prompt for phase 1')

    # Test recovery
    print("\nReconciling state from events...")
    state = logger.reconcile_state()
    print(f"Reconciled state: {json.dumps(state, indent=2)}")

    print(f"\n[SUCCESS] Audit logs saved to: {logger.session_dir}")
    print(f"   - Events: {len(list(logger.events_dir.glob('*.log')))} files")
    print(f"   - Session state: {logger.session_file}")
    print(f"   - Prompts: {len(list(logger.prompts_dir.glob('*.md')))} files")
