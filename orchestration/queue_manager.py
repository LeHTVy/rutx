"""
Snode Security Framework - Queue-based Exploitation Pattern

Allows analysis phases to output structured attack queues for exploitation.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class QueueItem:
    """Represents a single exploit opportunity discovered during analysis"""

    # Identification
    target: str
    service: str
    port: int

    # Vulnerability Details
    vulnerability_type: str  # e.g., "rce", "sqli", "xss", "auth_bypass"
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None

    # Proof of Concept
    proof_command: Optional[str] = None
    proof_output: Optional[str] = None

    # Exploitation Strategy
    exploit_tool: Optional[str] = None  # e.g., "metasploit", "custom_script", "manual"
    exploit_complexity: str = "medium"  # low, medium, high
    requires_auth: bool = False

    # Priority
    severity: str = "medium"  # critical, high, medium, low
    exploitability: str = "probable"  # confirmed, probable, possible, theoretical
    business_impact: Optional[str] = None

    # Metadata
    discovered_by: str = "analysis_phase"
    discovered_at: str = ""
    status: str = "queued"  # queued, in_progress, exploited, failed, skipped

    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QueueItem':
        """Create QueueItem from dictionary"""
        return cls(**data)


class ExploitQueue:
    """Manages the queue of exploit opportunities between analysis and exploitation phases"""

    def __init__(self, session_id: str, audit_log_dir: str = "audit_logs"):
        self.session_id = session_id
        self.queue_dir = Path(audit_log_dir) / session_id / "exploit_queue"
        self.queue_dir.mkdir(parents=True, exist_ok=True)

        self.queue_file = self.queue_dir / "queue.json"
        self.completed_file = self.queue_dir / "completed.json"

        # Initialize empty queue files if they don't exist
        if not self.queue_file.exists():
            self._save_queue([])
        if not self.completed_file.exists():
            self._save_completed([])

    def add_item(self, item: QueueItem) -> None:
        """Add an exploit opportunity to the queue"""
        queue = self._load_queue()
        queue.append(item.to_dict())
        self._save_queue(queue)

    def add_multiple(self, items: List[QueueItem]) -> None:
        """Add multiple exploit opportunities to the queue"""
        queue = self._load_queue()
        queue.extend([item.to_dict() for item in items])
        self._save_queue(queue)

    def get_next(self) -> Optional[QueueItem]:
        """Get the next queued item (highest priority first)"""
        queue = self._load_queue()

        if not queue:
            return None

        # Priority order: critical > high > medium > low
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

        # Sort by severity, then by exploitability
        queue.sort(key=lambda x: (
            priority_order.get(x.get('severity', 'medium'), 2),
            0 if x.get('exploitability') == 'confirmed' else 1
        ))

        # Get first item and mark as in_progress
        next_item_dict = queue.pop(0)
        next_item_dict['status'] = 'in_progress'

        # Save updated queue
        self._save_queue(queue)

        return QueueItem.from_dict(next_item_dict)

    def mark_completed(self, item: QueueItem, success: bool, result_data: Optional[Dict] = None) -> None:
        """Mark an item as completed (exploited or failed)"""
        item.status = 'exploited' if success else 'failed'

        completed = self._load_completed()
        completed_entry = item.to_dict()

        if result_data:
            completed_entry['result'] = result_data

        completed_entry['completed_at'] = datetime.now().isoformat()
        completed.append(completed_entry)

        self._save_completed(completed)

    def skip_item(self, item: QueueItem, reason: str) -> None:
        """Skip an exploit (e.g., too risky, out of scope)"""
        item.status = 'skipped'

        completed = self._load_completed()
        completed_entry = item.to_dict()
        completed_entry['skip_reason'] = reason
        completed_entry['completed_at'] = datetime.now().isoformat()
        completed.append(completed_entry)

        self._save_completed(completed)

    def get_all_queued(self) -> List[QueueItem]:
        """Get all queued items"""
        queue = self._load_queue()
        return [QueueItem.from_dict(item) for item in queue]

    def get_all_completed(self) -> List[Dict[str, Any]]:
        """Get all completed items"""
        return self._load_completed()

    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        queued = self._load_queue()
        completed = self._load_completed()

        exploited = [c for c in completed if c.get('status') == 'exploited']
        failed = [c for c in completed if c.get('status') == 'failed']
        skipped = [c for c in completed if c.get('status') == 'skipped']

        return {
            'total_discovered': len(queued) + len(completed),
            'queued': len(queued),
            'exploited': len(exploited),
            'failed': len(failed),
            'skipped': len(skipped),
            'success_rate': len(exploited) / len(completed) if completed else 0
        }

    def _load_queue(self) -> List[Dict[str, Any]]:
        """Load queued items from disk"""
        if not self.queue_file.exists():
            return []

        with open(self.queue_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _save_queue(self, queue: List[Dict[str, Any]]) -> None:
        """Save queued items to disk"""
        with open(self.queue_file, 'w', encoding='utf-8') as f:
            json.dump(queue, f, indent=2)

    def _load_completed(self) -> List[Dict[str, Any]]:
        """Load completed items from disk"""
        if not self.completed_file.exists():
            return []

        with open(self.completed_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _save_completed(self, completed: List[Dict[str, Any]]) -> None:
        """Save completed items to disk"""
        with open(self.completed_file, 'w', encoding='utf-8') as f:
            json.dump(completed, f, indent=2)


# Convenience function
def create_exploit_queue(session_id: str, audit_log_dir: str = "audit_logs") -> ExploitQueue:
    """Create an ExploitQueue instance"""
    return ExploitQueue(session_id, audit_log_dir)


# Example usage
if __name__ == "__main__":
    # Create test queue
    queue = ExploitQueue("test-session-123")

    # Add some test items
    item1 = QueueItem(
        target="192.168.1.100",
        service="Apache httpd",
        port=80,
        vulnerability_type="rce",
        cve_id="CVE-2021-41773",
        cvss_score=9.8,
        proof_command="curl http://192.168.1.100/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
        severity="critical",
        exploitability="confirmed",
        exploit_tool="metasploit"
    )

    item2 = QueueItem(
        target="192.168.1.100",
        service="OpenSSH",
        port=22,
        vulnerability_type="auth_bypass",
        severity="high",
        exploitability="probable",
        business_impact="Unauthorized access to server"
    )

    queue.add_multiple([item1, item2])

    # Show stats
    stats = queue.get_stats()
    print("\n[SUCCESS] Exploit Queue Test")
    print("=" * 60)
    print(f"Total discovered: {stats['total_discovered']}")
    print(f"Queued: {stats['queued']}")
    print(f"Exploited: {stats['exploited']}")
    print(f"Failed: {stats['failed']}")

    # Get next item
    next_item = queue.get_next()
    if next_item:
        print(f"\nNext exploit target: {next_item.service} on port {next_item.port}")
        print(f"Severity: {next_item.severity}")
        print(f"CVE: {next_item.cve_id}")

        # Mark as exploited
        queue.mark_completed(next_item, success=True, result_data={
            'method': 'metasploit',
            'shell_obtained': True
        })

        print("\n[SUCCESS] Item marked as exploited")

    # Final stats
    stats = queue.get_stats()
    print(f"\nFinal stats:")
    print(f"Queued: {stats['queued']}")
    print(f"Exploited: {stats['exploited']}")
    print(f"Success rate: {stats['success_rate']:.1%}")
