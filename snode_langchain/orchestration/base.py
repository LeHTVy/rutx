"""
Base Orchestrator - Foundation for complex multi-step security workflows

Features:
- State persistence (resume on crash)
- Error recovery with retry
- Progress callbacks for UI
- Result passing between phases via context
"""
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import json
import re
import time


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class WorkflowStatus(Enum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class BaseOrchestrator(ABC):
    """Base class for all orchestration workflows with state management"""
    
    def __init__(self, agent, verbose: bool = False, 
                 on_progress: Optional[Callable[[str, float], None]] = None):
        """
        Args:
            agent: SNODEAgent instance with tools
            verbose: Whether to print debug info
            on_progress: Callback for progress updates (phase_name, percent)
        """
        self.agent = agent
        self.verbose = verbose
        self.on_progress = on_progress
        
        # Workflow state
        self.workflow_id = None
        self.status = WorkflowStatus.NOT_STARTED
        self.results = {}
        self.errors = []
        self.start_time = None
        self.end_time = None
        
        # Context for passing data between phases
        self.context = {}
        
        # Phase tracking
        self.current_phase = None
        self.phases_completed = []
        
        # Retry configuration
        self.max_retries = 2
        self.retry_delay = 2.0  # seconds
        
        # State persistence directory
        self.state_dir = Path(agent.results_dir if hasattr(agent, 'results_dir') 
                              else '/tmp') / "workflow_state"
        self.state_dir.mkdir(exist_ok=True)
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Workflow name"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Workflow description"""
        pass
    
    @abstractmethod
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the workflow"""
        pass
    
    # ─────────────────────────────────────────────────────────────────
    # State Management
    # ─────────────────────────────────────────────────────────────────
    
    def _generate_workflow_id(self, target: str) -> str:
        """Generate unique workflow ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^\w]', '_', target)
        return f"{self.name}_{safe_target}_{timestamp}"
    
    def save_state(self) -> Path:
        """Persist workflow state for recovery"""
        state = {
            "workflow_id": self.workflow_id,
            "workflow_name": self.name,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "current_phase": self.current_phase,
            "phases_completed": self.phases_completed,
            "context": self.context,
            "results": self.results,
            "errors": self.errors,
            "saved_at": datetime.now().isoformat()
        }
        
        filepath = self.state_dir / f"{self.workflow_id}.json"
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2, default=str)
        
        if self.verbose:
            print(f"  [State] Saved checkpoint: {filepath.name}")
        
        return filepath
    
    def load_state(self, workflow_id: str) -> bool:
        """Load workflow state from disk"""
        filepath = self.state_dir / f"{workflow_id}.json"
        if not filepath.exists():
            return False
        
        try:
            with open(filepath, 'r') as f:
                state = json.load(f)
            
            self.workflow_id = state["workflow_id"]
            self.status = WorkflowStatus(state["status"])
            self.start_time = datetime.fromisoformat(state["start_time"]) if state["start_time"] else None
            self.current_phase = state["current_phase"]
            self.phases_completed = state["phases_completed"]
            self.context = state["context"]
            self.results = state["results"]
            self.errors = state["errors"]
            
            if self.verbose:
                print(f"  [State] Restored from: {filepath.name}")
            return True
        except Exception as e:
            self.errors.append(f"Failed to load state: {e}")
            return False
    
    def list_resumable(self) -> List[Dict]:
        """List workflows that can be resumed"""
        resumable = []
        for state_file in self.state_dir.glob("*.json"):
            try:
                with open(state_file, 'r') as f:
                    state = json.load(f)
                if state["status"] not in ["completed", "failed"]:
                    resumable.append({
                        "workflow_id": state["workflow_id"],
                        "name": state["workflow_name"],
                        "status": state["status"],
                        "phases_completed": state["phases_completed"],
                        "saved_at": state["saved_at"]
                    })
            except:
                continue
        return resumable
    
    # ─────────────────────────────────────────────────────────────────
    # Progress Reporting
    # ─────────────────────────────────────────────────────────────────
    
    def _report_progress(self, phase: str, percent: float, message: str = ""):
        """Report progress to callback and console"""
        self.current_phase = phase
        
        if self.on_progress:
            self.on_progress(phase, percent)
        
        if self.verbose or message:
            bar_len = 20
            filled = int(bar_len * percent)
            bar = "█" * filled + "░" * (bar_len - filled)
            print(f"  [{bar}] {percent*100:.0f}% - {phase} {message}")
    
    def start_phase(self, phase_name: str, total_phases: int = 1, current: int = 1):
        """Mark the start of a new phase"""
        self.current_phase = phase_name
        percent = (current - 1) / total_phases
        self._report_progress(phase_name, percent, "starting...")
        self.save_state()
    
    def complete_phase(self, phase_name: str, total_phases: int = 1, current: int = 1):
        """Mark a phase as complete"""
        self.phases_completed.append(phase_name)
        percent = current / total_phases
        self._report_progress(phase_name, percent, "✓ complete")
        self.save_state()
    
    # ─────────────────────────────────────────────────────────────────
    # Tool Execution with Retry
    # ─────────────────────────────────────────────────────────────────
    
    def run_tool(self, tool_name: str, args: dict, retries: int = None) -> Any:
        """Run a single tool with error recovery"""
        if retries is None:
            retries = self.max_retries
            
        if tool_name not in self.agent.tool_map:
            self.errors.append(f"Tool not found: {tool_name}")
            return {"error": f"Tool not found: {tool_name}", "status": "skipped"}
        
        last_error = None
        for attempt in range(retries + 1):
            try:
                if self.verbose:
                    attempt_str = f" (attempt {attempt+1}/{retries+1})" if attempt > 0 else ""
                    print(f"  [Tool] Running {tool_name}{attempt_str}...")
                
                tool = self.agent.tool_map[tool_name]
                result = tool.invoke(args)
                
                # Check for error in result
                if isinstance(result, dict) and "error" in result:
                    raise Exception(result["error"])
                
                return result
                
            except Exception as e:
                last_error = str(e)
                if attempt < retries:
                    if self.verbose:
                        print(f"    ⚠ {tool_name} failed: {last_error}, retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay * (attempt + 1))  # Exponential backoff
                else:
                    error_msg = f"{tool_name}: {last_error}"
                    self.errors.append(error_msg)
                    return {"error": error_msg, "status": "failed"}
    
    def run_parallel(self, tools: List[str], args: dict, max_workers: int = 3) -> Dict[str, Any]:
        """Run multiple tools in parallel with shared args and retry"""
        results = {}
        
        def _run(tool_name):
            return tool_name, self.run_tool(tool_name, args)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_run, tool): tool for tool in tools}
            for future in as_completed(futures):
                tool_name, result = future.result()
                results[tool_name] = result
                
                # Report individual tool completion
                is_error = isinstance(result, dict) and "error" in result
                status = "✗" if is_error else "✓"
                if self.verbose:
                    print(f"    {status} {tool_name}")
        
        return results
    
    def run_sequential(self, tool_name: str, targets: List[str], 
                       target_key: str = "target") -> List[Dict]:
        """Run a tool sequentially across multiple targets"""
        results = []
        for i, target in enumerate(targets):
            if self.verbose:
                print(f"    [{i+1}/{len(targets)}] {target}")
            result = self.run_tool(tool_name, {target_key: target})
            results.append({"target": target, "result": result})
        return results
    
    # ─────────────────────────────────────────────────────────────────
    # Context & Result Passing
    # ─────────────────────────────────────────────────────────────────
    
    def set_context(self, key: str, value: Any):
        """Set a context value for use in later phases"""
        self.context[key] = value
        if self.verbose:
            val_preview = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
            print(f"  [Context] {key} = {val_preview}")
    
    def get_context(self, key: str, default: Any = None) -> Any:
        """Get a context value from previous phases"""
        return self.context.get(key, default)
    
    # ─────────────────────────────────────────────────────────────────
    # Result Merging
    # ─────────────────────────────────────────────────────────────────
    
    def merge_subdomains(self, results: Dict[str, Any]) -> List[str]:
        """Extract and deduplicate subdomains from multiple tool results"""
        subdomains = set()
        
        for tool_name, result in results.items():
            if isinstance(result, dict) and "subdomains" in result:
                for sub in result["subdomains"]:
                    if isinstance(sub, str):
                        subdomains.add(sub.lower().strip())
            elif isinstance(result, str):
                # Parse text format
                pattern = r'[•\-\*]\s*([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})'
                found = re.findall(pattern, result)
                for sub in found:
                    if not sub.startswith('_'):
                        subdomains.add(sub.lower().strip())
        
        return sorted(subdomains)
    
    def merge_ports(self, results: List[Dict]) -> Dict[str, List[int]]:
        """Merge port scan results by target"""
        port_map = {}
        for item in results:
            target = item.get("target")
            result = item.get("result", {})
            if isinstance(result, dict) and "ports" in result:
                port_map[target] = result["ports"]
        return port_map
    
    # ─────────────────────────────────────────────────────────────────
    # Output & Persistence
    # ─────────────────────────────────────────────────────────────────
    
    def save_results(self, output_dir: Optional[Path] = None) -> Path:
        """Save workflow results to JSON file"""
        if output_dir is None:
            output_dir = self.agent.results_dir if hasattr(self.agent, 'results_dir') else Path('/tmp')
        
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"workflow_{self.name}_{timestamp}.json"
        filepath = output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump({
                "workflow_id": self.workflow_id,
                "workflow": self.name,
                "description": self.description,
                "status": self.status.value,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "duration_seconds": (self.end_time - self.start_time).total_seconds() 
                                    if self.start_time and self.end_time else None,
                "phases_completed": self.phases_completed,
                "context": self.context,
                "results": self.results,
                "errors": self.errors,
            }, f, indent=2, default=str)
        
        return filepath
    
    def format_output(self) -> str:
        """Format results for display"""
        lines = [
            f"📋 **{self.name} Workflow Results**",
            f"   {self.description}",
            f"   Status: {self.status.value}",
            "",
        ]
        
        if self.phases_completed:
            lines.append(f"✓ Phases: {', '.join(self.phases_completed)}")
        
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
            lines.append(f"⏱️ Duration: {duration:.1f}s")
        
        if self.errors:
            lines.append(f"⚠️ Errors: {len(self.errors)}")
            for err in self.errors[:3]:
                lines.append(f"   • {err}")
            if len(self.errors) > 3:
                lines.append(f"   ... and {len(self.errors) - 3} more")
        
        return "\n".join(lines)
