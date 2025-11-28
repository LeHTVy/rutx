"""
Agent Runner for SNODE AI
Executes agents with automatic handoffs and max_turns control
Based on CAI's Runner class
"""

from typing import Dict, Any, Optional
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_sdk.base_agent import BaseAgent

# Try to import MAX_TURNS from config, default to 15
try:
    from config import MAX_TURNS
    DEFAULT_MAX_TURNS = MAX_TURNS
except (ImportError, AttributeError):
    DEFAULT_MAX_TURNS = 15


class MaxTurnsExceeded(Exception):
    """Raised when max_turns limit is exceeded"""
    pass


class AgentRunner:
    """
    Runs agents with automatic handoffs and turn management
    
    Features:
    - max_turns limit
    - Automatic handoff detection
    - Message history management
    - Database persistence
    """
    
    def __init__(self, max_turns: int = 15):
        """
        Initialize agent runner
        
        Args:
            max_turns: Maximum number of turns before raising exception
        """
        self.max_turns = max_turns
        self.current_turn = 0
        self.current_agent: Optional[BaseAgent] = None
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def run(
        self,
        starting_agent: BaseAgent,
        user_input: str,
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Run agent loop with automatic handoffs
        
        Args:
            starting_agent: Initial agent to run
            user_input: User's input
            context: Optional context dictionary
        
        Returns:
            Final result dictionary
        
        Raises:
            MaxTurnsExceeded: If max_turns is exceeded
        """
        self.current_agent = starting_agent
        self.current_turn = 0
        self.current_agent.session_id = self.session_id
        
        print(f"\n🚀 Starting agent run")
        print(f"   Agent: {self.current_agent.name}")
        print(f"   Max turns: {self.max_turns}\n")
        
        # Main agent loop
        while self.current_turn < self.max_turns:
            self.current_turn += 1
            
            print(f"Turn {self.current_turn}/{self.max_turns}: {self.current_agent.name}")
            
            try:
                # Run current agent's phase
                result = self.current_agent.run_phase(
                    phase=self._determine_phase(),
                    user_input=user_input,
                    context=context or {}
                )
                
                # Save to database after each turn
                if hasattr(self.current_agent, 'save_to_database'):
                    self.current_agent.save_to_database()
                
                # Check for handoff
                if result.get("handoff_to"):
                    next_agent: BaseAgent = result["handoff_to"]
                    handoff_context = result.get("handoff_context", {})
                    
                    print(f"  🔄 Handoff detected: {self.current_agent.name} → {next_agent.name}")
                    
                    # Perform handoff
                    self.current_agent.handoff_to(next_agent, handoff_context)
                    self.current_agent = next_agent
                    
                    # Reset user_input for next agent (they have history)
                    user_input = ""
                    continue
                
                # Check for final output
                if result.get("final_output"):
                    print(f"\n✅ Agent run complete in {self.current_turn} turns")
                    return {
                        "success": True,
                        "final_output": result["final_output"],
                        "total_turns": self.current_turn,
                        "session_id": self.session_id,
                        "final_agent": self.current_agent.name
                    }
                
                # Continue with same agent (next phase)
                context = result.get("context", context)
                
            except NotImplementedError as e:
                print(f"  ⚠️  Agent {self.current_agent.name} not fully implemented: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "total_turns": self.current_turn
                }
            
            except Exception as e:
                print(f"  ❌ Error in agent run: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "total_turns": self.current_turn
                }
        
        # Max turns exceeded
        raise MaxTurnsExceeded(
            f"Max turns ({self.max_turns}) exceeded. "
            f"Current agent: {self.current_agent.name}"
        )
    
    def _determine_phase(self) -> int:
        """
        Determine which phase to run based on current state
        
        Returns:
            Phase number (1-4)
        """
        # Simple logic: increment phase each turn for same agent
        # Subclasses can override this
        return min(self.current_agent.current_phase, 4)


if __name__ == "__main__":
    # Test the agent runner
    print("🧪 Testing AgentRunner\n")
    
    # Create a mock agent
    class MockAgent(BaseAgent):
        def __init__(self, name: str):
            super().__init__(name=name)
            self.calls = 0
        
        def run_phase(self, phase: int, user_input: str, context: Optional[Dict] = None):
            self.calls += 1
            self.add_message("assistant", f"Phase {phase} response from {self.name}")
            
            if self.calls >= 2:
                return {"final_output": f"Done from {self.name}!"}
            
            return {"context": context}
    
    # Test runner
    runner = AgentRunner(max_turns=10)
    agent = MockAgent("TestAgent")
    
    try:
        result = runner.run(
            starting_agent=agent,
            user_input="Test input"
        )
        print(f"\n✅ Result: {result}")
    except MaxTurnsExceeded as e:
        print(f"\n⚠️  {e}")
    
    print(f"\n✅ AgentRunner test complete!")
