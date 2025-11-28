"""
Base Agent Class for SNODE AI Multi-Agent System
Provides automatic message history management and database persistence
Based on CAI's Agent architecture
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.message_history import MessageHistoryManager
from config import MODEL_NAME, ENABLE_DATABASE


class BaseAgent:
    """
    Base class for all SNODE agents
    
    Features:
    - Automatic message history management
    - Database persistence
    - Agent handoff support
    - Phase-based execution
    """
    
    def __init__(
        self,
        name: str,
        model: Optional[str] = None,
        instructions: Optional[str] = None,
        tools: Optional[List] = None
    ):
        """
        Initialize base agent
        
        Args:
            name: Agent name (e.g., "ReconAgent")
            model: LLM model to use (defaults to config.MODEL_NAME)
            instructions: System instructions for this agent
            tools: List of tools this agent can use
        """
        self.name = name
        self.model = model or MODEL_NAME
        self.instructions = instructions or f"You are {name}, a specialized security agent."
        self.tools = tools or []
        
        # Message history management
        self.message_history = MessageHistoryManager()
        
        # Session management
        self.session_id = None
        if ENABLE_DATABASE:
            try:
                from database import ScanSessionManager
                self.session_manager = ScanSessionManager()
            except Exception as e:
                print(f"  ⚠️  Could not initialize session manager: {e}")
                self.session_manager = None
        else:
            self.session_manager = None
        
        # Agent state
        self.current_phase = 1
        self.context = {}
    
    def handoff_to(self, target_agent: 'BaseAgent', context: Optional[Dict] = None) -> None:
        """
        Handoff control to another agent with history transfer
        
        Args:
            target_agent: Target agent to handoff to
            context: Optional context to pass to target agent
        """
        # Transfer message history
        target_agent.message_history = self.message_history
        self.message_history.transfer_to_agent(self.name, target_agent.name)
        
        # Transfer context
        if context:
            target_agent.context.update(context)
        else:
            target_agent.context = self.context.copy()
        
        # Transfer session
        target_agent.session_id = self.session_id
        
        print(f"  🔄 Handoff: {self.name} → {target_agent.name}")
    
    def add_message(self, role: str, content: str, metadata: Optional[Dict] = None) -> None:
        """
        Add a message to history
        
        Args:
            role: Message role (user/assistant/system)
            content: Message content
            metadata: Optional metadata
        """
        agent_name = self.name if role == "assistant" else None
        self.message_history.add_message(
            role=role,
            content=content,
            agent_name=agent_name,
            metadata=metadata
        )
    
    def get_system_prompt(self) -> str:
        """
        Get system prompt for this agent
        
        Returns:
            System prompt string
        """
        prompt = self.instructions
        
        # Add tool information
        if self.tools:
            tool_list = "\n".join([f"- {tool.get('function', {}).get('name', 'unknown')}" 
                                   for tool in self.tools])
            prompt += f"\n\nAvailable tools:\n{tool_list}"
        
        # Add context if available
        if self.context:
            prompt += f"\n\nContext: {self.context}"
        
        return prompt
    
    def run_phase(self, phase: int, user_input: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Run a specific phase of the agent workflow
        
        Args:
            phase: Phase number (1-4)
            user_input: User input
            context: Optional context dictionary
        
        Returns:
            Result dictionary with output and optional handoff
        """
        self.current_phase = phase
        
        if context:
            self.context.update(context)
        
        # Add user message to history
        if phase == 1:  # Only add user input in first phase
            self.add_message("user", user_input)
        
        # Subclasses should override this
        raise NotImplementedError(f"{self.name} must implement run_phase()")
    
    def save_to_database(self) -> bool:
        """
        Save agent state and history to database
        
        Returns:
            True if successful
        """
        if not self.session_id:
            return False
        
        # Save message history
        success = self.message_history.save_to_database(self.session_id)
        
        # Save agent context
        if success and self.session_manager:
            try:
                self.session_manager.update_context(self.session_id, {
                    "agent_name": self.name,
                    "phase": self.current_phase,
                    "context": self.context
                })
            except Exception as e:
                print(f"  ⚠️  Failed to save agent context: {e}")
                return False
        
        return success
    
    def __repr__(self) -> str:
        return f"<{self.name}: {len(self.message_history)} messages, phase {self.current_phase}>"


if __name__ == "__main__":
    # Test the base agent
    print("🧪 Testing BaseAgent\n")
    
    # Create a test agent
    agent1 = BaseAgent(
        name="TestAgent1",
        instructions="You are a test agent"
    )
    
    # Add some messages
    agent1.add_message("user", "Test message 1")
    agent1.add_message("assistant", "Response 1")
    
    print(f"Agent 1: {agent1}")
    print(f"History: {len(agent1.message_history)} messages")
    
    # Create another agent and handoff
    agent2 = BaseAgent(
        name="TestAgent2",
        instructions="You are another test agent"
    )
    
    agent1.handoff_to(agent2, context={"test": "data"})
    
    print(f"\nAfter handoff:")
    print(f"Agent 2: {agent2}")
    print(f"History: {len(agent2.message_history)} messages")
    print(f"Context: {agent2.context}")
    
    print(f"\n✅ BaseAgent test complete!")
