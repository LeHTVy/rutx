"""
ReconAgent - Reconnaissance Specialist for SNODE AI
Handles subdomain enumeration, port scanning, and OSINT
"""

from typing import Dict, Any, Optional
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_sdk.base_agent import BaseAgent
from tools import ALL_TOOLS


class ReconAgent(BaseAgent):
    """
    Reconnaissance specialist agent
    
    Responsibilities:
    - Subdomain enumeration (amass, bbot)
    - Port scanning (nmap)
    - OSINT gathering (shodan)
    - Initial attack surface mapping
    
    Hands off to ExploitAgent after recon complete
    """
    
    def __init__(self):
        # Filter tools relevant to recon
        recon_tools = [
            tool for tool in ALL_TOOLS
            if any(keyword in tool['function']['name'].lower() 
                   for keyword in ['amass', 'bbot', 'nmap', 'shodan', 'masscan'])
        ]
        
        super().__init__(
            name="ReconAgent",
            instructions="""You are ReconAgent, a reconnaissance specialist for penetration testing.

Your responsibilities:
1. Subdomain enumeration using amass and bbot
2. Port scanning using nmap and masscan
3. OSINT gathering using Shodan
4. Identify high-value targets (api, admin, dev subdomains)

Execute Phase 1 (Tool Selection) and Phase 2 (Execution).
After completing reconnaissance, handoff to ExploitAgent with findings.""",
            tools=recon_tools
        )
    
    def run_phase(self, phase: int, user_input: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Execute reconnaissance phase
        
        Phase 1: Tool selection
        Phase 2: Execution
        """
        from tools import execute_tool
        from config import OLLAMA_ENDPOINT, MODEL_NAME, TIMEOUT_OLLAMA
        import requests
        
        context = context or {}
        
        if phase == 1:
            # Phase 1: Tool Selection
            self.add_message("system", f"Phase 1: Tool Selection for reconnaissance")
            
            # Use LLM to select appropriate tools
            system_prompt = self.get_system_prompt()
            messages = self.message_history.get_history_for_llm()
            
            # Add system prompt if not already there
            if not messages or messages[0].get("role") != "system":
                messages.insert(0, {"role": "system", "content": system_prompt})
            
            # Call LLM for tool selection
            try:
                response = requests.post(
                    OLLAMA_ENDPOINT,
                    json={
                        "model": MODEL_NAME,
                        "messages": messages,
                        "tools": self.tools,
                        "stream": False
                    },
                    timeout=TIMEOUT_OLLAMA
                )
                
                if response.status_code == 200:
                    result = response.json()
                    tool_calls = result.get("message", {}).get("tool_calls", [])
                    
                    if tool_calls:
                        # Store selected tools in context
                        context["selected_tools"] = tool_calls
                        context["completed_phases"] = [1]
                        
                        self.add_message("assistant", 
                                       f"Selected {len(tool_calls)} reconnaissance tools")
                        
                        # Move to phase 2
                        self.current_phase = 2
                        return {"context": context}
                    else:
                        self.add_message("assistant", "No tools selected, using default reconnaissance tools")
                        # Default to subdomain enum + port scan
                        context["selected_tools"] = [
                            {"function": {"name": "amass_enum", "arguments": {"domain": user_input}}},
                            {"function": {"name": "nmap_quick_scan", "arguments": {"target": user_input}}}
                        ]
                        context["completed_phases"] = [1]
                        self.current_phase = 2
                        return {"context": context}
                
            except Exception as e:
                print(f"  ⚠️  LLM tool selection failed: {e}")
                # Fallback to default tools
                context["selected_tools"] = [
                    {"function": {"name": "amass_enum", "arguments": {"domain": user_input}}}
                ]
                context["completed_phases"] = [1]
                self.current_phase = 2
                return {"context": context}
        
        elif phase == 2:
            # Phase 2: Execute reconnaissance tools
            self.add_message("system", "Phase 2: Executing reconnaissance")
            
            selected_tools = context.get("selected_tools", [])
            results = []
            
            for tool_call in selected_tools:
                function_name = tool_call.get("function", {}).get("name")
                arguments = tool_call.get("function", {}).get("arguments", {})
                
                print(f"  🔍 Executing: {function_name}")
                
                try:
                    result = execute_tool(function_name, arguments)
                    results.append({
                        "tool": function_name,
                        "result": result
                    })
                except Exception as e:
                    print(f"  ⚠️  Tool execution failed: {e}")
                    results.append({
                        "tool": function_name,
                        "error": str(e)
                    })
            
            # Store results
            context["recon_results"] = results
            context["completed_phases"] = context.get("completed_phases", []) + [2]
            
            self.add_message("assistant", 
                           f"Reconnaissance complete. Executed {len(results)} tools.")
            
            # Check if we should handoff to ExploitAgent
            from agent_sdk.exploit_agent import ExploitAgent
            
            next_agent = ExploitAgent()
            
            return {
                "handoff_to": next_agent,
                "handoff_context": context,
                "message": "Reconnaissance complete, handing off to ExploitAgent"
            }
        
        else:
            # Invalid phase for ReconAgent
            raise ValueError(f"ReconAgent does not handle phase {phase}")


if __name__ == "__main__":
    # Test ReconAgent
    print("🧪 Testing ReconAgent\n")
    
    agent = ReconAgent()
    print(f"Agent: {agent}")
    print(f"Tools: {len(agent.tools)} recon tools available")
    
    # Show some tools
    for tool in agent.tools[:3]:
        print(f"  - {tool['function']['name']}")
    
    print(f"\n✅ ReconAgent initialized successfully!")
