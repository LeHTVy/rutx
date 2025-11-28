"""
FlagAgent - CTF Flag Extraction Specialist for SNODE AI
Handles flag finding, report generation, and final analysis
"""

from typing import Dict, Any, Optional
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_sdk.base_agent import BaseAgent
from tools import ALL_TOOLS


class FlagAgent(BaseAgent):
    """
    CTF flag extraction specialist agent
    
    Responsibilities:
    - Extract flags from vulnerabilities
    - Generate comprehensive reports
    - Final security analysis
    - CTF completion
    
    This is the final agent in the chain
    """
    
    def __init__(self):
        # Flag agent doesn't need many tools - focuses on analysis
        super().__init__(
            name="FlagAgent",
            instructions="""You are FlagAgent, a CTF flag extraction and reporting specialist.

Your responsibilities:
1. Analyze vulnerability scan results for potential flags
2. Extract any CTF flags found
3. Generate comprehensive security reports
4. Provide final recommendations

Execute Phase 3 (Analysis) and Phase 4 (Report).
This is the final agent - you produce the final output.""",
            tools=[]  # No tools needed, pure analysis
        )
    
    def run_phase(self, phase: int, user_input: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Execute flag extraction phase
        
        Phase 3: Flag analysis
        Phase 4: Final report
        """
        from config import OLLAMA_ENDPOINT, MODEL_NAME, TIMEOUT_OLLAMA
        import requests
        
        context = context or {}
        
        if phase == 3:
            # Phase 3: Analyze for flags
            self.add_message("system", "Phase 3: Analyzing for CTF flags")
            
            # Get all results from context
            recon_results = context.get("recon_results", [])
            vuln_results = context.get("vuln_results", [])
            exploit_analysis = context.get("exploit_analysis", "No analysis")
            
            # Build comprehensive context
            full_context = f"""
RECONNAISSANCE RESULTS:
{len(recon_results)} tools executed

VULNERABILITY SCAN RESULTS:
{len(vuln_results)} targets scanned

EXPLOITATION ANALYSIS:
{exploit_analysis}
"""
            
            self.add_message("system", full_context)
            
            # Use LLM to find flags
            system_prompt = self.get_system_prompt()
            messages = self.message_history.get_history_for_llm()
            
            messages.append({
                "role": "user",
                "content": "Analyze all the scan results and look for any CTF flags (format: flag{...} or similar). List any flags found and potential locations for flags."
            })
            
            try:
                response = requests.post(
                    OLLAMA_ENDPOINT,
                    json={
                        "model": MODEL_NAME,
                        "messages": messages,
                        "stream": False
                    },
                    timeout=TIMEOUT_OLLAMA
                )
                
                if response.status_code == 200:
                    result = response.json()
                    flag_analysis = result.get("message", {}).get("content", "No flags found")
                    
                    self.add_message("assistant", flag_analysis)
                    context["flag_analysis"] = flag_analysis
                
            except Exception as e:
                print(f"  ⚠️  Flag analysis failed: {e}")
                context["flag_analysis"] = "Analysis failed"
            
            context["completed_phases"] = context.get("completed_phases", []) + [3]
            
            # Move to phase 4
            self.current_phase = 4
            return {"context": context}
        
        elif phase == 4:
            # Phase 4: Generate final report
            self.add_message("system", "Phase 4: Generating final report")
            
            # Compile comprehensive report
            recon_count = len(context.get("recon_results", []))
            vuln_count = len(context.get("vuln_results", []))
            flag_analysis = context.get("flag_analysis", "No flags found")
            completed_phases = context.get("completed_phases", [])
            
            report = f"""
═══════════════════════════════════════════════════════════
SNODE AI - COMPREHENSIVE SECURITY ASSESSMENT REPORT
═══════════════════════════════════════════════════════════

## EXECUTION SUMMARY

**Phases Completed:** {', '.join(map(str, completed_phases))}

**Agents Involved:**
1. ReconAgent - Subdomain enumeration & port scanning
2. ExploitAgent - Vulnerability assessment
3. FlagAgent - Flag extraction & reporting

## RECONNAISSANCE

**Tools Executed:** {recon_count}
**Scope:** Domain enumeration, port scanning, OSINT

## VULNERABILITY ASSESSMENT

**Targets Scanned:** {vuln_count}
**Scan Type:** Nmap vulnerability scripts

## CTF FLAG ANALYSIS

{flag_analysis}

## RECOMMENDATIONS

Based on the multi-agent assessment:
1. Review all CRITICAL findings from vulnerability scans
2. Patch identified vulnerabilities
3. Secure exposed services discovered during recon
4. Implement proper access controls

═══════════════════════════════════════════════════════════
Report generated by FlagAgent (Final Agent)
═══════════════════════════════════════════════════════════
"""
            
            self.add_message("assistant", report)
            context["final_report"] = report
            context["completed_phases"] = context.get("completed_phases", []) + [4]
            
            # This is the final output
            return {
                "final_output": report,
                "context": context
            }
        
        else:
            raise ValueError(f"FlagAgent does not handle phase {phase}")


if __name__ == "__main__":
    # Test FlagAgent
    print("🧪 Testing FlagAgent\\n")
    
    agent = FlagAgent()
    print(f"Agent: {agent}")
    print(f"Instructions: {agent.instructions[:100]}...")
    
    print(f"\\n✅ FlagAgent initialized successfully!")
