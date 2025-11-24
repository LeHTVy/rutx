"""
SNODE AI - Security Node Agent
3-Phase Iteration System for Penetration Testing

Phase 1: Tool Selection (BlackBox) - LLM chooses appropriate tools
Phase 2: Execution & Storage - Run tools and save results to database
Phase 3: Analysis & Report - Analyze vulnerabilities and generate report
"""

import json
import requests
import sys
import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    OLLAMA_ENDPOINT,
    MODEL_NAME,
    TIMEOUT_OLLAMA,
    ENABLE_DATABASE
)
from tools import ALL_TOOLS, execute_tool, get_all_tool_names
from database import save_scan_result, get_llm_context, query_database
from prompts import get_phase1_prompt, get_phase3_prompt, get_phase4_prompt


class IterationPhase:
    """Enumeration for iteration phases"""
    TOOL_SELECTION = 1
    EXECUTION = 2
    ANALYSIS = 3
    COMBINE_ANALYSIS = 4  # For subdomain scans with multiple tools


class SNODEAgent:
    """
    SNODE AI Agent - 3-Phase Security Scanning System
    """

    def __init__(self, model: str = None):
        self.model = model or MODEL_NAME
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.conversation_history = []
        self.scan_results = []
        self.current_phase = IterationPhase.TOOL_SELECTION
        self.is_subdomain_scan = False  # Track if this is a subdomain enumeration scan

    def _call_ollama(
        self,
        messages: List[Dict],
        tools: List[Dict] = None,
        timeout: int = None
    ) -> Dict[str, Any]:
        """Call Ollama API"""
        if timeout is None:
            timeout = TIMEOUT_OLLAMA

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False
        }

        if tools:
            payload["tools"] = tools

        try:
            response = requests.post(
                OLLAMA_ENDPOINT,
                json=payload,
                timeout=timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def _get_tool_list_string(self) -> str:
        """Get formatted list of available tools"""
        lines = []
        for tool in ALL_TOOLS:
            name = tool['function']['name']
            desc = tool['function'].get('description', '')[:80]
            lines.append(f"  - {name}: {desc}")
        return "\n".join(lines)

    def _detect_subdomain_scan(self, user_prompt: str) -> bool:
        """Detect if user is requesting subdomain enumeration"""
        subdomain_keywords = [
            'subdomain', 'subdomains', 'sub-domain', 'sub-domains',
            'enumerate domain', 'domain enumeration', 'find subdomains',
            'discover subdomains', 'subdomain discovery', 'recon domain'
        ]
        prompt_lower = user_prompt.lower()
        return any(keyword in prompt_lower for keyword in subdomain_keywords)

    def _extract_domain_from_prompt(self, user_prompt: str) -> Optional[str]:
        """Extract domain from user prompt"""
        import re
        # Match common domain patterns
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        matches = re.findall(domain_pattern, user_prompt)
        return matches[0] if matches else None

    def _get_subdomain_tools(self, domain: str) -> List[Dict]:
        """Get both amass and bbot tools for subdomain enumeration"""
        return [
            {
                "name": "amass_enum",
                "arguments": {"domain": domain, "passive": True, "timeout": 1800}
            },
            {
                "name": "bbot_subdomain_enum",
                "arguments": {"target": domain, "timeout": 1800}
            }
        ]

    def phase_1_tool_selection(self, user_prompt: str) -> Tuple[List[Dict], str]:
        """
        Phase 1: BlackBox Tool Selection
        LLM analyzes user request and selects appropriate tools

        Special handling: If subdomain enumeration detected, auto-select amass + bbot

        Returns:
            Tuple of (selected_tools, reasoning)
        """
        print("\n" + "="*60)
        print("📦 PHASE 1: TOOL SELECTION")
        print("="*60)

        # Check for subdomain enumeration request
        if self._detect_subdomain_scan(user_prompt):
            domain = self._extract_domain_from_prompt(user_prompt)
            if domain:
                self.is_subdomain_scan = True
                selected_tools = self._get_subdomain_tools(domain)
                reasoning = f"Subdomain enumeration detected. Using both Amass and BBOT for comprehensive coverage on {domain}."
                print(f"  🔍 Subdomain scan detected for: {domain}")
                print(f"  ✓ Selected: amass_enum (passive mode)")
                print(f"  ✓ Selected: bbot_subdomain_enum")
                return selected_tools, reasoning

        system_prompt = get_phase1_prompt(self._get_tool_list_string())

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        response = self._call_ollama(messages, tools=ALL_TOOLS)

        if "error" in response:
            return [], f"Error: {response['error']}"

        message = response.get("message", {})
        tool_calls = message.get("tool_calls", [])
        reasoning = message.get("content", "")

        selected_tools = []
        for call in tool_calls:
            tool_info = {
                "name": call.get("function", {}).get("name"),
                "arguments": call.get("function", {}).get("arguments", {})
            }
            selected_tools.append(tool_info)
            print(f"  ✓ Selected: {tool_info['name']}")

        if not selected_tools and reasoning:
            print(f"  ℹ️  {reasoning[:100]}...")

        return selected_tools, reasoning

    def phase_2_execution(self, selected_tools: List[Dict]) -> List[Dict]:
        """
        Phase 2: Execute Tools & Store Results
        Run each selected tool and save to database

        Returns:
            List of execution results
        """
        print("\n" + "="*60)
        print("⚙️  PHASE 2: EXECUTION & STORAGE")
        print("="*60)

        results = []

        for i, tool in enumerate(selected_tools, 1):
            tool_name = tool["name"]
            tool_args = tool["arguments"]

            print(f"\n[{i}/{len(selected_tools)}] Running: {tool_name}")
            print(f"    Args: {json.dumps(tool_args, indent=2)[:100]}...")

            # Execute the tool
            try:
                result = execute_tool(tool_name, tool_args)

                if isinstance(result, str):
                    try:
                        result = json.loads(result)
                    except:
                        result = {"output": result}

                # Save to database if enabled
                if ENABLE_DATABASE and result.get("success"):
                    output_file = (
                        result.get("output_xml") or
                        result.get("output_json") or
                        result.get("json_output_file")
                    )

                    if output_file:
                        target = tool_args.get("target") or tool_args.get("domain") or tool_args.get("ip", "unknown")
                        db_result = save_scan_result(
                            tool=tool_name.split("_")[0],  # Extract tool name
                            target=target,
                            output_file=output_file,
                            scan_profile=tool_name,
                            elapsed_seconds=result.get("elapsed_seconds", 0),
                            session_id=self.session_id
                        )
                        result["database"] = db_result
                        print(f"    💾 Saved to database: {db_result.get('scan_id', 'N/A')}")

                results.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": result
                })

                if result.get("success"):
                    print(f"    ✅ Success")
                else:
                    print(f"    ⚠️  {result.get('error', 'Unknown error')}")

            except Exception as e:
                print(f"    ❌ Error: {e}")
                results.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": {"error": str(e)}
                })

        self.scan_results = results
        return results

    def phase_3_analysis(self, scan_results: List[Dict]) -> str:
        """
        Phase 3: Analyze & Generate Report
        LLM analyzes results and generates vulnerability report

        Returns:
            Analysis report string
        """
        print("\n" + "="*60)
        print("📊 PHASE 3: ANALYSIS & REPORT")
        print("="*60)

        # Prepare scan results for LLM
        results_summary = []
        for r in scan_results:
            summary = {
                "tool": r["tool"],
                "success": r["result"].get("success", False),
                "summary": r["result"].get("summary", ""),
                "findings": r["result"].get("findings_count", 0),
                "hosts": r["result"].get("hosts_discovered", 0),
                "ports": r["result"].get("open_ports_count", 0),
                "subdomains": r["result"].get("subdomains_found", 0)
            }

            # Include port details if available
            if r["result"].get("ports_detail"):
                summary["ports_detail"] = r["result"]["ports_detail"][:10]

            # Include subdomains if available
            if r["result"].get("subdomains"):
                summary["subdomains_list"] = r["result"]["subdomains"][:20]

            results_summary.append(summary)

        # Get database context if available
        db_context = {}
        if ENABLE_DATABASE:
            try:
                db_context = query_database("stats")
            except:
                db_context = {"note": "Database query unavailable"}

        system_prompt = get_phase3_prompt(
            json.dumps(results_summary, indent=2),
            json.dumps(db_context, indent=2)
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Analyze the scan results and provide a comprehensive security report."}
        ]

        print("\n🔍 Analyzing results...")

        # Use config timeout (TIMEOUT_OLLAMA) for LLM analysis
        response = self._call_ollama(messages, timeout=TIMEOUT_OLLAMA)

        if "error" in response:
            return f"Analysis Error: {response['error']}"

        analysis = response.get("message", {}).get("content", "No analysis generated")

        return analysis

    def phase_4_combine_analysis(self, scan_results: List[Dict]) -> str:
        """
        Phase 4: Combine & Analyze Multi-Tool Results
        Used for subdomain scans with Amass + BBOT

        Returns:
            Combined analysis report string
        """
        print("\n" + "="*60)
        print("🔄 PHASE 4: COMBINING RESULTS & ANALYSIS")
        print("="*60)

        # Collect all subdomains from both tools
        combined_data = {
            "tools_used": [],
            "amass_subdomains": [],
            "bbot_subdomains": [],
            "all_subdomains": set()
        }

        for r in scan_results:
            tool_name = r["tool"]
            result = r["result"]

            if result.get("success"):
                combined_data["tools_used"].append(tool_name)
                subdomains = result.get("subdomains", [])

                if "amass" in tool_name.lower():
                    combined_data["amass_subdomains"] = subdomains
                    combined_data["all_subdomains"].update(subdomains)
                    print(f"  📥 Amass found: {len(subdomains)} subdomains")
                elif "bbot" in tool_name.lower():
                    combined_data["bbot_subdomains"] = subdomains
                    combined_data["all_subdomains"].update(subdomains)
                    print(f"  📥 BBOT found: {len(subdomains)} subdomains")

        # Calculate overlap
        amass_set = set(combined_data["amass_subdomains"])
        bbot_set = set(combined_data["bbot_subdomains"])
        overlap = amass_set.intersection(bbot_set)

        # Prepare summary for LLM
        combined_summary = {
            "total_unique": len(combined_data["all_subdomains"]),
            "amass_count": len(amass_set),
            "bbot_count": len(bbot_set),
            "overlap_count": len(overlap),
            "unique_to_amass": len(amass_set - bbot_set),
            "unique_to_bbot": len(bbot_set - amass_set),
            "all_subdomains": sorted(list(combined_data["all_subdomains"]))[:100],  # Limit for LLM
            "overlap_subdomains": sorted(list(overlap))[:50]
        }

        print(f"\n  📊 Total unique subdomains: {combined_summary['total_unique']}")
        print(f"  📊 Overlap (found by both): {combined_summary['overlap_count']}")

        system_prompt = get_phase4_prompt(
            json.dumps(combined_summary, indent=2),
            len(combined_data["tools_used"])
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Combine and analyze the subdomain enumeration results from both tools."}
        ]

        print("\n🔍 Analyzing combined results...")

        response = self._call_ollama(messages, timeout=TIMEOUT_OLLAMA)

        if "error" in response:
            return f"Analysis Error: {response['error']}"

        analysis = response.get("message", {}).get("content", "No analysis generated")

        return analysis

    def run(self, user_prompt: str) -> Dict[str, Any]:
        """
        Execute full scan cycle (3-phase or 4-phase for subdomain scans)

        Args:
            user_prompt: User's natural language request

        Returns:
            Complete results including tools, execution, and analysis
        """
        start_time = datetime.now()

        # Phase 1: Tool Selection
        self.current_phase = IterationPhase.TOOL_SELECTION
        selected_tools, reasoning = self.phase_1_tool_selection(user_prompt)

        if not selected_tools:
            return {
                "success": False,
                "phase": 1,
                "error": "No tools selected",
                "reasoning": reasoning
            }

        # Phase 2: Execution
        self.current_phase = IterationPhase.EXECUTION
        execution_results = self.phase_2_execution(selected_tools)

        # Phase 3 or Phase 4 based on scan type
        if self.is_subdomain_scan:
            # Phase 4: Combined analysis for subdomain scans (Amass + BBOT)
            self.current_phase = IterationPhase.COMBINE_ANALYSIS
            analysis_report = self.phase_4_combine_analysis(execution_results)
            phase_key = "phase_4_combined_analysis"
        else:
            # Phase 3: Standard analysis
            self.current_phase = IterationPhase.ANALYSIS
            analysis_report = self.phase_3_analysis(execution_results)
            phase_key = "phase_3_analysis"

        elapsed = (datetime.now() - start_time).total_seconds()

        result = {
            "success": True,
            "session_id": self.session_id,
            "user_prompt": user_prompt,
            "elapsed_seconds": round(elapsed, 2),
            "is_subdomain_scan": self.is_subdomain_scan,
            "phases": {
                "phase_1_tools": selected_tools,
                "phase_2_results": [
                    {
                        "tool": r["tool"],
                        "success": r["result"].get("success", False),
                        "summary": r["result"].get("summary", "")
                    }
                    for r in execution_results
                ],
                phase_key: analysis_report
            }
        }

        return result


def _get_analysis_from_result(result: Dict) -> str:
    """Extract analysis report from result (handles both phase 3 and 4)"""
    phases = result.get("phases", {})
    return phases.get("phase_4_combined_analysis") or phases.get("phase_3_analysis", "No analysis available")


def main():
    """Simple command-line interface for testing"""
    agent = SNODEAgent()

    print("\n" + "="*60)
    print("  SNODE AI - Security Node Agent")
    print("  3/4-Phase Penetration Testing System")
    print("="*60)

    if len(sys.argv) > 1:
        # Command line mode
        prompt = " ".join(sys.argv[1:])
        result = agent.run(prompt)
        print("\n" + _get_analysis_from_result(result))
    else:
        # Interactive mode
        print("\nEnter your security objective (or 'quit' to exit):\n")

        while True:
            try:
                prompt = input("SNODE> ").strip()

                if prompt.lower() in ['quit', 'exit', 'q']:
                    print("\nGoodbye!")
                    break

                if not prompt:
                    continue

                result = agent.run(prompt)

                print("\n" + "="*60)
                print("📋 FINAL REPORT")
                print("="*60)
                print(_get_analysis_from_result(result))
                print("\n" + "="*60)
                scan_type = "Subdomain Scan (4-Phase)" if result.get("is_subdomain_scan") else "Standard Scan (3-Phase)"
                print(f"Session: {result['session_id']} | Type: {scan_type} | Time: {result['elapsed_seconds']}s")
                print("="*60 + "\n")

            except KeyboardInterrupt:
                print("\n\nInterrupted. Goodbye!")
                break
            except Exception as e:
                print(f"\nError: {e}")


if __name__ == "__main__":
    main()
