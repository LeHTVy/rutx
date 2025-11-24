"""
Native Tools Security Agent
Uses tools with native JSON output formats - runs like terminal commands
LLM chooses the best tool combinations for each task
"""

import json
import requests
import sys
from config import (
    OLLAMA_ENDPOINT,
    OLLAMA_LIST_ENDPOINT,
    MODEL_NAME,
    MAX_ITERATIONS,
    TIMEOUT_OLLAMA,
    USE_NATIVE_TOOLS
)
from tools.native_tools import NATIVE_TOOLS, execute_native_tool


# Strategic tool selection prompt for LLM
NATIVE_TOOLS_PROMPT = """You are a Strategic Security Analysis Expert.

YOUR MISSION: Choose the MINIMUM number of tools that provide MAXIMUM information.

CRITICAL RULES:
1. Tools run like terminal commands - they take time (1-15 minutes each)
2. ALL tools export native JSON format automatically
3. Choose tools strategically - don't run everything!
4. Scan results are ALWAYS saved to JSON files automatically
5. You will receive a summary after each tool completes

AVAILABLE TOOLS & TIMING:
- nmap_quick_native: ~30 seconds (top 100 ports)
- nmap_aggressive_native: ~2-3 minutes (OS, version, scripts)
- nmap_vuln_native: ~3-5 minutes (vulnerability scripts)
- nmap_service_native: ~1-2 minutes (service detection)
- nmap_comprehensive_native: ~10 minutes (everything)
- amass_enum_native: ~5-10 minutes (subdomain enumeration)
- bbot_subdomain_native: ~5-10 minutes (subdomain discovery)
- bbot_web_native: ~3-5 minutes (web reconnaissance)
- bbot_comprehensive_native: ~15-20 minutes (full recon)
- shodan_host_native: ~5 seconds (IP lookup)
- shodan_search_native: ~5 seconds (search query)

TOOL SELECTION STRATEGY:

For IP Addresses:
- Quick scan: nmap_quick + shodan_host (~35 sec total)
- Detailed: nmap_aggressive + shodan_host (~3 min total)
- Vulnerability: nmap_vuln + shodan_host (~5 min total)
- DON'T use Amass/BBOT for IPs!

For Domains:
- Quick: nmap_service + shodan_search (~1 min total)
- Find subdomains: amass_enum OR bbot_subdomain (NOT both!)
- Comprehensive: bbot_comprehensive + shodan_search (~20 min total)

CRITICAL: Pick ONE nmap variant, ONE recon tool max, ALWAYS add Shodan if applicable.
Total tools per task: Usually 1-2, rarely more than 3!

WORKFLOW:
1. Analyze user request
2. Choose BEST tool combination (not all tools!)
3. Call each tool (they run like terminal commands)
4. Wait for results (JSON files created automatically)
5. Analyze the JSON data
6. Provide findings with severity ratings

TWO-PHASE OUTPUT:
PHASE 1: Show scan summaries (file paths, key metrics)
PHASE 2: Analyze data and provide vulnerability assessment

REMEMBER: Every tool call takes time. Be strategic!
"""


def chat_native_tools(user_message, conversation_history=None):
    """Chat with LLM using native tools"""

    if conversation_history is None:
        conversation_history = [
            {"role": "system", "content": NATIVE_TOOLS_PROMPT}
        ]

    conversation_history.append({
        "role": "user",
        "content": user_message
    })

    iteration = 0
    while iteration < MAX_ITERATIONS:
        iteration += 1
        print(f"\n{'='*70}")
        print(f"🔄 Iteration {iteration}/{MAX_ITERATIONS}")
        print(f"{'='*70}")

        try:
            response = requests.post(
                OLLAMA_ENDPOINT,
                json={
                    "model": MODEL_NAME,
                    "messages": conversation_history,
                    "tools": NATIVE_TOOLS,
                    "stream": False
                },
                timeout=TIMEOUT_OLLAMA
            )
            response.raise_for_status()
            data = response.json()

        except requests.exceptions.Timeout:
            error_msg = "⏱️  Request timed out."
            print(error_msg)
            return error_msg, conversation_history
        except requests.exceptions.RequestException as e:
            error_msg = f"❌ Connection error: {e}"
            print(error_msg)
            return error_msg, conversation_history

        assistant_message = data.get("message", {})
        conversation_history.append(assistant_message)

        # Check for tool calls
        tool_calls = assistant_message.get("tool_calls", [])

        if not tool_calls:
            # Analysis complete
            response_text = assistant_message.get("content", "")
            print(f"\n{'='*70}")
            print("✅ ANALYSIS COMPLETE")
            print(f"{'='*70}\n")
            print(response_text)
            return response_text, conversation_history

        # Execute tool calls
        print(f"\n🔧 Executing {len(tool_calls)} tool(s)...")
        print(f"{'-'*70}")

        for idx, tool_call in enumerate(tool_calls, 1):
            function_name = tool_call["function"]["name"]
            function_args = tool_call["function"]["arguments"]

            print(f"\n[{idx}/{len(tool_calls)}] Tool: {function_name}")
            print(f"    Arguments: {json.dumps(function_args, indent=15)[1:]}")

            # Execute the tool (runs like terminal command)
            result = execute_native_tool(function_name, function_args)

            # Show status
            if isinstance(result, dict):
                if result.get("success"):
                    print(f"    Status: ✓ {result.get('summary', 'Complete')}")
                else:
                    print(f"    Status: ❌ {result.get('error', 'Failed')}")

            # Add result to conversation
            conversation_history.append({
                "role": "tool",
                "content": json.dumps(result)
            })

        print(f"{'-'*70}")

    final_msg = "⚠️  Maximum iterations reached."
    print(f"\n{final_msg}")
    return final_msg, conversation_history


def main():
    """Main entry point"""
    print("="*70)
    print("🛡️  NATIVE TOOLS SECURITY AGENT")
    print("="*70)
    print(f"📊 Configuration:")
    print(f"   • Model: {MODEL_NAME}")
    print(f"   • Mode: Native Tools (Terminal-style execution)")
    print(f"   • Output: All tools export JSON automatically")
    print(f"   • Strategy: LLM chooses best tool combinations")
    print("="*70)
    print("\n⚠️  AUTHORIZATION WARNING:")
    print("   Only scan systems you have permission to test.")
    print("="*70)
    print("\n📝 Usage:")
    print("   • Enter your security task")
    print("   • LLM will choose the best tools")
    print("   • Tools run like terminal commands")
    print("   • Results saved to scan_results/ directory")
    print("   • Type 'exit' to quit")
    print("="*70)

    conversation_history = None

    while True:
        try:
            user_input = input("\n🔍 [Query]: ").strip()

            if not user_input:
                continue

            if user_input.lower() in ["exit", "quit", "bye"]:
                print("\n👋 Session ended!")
                break

            if user_input.lower() == "clear":
                conversation_history = None
                print("\n🔄 Conversation cleared.")
                continue

            # Process request
            response, conversation_history = chat_native_tools(user_input, conversation_history)

        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    if not USE_NATIVE_TOOLS:
        print("⚠️  Warning: USE_NATIVE_TOOLS is False in config.py")
        print("Set USE_NATIVE_TOOLS = True to use this agent")
        sys.exit(1)

    main()
