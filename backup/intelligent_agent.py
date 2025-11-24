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


def check_model_available():
    """Check if the Ollama model has been pulled."""
    try:
        response = requests.get(OLLAMA_LIST_ENDPOINT, timeout=5)
        response.raise_for_status()
        data = response.json()
        models = [model['name'] for model in data.get('models', [])]
        return MODEL_NAME in models, models
    except:
        return False, []


def interactive_mode():
    """Run the agent in interactive mode"""
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
    print("   • Type 'clear' to reset conversation")
    print("   • Type 'help' for examples")
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

            if user_input.lower() == "help":
                print("\n" + "="*70)
                print("💡 USAGE EXAMPLES - Strategic Tool Selection")
                print("="*70)
                print("\n🎯 The LLM will choose the BEST tools, not all tools!")
                print("\n1. Quick IP Scan (~1 min, 2 tools):")
                print("   → 'Quick scan of 192.168.1.100'")
                print("   Tools: nmap_quick_native + shodan_host_native")
                print("\n2. Detailed IP Scan (~3 min, 2 tools):")
                print("   → 'Scan 104.248.174.15'")
                print("   Tools: nmap_aggressive_native + shodan_host_native")
                print("\n3. Vulnerability Assessment (~5 min, 2 tools):")
                print("   → 'Find vulnerabilities on 192.168.1.100'")
                print("   Tools: nmap_vuln_native + shodan_host_native")
                print("\n4. Subdomain Discovery (~8 min, 1 tool):")
                print("   → 'Find all subdomains of example.com'")
                print("   Tools: amass_enum_native OR bbot_subdomain_native (picks ONE)")
                print("\n5. Comprehensive Domain Assessment (~17 min, 2-3 tools):")
                print("   → 'Full security assessment of target.org'")
                print("   Tools: bbot_comprehensive_native + shodan_search_native")
                print("\n6. Network Discovery (~1 min, 1 tool):")
                print("   → 'Scan network 192.168.1.0/24'")
                print("   Tools: nmap_quick_native")
                print("\n⚡ Smart Selection: 1-3 tools max, based on your request!")
                print("="*70)
                continue

            # Process request
            response, conversation_history = chat_native_tools(user_input, conversation_history)

        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


def single_prompt_mode(prompt):
    """Execute a single prompt and return result"""
    print(f"\n{'='*70}")
    print(f"🔍 Executing Task")
    print(f"{'='*70}")
    print(f"Query: {prompt}")
    print(f"{'='*70}")

    response, _ = chat_native_tools(prompt)
    return response


def main():
    """Main entry point"""
    # Check if Ollama model is available
    model_available, available_models = check_model_available()

    if not model_available:
        print(f"❌ Error: Model '{MODEL_NAME}' not found in Ollama.")
        print(f"Available models: {', '.join(available_models) if available_models else 'None'}")
        print(f"\n💡 Please pull the model first:")
        print(f"   ollama pull {MODEL_NAME}")
        sys.exit(1)

    if not USE_NATIVE_TOOLS:
        print("⚠️  Warning: USE_NATIVE_TOOLS is False in config.py")
        print("Set USE_NATIVE_TOOLS = True to use this agent")
        sys.exit(1)

    # Parse command line arguments
    if len(sys.argv) == 1:
        # No arguments - interactive mode
        interactive_mode()

    elif len(sys.argv) >= 3:
        # Command with arguments
        command = sys.argv[1].lower()

        if command == "investigate":
            ip = sys.argv[2]
            prompt = (
                f"Investigate this IP address: {ip}. "
                f"Perform comprehensive scanning using Nmap and Shodan. "
                f"First output the raw scan results, then analyze all findings, "
                f"rate vulnerabilities by severity, and provide actionable recommendations."
            )
            single_prompt_mode(prompt)

        elif command == "scan":
            target = sys.argv[2]
            prompt = (
                f"Scan this target: {target}. "
                f"Identify all live hosts, open ports, and services using Nmap. "
                f"Check threat intelligence via Shodan. "
                f"First output raw scan results, then provide comprehensive vulnerability assessment."
            )
            single_prompt_mode(prompt)

        elif command == "web":
            target = sys.argv[2]
            prompt = (
                f"Perform web security assessment on: {target}. "
                f"Use Nmap to scan for web services, check SSL/TLS configuration, "
                f"and identify security headers. Use Shodan for additional web vulnerability data. "
                f"Output raw results first, then rate all findings by severity."
            )
            single_prompt_mode(prompt)

        elif command == "threat":
            ip = sys.argv[2]
            prompt = (
                f"Check if this IP is malicious or compromised: {ip}. "
                f"Use Shodan for threat intelligence, perform quick Nmap scan. "
                f"Output raw results first, then provide threat assessment with evidence and severity ratings."
            )
            single_prompt_mode(prompt)

        elif command == "custom":
            custom_prompt = " ".join(sys.argv[2:])
            single_prompt_mode(custom_prompt)

        else:
            print(f"❌ Unknown command: {command}")
            print("\n" + "="*70)
            print("USAGE")
            print("="*70)
            print(f"  {sys.argv[0]}")
            print(f"      Interactive mode")
            print()
            print(f"  {sys.argv[0]} investigate <IP>")
            print(f"      Comprehensive investigation of an IP address")
            print()
            print(f"  {sys.argv[0]} scan <target>")
            print(f"      Scan a network or host")
            print()
            print(f"  {sys.argv[0]} web <target>")
            print(f"      Web vulnerability assessment")
            print()
            print(f"  {sys.argv[0]} threat <IP>")
            print(f"      Threat intelligence check")
            print()
            print(f"  {sys.argv[0]} custom <prompt>")
            print(f"      Custom security task")
            print("="*70)
            sys.exit(1)
    else:
        print("="*70)
        print("USAGE")
        print("="*70)
        print(f"  {sys.argv[0]}")
        print(f"      Interactive mode")
        print()
        print(f"  {sys.argv[0]} investigate <IP>")
        print(f"      Comprehensive investigation of an IP address")
        print()
        print(f"  {sys.argv[0]} scan <target>")
        print(f"      Scan a network or host")
        print()
        print(f"  {sys.argv[0]} web <target>")
        print(f"      Web vulnerability assessment")
        print()
        print(f"  {sys.argv[0]} threat <IP>")
        print(f"      Threat intelligence check")
        print()
        print(f"  {sys.argv[0]} custom <prompt>")
        print(f"      Custom security task")
        print("="*70)
        sys.exit(1)


if __name__ == "__main__":
    main()
