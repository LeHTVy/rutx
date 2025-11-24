"""
Unified Security Agent
Main entry point for the RUTX security scanning framework
Consolidates functionality from ollama_agents.py and ollama_agents_nmap_only.py
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
    ENABLE_NMAP,
    ENABLE_NIKTO
)
from nmap_tools import NMAP_TOOLS, execute_tool as execute_nmap_tool

# Conditionally import Nikto tools if enabled
if ENABLE_NIKTO:
    try:
        from nikto_tools import NIKTO_TOOLS, execute_nikto_tool
        ALL_SECURITY_TOOLS = NMAP_TOOLS + NIKTO_TOOLS
    except ImportError:
        print("⚠️  Warning: Nikto tools not available. Running in Nmap-only mode.")
        NIKTO_TOOLS = []
        ALL_SECURITY_TOOLS = NMAP_TOOLS
else:
    NIKTO_TOOLS = []
    ALL_SECURITY_TOOLS = NMAP_TOOLS


def execute_tool(tool_name, tool_args):
    """
    Unified tool dispatcher for both Nmap and Nikto tools

    Args:
        tool_name: Name of the tool to execute
        tool_args: Arguments for the tool

    Returns:
        Result of the tool execution
    """
    # Check if it's a Nikto tool
    if NIKTO_TOOLS:
        nikto_tool_names = [tool['function']['name'] for tool in NIKTO_TOOLS]
        if tool_name in nikto_tool_names:
            return execute_nikto_tool(tool_name, tool_args)

    # Default to Nmap tools
    return execute_nmap_tool(tool_name, tool_args)


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


def create_system_message():
    """Create system message for the agent"""
    nikto_section = ""
    if NIKTO_TOOLS:
        nikto_section = """
Available Nikto tools (for web vulnerability scanning):
- nikto_scan: Basic web vulnerability scan (requires: target, optional port/ssl/options)
- nikto_quick_scan: Quick web scan for faster results (requires: target, optional port/ssl)
- nikto_full_scan: Comprehensive web vulnerability scan (requires: target, optional port/ssl)
- nikto_ssl_scan: Scan HTTPS/SSL web server (requires: target, optional port)
- nikto_common_ports_scan: Scan common web ports 80,443,8080,8443 (requires: target)
- nikto_vulnerability_scan: Focus on XSS, SQLi, etc. (requires: target, optional port/ssl)
- nikto_plugin_scan: Run specific plugins (requires: target, plugins, optional port/ssl)
- nikto_mutation_scan: Scan with mutation techniques (requires: target, optional port/ssl)
- nikto_cgi_scan: Scan for CGI vulnerabilities (requires: target, optional port/ssl)
- nikto_auth_scan: Scan with HTTP authentication (requires: target, username, password, optional port/ssl)
"""

    tool_selection = ""
    if NIKTO_TOOLS:
        tool_selection = """
TOOL SELECTION GUIDE:
- If user mentions "web", "website", "HTTP", "HTTPS" → Use Nikto tools
- If user mentions "port", "network", "hosts", "devices" → Use Nmap tools
- If user wants "comprehensive" or "full" scan → Use BOTH Nmap AND Nikto
- For IP addresses without context, start with Nmap to find ports, then use Nikto for web ports
"""
    else:
        tool_selection = """
NOTE: This agent is running in Nmap-only mode. For web vulnerability scanning,
use nmap_web_scan and nmap_vuln_scan which provide basic web security checks.
"""

    return f"""LANGUAGE RULE - READ THIS FIRST:
⚠️ CRITICAL: You MUST ALWAYS respond in ENGLISH for all outputs!
- Accept user input in ANY language (English, Vietnamese, Spanish, etc.)
- Always provide output, analysis, and results in ENGLISH ONLY
- This ensures professional security reports and international standards

Example:
User: "Scan my network" → You: "I'll scan your network..." (English)
User: (any other language) → You: "I'll scan your network..." (English)

You are an expert security analyst with access to network scanning tools.

CRITICAL INSTRUCTIONS:
- You have access to REAL tools that you can call directly
- When you need to scan, you MUST call the appropriate tool function
- DO NOT write code or describe what to do - CALL the actual tools
- Choose the right tool based on the user's request

Available Nmap tools (for network/port scanning):
- get_local_network_info: Get local network details (no arguments needed)
- nmap_ping_scan: Find live hosts (requires: target network range)
- nmap_quick_scan: Fast port scan (requires: target IP)
- nmap_port_scan: Scan specific ports (requires: target IP, ports)
- nmap_all_ports: Scan all 65535 ports (requires: target IP)
- nmap_top_ports: Scan top N ports (requires: target IP, num_ports)
- nmap_service_detection: Detect service versions (requires: target IP, optional ports)
- nmap_os_detection: Detect operating system (requires: target IP)
- nmap_aggressive_scan: Comprehensive scan with OS, services, scripts (requires: target IP)
- nmap_vuln_scan: Scan for vulnerabilities (requires: target IP)
- nmap_web_scan: Scan for web services (requires: target IP, optional ports)
- nmap_udp_scan: Scan UDP ports (requires: target IP, optional ports)
- nmap_stealth_scan: Stealth SYN scan (requires: target IP, optional ports)
- nmap_traceroute: Trace network path (requires: target IP)
- nmap_no_ping_scan: Scan without ping (requires: target IP, optional ports)
- nmap_scan: Custom scan with any options (requires: target IP, optional options)
{nikto_section}
{tool_selection}
Workflow examples:
1. "Scan network 192.168.1.0/24":
   → CALL nmap_ping_scan to find hosts

2. "Check web vulnerabilities on example.com":
   → CALL nikto_scan or nikto_vulnerability_scan (if available)
   → Otherwise use nmap_web_scan

3. "Comprehensive scan of 192.168.1.100":
   → CALL nmap_quick_scan first to find ports
   → Then CALL nikto_scan if web ports are found (if available)

4. "Scan HTTPS website":
   → CALL nikto_ssl_scan (if available)

REMEMBER THESE CRITICAL RULES:
- ⚠️ ALWAYS RESPOND IN ENGLISH - Accept any language input, output in ENGLISH only
- DO NOT write code or pseudocode
- ALWAYS call the actual tools directly
- Be direct and action-oriented
- Choose the right tool (Nmap for network, Nikto for web if available)

⚠️ FINAL REMINDER: All outputs must be in ENGLISH for professional security reporting"""


def chat_with_tools(user_message, conversation_history=None):
    """
    Send a message to Ollama with tool support and handle tool calls

    Args:
        user_message: The user's prompt
        conversation_history: Previous messages (optional)

    Returns:
        tuple: (assistant_response, updated_conversation_history)
    """
    if conversation_history is None:
        conversation_history = [
            {"role": "system", "content": create_system_message()}
        ]

    conversation_history.append({
        "role": "user",
        "content": user_message
    })

    iteration = 0
    while iteration < MAX_ITERATIONS:
        iteration += 1
        print(f"\n--- Iteration {iteration} ---")

        try:
            response = requests.post(
                OLLAMA_ENDPOINT,
                json={
                    "model": MODEL_NAME,
                    "messages": conversation_history,
                    "tools": ALL_SECURITY_TOOLS,
                    "stream": False
                },
                timeout=TIMEOUT_OLLAMA
            )
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.Timeout:
            error_msg = "⏱️  Request timed out. The model took too long to respond."
            print(error_msg)
            return error_msg, conversation_history
        except requests.exceptions.RequestException as e:
            error_msg = f"❌ Connection error: {e}"
            print(error_msg)
            return error_msg, conversation_history

        assistant_message = data.get("message", {})
        conversation_history.append(assistant_message)

        # Check if there are tool calls
        tool_calls = assistant_message.get("tool_calls", [])

        if not tool_calls:
            # No more tool calls, return the response
            response_text = assistant_message.get("content", "")
            print(f"\n[Agent Response]:\n{response_text}")
            return response_text, conversation_history

        # Process tool calls
        print(f"[Agent performing {len(tool_calls)} security operation(s)]")
        for tool_call in tool_calls:
            function_name = tool_call["function"]["name"]
            function_args = tool_call["function"]["arguments"]

            print(f"Operation: {function_name}")
            print(f"Target: {json.dumps(function_args, indent=2)}")

            # Execute the tool
            result = execute_tool(function_name, function_args)
            print(f"Status: Complete")

            # Add tool result to conversation
            conversation_history.append({
                "role": "tool",
                "content": json.dumps(result)
            })

    # Max iterations reached
    final_msg = "⚠️  Maximum iterations reached. Please refine your request or start a new conversation."
    print(final_msg)
    return final_msg, conversation_history


def interactive_mode():
    """Run the agent in interactive mode"""
    print("=" * 60)
    print("🔒 RUTX Security Agent - Interactive Mode")
    print("=" * 60)
    print(f"Model: {MODEL_NAME}")
    print(f"Nmap: {'✓ Enabled' if ENABLE_NMAP else '✗ Disabled'}")
    print(f"Nikto: {'✓ Enabled' if ENABLE_NIKTO and NIKTO_TOOLS else '✗ Disabled'}")
    print("=" * 60)
    print("\n⚠️  AUTHORIZATION WARNING:")
    print("Only scan networks and systems you have permission to test.")
    print("Unauthorized scanning may be illegal in your jurisdiction.")
    print("=" * 60)
    print("\nCommands:")
    print("  - Type your security task or question")
    print("  - Type 'exit' or 'quit' to end the session")
    print("  - Type 'clear' to start a new conversation")
    print("=" * 60)

    conversation_history = None

    while True:
        try:
            user_input = input("\n[Command]: ").strip()

            if not user_input:
                continue

            if user_input.lower() in ["exit", "quit"]:
                print("\n👋 Goodbye! Stay secure!")
                break

            if user_input.lower() == "clear":
                conversation_history = None
                print("\n🔄 Conversation cleared. Starting fresh.")
                continue

            # Process the request
            response, conversation_history = chat_with_tools(user_input, conversation_history)

        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


def single_prompt_mode(prompt):
    """Execute a single prompt and return result"""
    print(f"\n🔍 Executing: {prompt}\n")
    response, _ = chat_with_tools(prompt)
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

    # Parse command line arguments
    if len(sys.argv) == 1:
        # No arguments - interactive mode
        interactive_mode()
    elif len(sys.argv) >= 3:
        # Command with arguments
        command = sys.argv[1].lower()

        if command == "investigate":
            ip = sys.argv[2]
            prompt = f"Investigate this IP address: {ip}. Perform comprehensive scanning and security assessment."
            single_prompt_mode(prompt)

        elif command == "scan":
            target = sys.argv[2]
            prompt = f"Scan this network or target: {target}. Identify all live hosts and their services."
            single_prompt_mode(prompt)

        elif command == "custom":
            custom_prompt = " ".join(sys.argv[2:])
            single_prompt_mode(custom_prompt)

        else:
            print(f"❌ Unknown command: {command}")
            print("\nUsage:")
            print(f"  {sys.argv[0]}                          # Interactive mode")
            print(f"  {sys.argv[0]} investigate <IP>        # Investigate an IP")
            print(f"  {sys.argv[0]} scan <target>           # Scan a network")
            print(f"  {sys.argv[0]} custom <prompt>         # Custom task")
            sys.exit(1)
    else:
        print("Usage:")
        print(f"  {sys.argv[0]}                          # Interactive mode")
        print(f"  {sys.argv[0]} investigate <IP>        # Investigate an IP")
        print(f"  {sys.argv[0]} scan <target>           # Scan a network")
        print(f"  {sys.argv[0]} custom <prompt>         # Custom task")
        sys.exit(1)


if __name__ == "__main__":
    main()
