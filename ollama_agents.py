"""
Ollama Multi-Agent Security Scanner
Combines Nmap and Nikto scanning capabilities with AI-driven tool selection
Simple and easy to use for quick security assessments
"""

import json
import requests
import sys
from nmap_tools import NMAP_TOOLS, execute_tool as execute_nmap_tool
from nikto_tools import NIKTO_TOOLS, execute_nikto_tool

OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"
OLLAMA_LIST_ENDPOINT = "http://localhost:11434/api/tags"
MODEL_NAME = "llama3.2:3b"

# Combine all security tools
ALL_SECURITY_TOOLS = NMAP_TOOLS + NIKTO_TOOLS


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
    nikto_tool_names = [tool['function']['name'] for tool in NIKTO_TOOLS]

    if tool_name in nikto_tool_names:
        return execute_nikto_tool(tool_name, tool_args)
    else:
        # Default to Nmap tools
        return execute_nmap_tool(tool_name, tool_args)


def check_model_available():
    """Check if the model has been pulled."""
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
    return """LANGUAGE RULE - READ THIS FIRST:
⚠️ CRITICAL: You MUST ALWAYS respond in the EXACT SAME LANGUAGE as the user's message!
- If the user writes in ENGLISH → You respond in ENGLISH
- If the user writes in VIETNAMESE → You respond in VIETNAMESE
- NEVER mix languages or use a different language than the user
- This rule applies to ALL your responses - analysis, explanations, everything

Examples:
User: "Scan my network" → You: "I'll scan your network..." (English)
User: "Quét mạng của tôi" → You: "Tôi sẽ quét mạng của bạn..." (Vietnamese)

You are an expert security analyst with access to BOTH network scanning (Nmap) and web vulnerability scanning (Nikto) tools.

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

TOOL SELECTION GUIDE:
- If user mentions "web", "website", "HTTP", "HTTPS" → Use Nikto tools
- If user mentions "port", "network", "hosts", "devices" → Use Nmap tools
- If user wants "comprehensive" or "full" scan → Use BOTH Nmap AND Nikto
- For IP addresses without context, start with Nmap to find ports, then use Nikto for web ports

Workflow examples:
1. "Scan network 192.168.1.0/24":
   → CALL nmap_ping_scan to find hosts

2. "Check web vulnerabilities on example.com":
   → CALL nikto_scan or nikto_vulnerability_scan

3. "Comprehensive scan of 192.168.1.100":
   → CALL nmap_quick_scan first to find ports
   → Then CALL nikto_scan if web ports are found

4. "Scan HTTPS website":
   → CALL nikto_ssl_scan

REMEMBER THESE CRITICAL RULES:
- ⚠️ RESPOND IN THE SAME LANGUAGE AS THE USER - THIS IS MANDATORY
- DO NOT write code or pseudocode
- ALWAYS call the actual tools directly
- Be direct and action-oriented
- Choose the right tool (Nmap for network, Nikto for web)

⚠️ FINAL REMINDER: Match the user's language EXACTLY - English input = English output, Vietnamese input = Vietnamese output"""


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

    # Add user message
    conversation_history.append({
        "role": "user",
        "content": user_message
    })

    max_iterations = 15  # Allow more iterations for complex scans
    iteration = 0

    while iteration < max_iterations:
        iteration += 1

        print(f"\n{'='*60}")
        print(f"Iteration {iteration}")
        print(f"{'='*60}")

        # Prepare request payload with ALL security tools
        payload = {
            "model": MODEL_NAME,
            "messages": conversation_history,
            "stream": False,
            "tools": ALL_SECURITY_TOOLS  # Both Nmap and Nikto tools
        }

        try:
            # Call Ollama API
            response = requests.post(OLLAMA_ENDPOINT, json=payload, timeout=300)
            response.raise_for_status()

            response_data = response.json()
            assistant_message = response_data.get('message', {})

            # Add assistant's response to conversation
            conversation_history.append(assistant_message)

            # Check if the model wants to use tools
            tool_calls = assistant_message.get('tool_calls', [])

            if not tool_calls:
                # No tool calls, the agent has finished
                final_response = assistant_message.get('content', '')
                print(f"\n[Agent Response]:")
                print(f"{final_response}")
                return final_response, conversation_history

            # Execute tool calls
            print(f"\n[Agent is using {len(tool_calls)} tool(s)]")

            for tool_call in tool_calls:
                tool_name = tool_call['function']['name']
                tool_args = tool_call['function']['arguments']

                # Determine tool type
                tool_type = "Nikto" if tool_name.startswith('nikto_') else "Nmap"

                print(f"\n  🔧 Tool: {tool_name} ({tool_type})")
                print(f"  📝 Arguments: {json.dumps(tool_args, indent=2)}")

                # Execute the tool
                tool_result = execute_tool(tool_name, tool_args)

                # Convert result to string if it's a dict
                if isinstance(tool_result, dict):
                    tool_result_str = json.dumps(tool_result, indent=2)
                else:
                    tool_result_str = str(tool_result)

                # Show preview
                preview_length = 300
                if len(tool_result_str) > preview_length:
                    print(f"\n  ✅ Result preview: {tool_result_str[:preview_length]}...")
                else:
                    print(f"\n  ✅ Result: {tool_result_str}")

                # Add tool result to conversation
                conversation_history.append({
                    "role": "tool",
                    "content": tool_result_str
                })

            # Continue the loop to let the model process tool results

        except requests.exceptions.ConnectionError:
            error_msg = f"Error: Cannot connect to Ollama at {OLLAMA_ENDPOINT}"
            print(error_msg)
            return error_msg, conversation_history

        except requests.exceptions.Timeout:
            error_msg = "Error: Request to Ollama timed out"
            print(error_msg)
            return error_msg, conversation_history

        except requests.exceptions.RequestException as e:
            error_msg = f"Error calling Ollama API: {e}"
            print(error_msg)
            if hasattr(e, 'response') and e.response is not None:
                print(f"Details: {e.response.text}")
            return error_msg, conversation_history

        except Exception as e:
            error_msg = f"Unexpected error: {type(e).__name__}: {e}"
            print(error_msg)
            return error_msg, conversation_history

    return "Max iterations reached. The scan may be incomplete.", conversation_history


def interactive_mode():
    """Run the agent in interactive mode"""
    print("\n" + "="*60)
    print("🔐 Ollama Multi-Agent Security Scanner")
    print("="*60)
    print("Tools: Nmap (network) + Nikto (web)")
    print("\nCommands:")
    print("  'exit' or 'quit' - Exit the program")
    print("  'clear'         - Clear conversation history")
    print("="*60 + "\n")

    conversation_history = None

    print("Examples:")
    print("  - Scan network 192.168.1.0/24")
    print("  - Check web vulnerabilities on example.com")
    print("  - Comprehensive scan of 192.168.1.100")
    print("  - Quét mạng 192.168.1.0/24")
    print("  - Kiểm tra lỗ hổng web của example.com")
    print()

    while True:
        try:
            user_input = input("\n[You]: ").strip()

            if not user_input:
                continue

            if user_input.lower() in ['exit', 'quit']:
                print("\n👋 Goodbye!")
                break

            if user_input.lower() == 'clear':
                conversation_history = None
                print("\n✅ Conversation history cleared.")
                continue

            # Process the message
            response, conversation_history = chat_with_tools(user_input, conversation_history)

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


def single_prompt_mode(prompt):
    """Run a single prompt and exit"""
    print("\n" + "="*60)
    print("🔐 Ollama Multi-Agent Security Scanner - Single Scan")
    print("="*60 + "\n")

    print(f"[Task]: {prompt}\n")

    response, _ = chat_with_tools(prompt)

    print("\n" + "="*60)
    print("✅ Scan Complete")
    print("="*60 + "\n")


def main():
    print("\n" + "="*60)
    print("🔐 Ollama Multi-Agent Security Scanner")
    print("="*60)
    print("Checking Ollama connection and model availability...\n")

    # Check if model is available
    is_available, models = check_model_available()

    if not is_available:
        print(f"❌ Error: Model '{MODEL_NAME}' is not available.")
        if models:
            print(f"\n📋 Available models: {', '.join(models)}")
            print(f"\nOptions:")
            print(f"  1. Pull the model: ollama pull {MODEL_NAME}")
            print(f"  2. Update MODEL_NAME in the script")
        else:
            print(f"\n❌ No models found. Please run: ollama pull {MODEL_NAME}")

        print(f"\n💡 Recommended models:")
        print(f"  - llama3.2:3b (fast)")
        print(f"  - llama3.1:8b (balanced)")
        print(f"  - mistral (alternative)")
        sys.exit(1)

    print(f"✅ Model '{MODEL_NAME}' is ready")
    print(f"✅ Nmap tools: {len(NMAP_TOOLS)} available")
    print(f"✅ Nikto tools: {len(NIKTO_TOOLS)} available")
    print(f"✅ Total tools: {len(ALL_SECURITY_TOOLS)}\n")

    # Check for command line arguments
    if len(sys.argv) > 1:
        # Single prompt mode
        prompt = ' '.join(sys.argv[1:])
        single_prompt_mode(prompt)
    else:
        # Interactive mode
        interactive_mode()


if __name__ == "__main__":
    main()
