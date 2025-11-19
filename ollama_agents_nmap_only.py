"""
Ollama Agent - Nmap Only Version
For Windows users who cannot install Nikto easily
This version only uses Nmap tools for scanning
"""

import json
import requests
import sys
from nmap_tools import NMAP_TOOLS, execute_tool

OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"
OLLAMA_LIST_ENDPOINT = "http://localhost:11434/api/tags"
MODEL_NAME = "llama3.2:3b"


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

You are an expert network security analyst with access to Nmap scanning tools.

CRITICAL INSTRUCTIONS:
- You have access to REAL Nmap tools that you can call directly
- When you need to scan, you MUST call the appropriate tool function
- DO NOT write code or describe what to do - CALL the actual tools

Available Nmap tools:
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

NOTE: This version only has Nmap tools. For web vulnerability scanning,
      you can use nmap_web_scan and nmap_vuln_scan which provide basic web security checks.

Workflow examples:
1. "Scan network 192.168.1.0/24":
   → CALL nmap_ping_scan to find hosts

2. "Check web vulnerabilities on example.com":
   → CALL nmap_web_scan (uses Nmap NSE scripts for web checks)
   → CALL nmap_vuln_scan (uses Nmap vuln scripts)

3. "Comprehensive scan of 192.168.1.100":
   → CALL nmap_aggressive_scan for complete assessment

REMEMBER THESE CRITICAL RULES:
- ⚠️ RESPOND IN THE SAME LANGUAGE AS THE USER - THIS IS MANDATORY
- DO NOT write code or pseudocode
- ALWAYS call the actual tools directly
- Be direct and action-oriented
- For web scans, use nmap_web_scan and nmap_vuln_scan

⚠️ FINAL REMINDER: Match the user's language EXACTLY"""


def chat_with_tools(user_message, conversation_history=None):
    """
    Send a message to Ollama with tool support and handle tool calls
    """
    if conversation_history is None:
        conversation_history = [
            {"role": "system", "content": create_system_message()}
        ]

    conversation_history.append({
        "role": "user",
        "content": user_message
    })

    max_iterations = 15
    iteration = 0

    while iteration < max_iterations:
        iteration += 1

        print(f"\n{'='*60}")
        print(f"Iteration {iteration}")
        print(f"{'='*60}")

        payload = {
            "model": MODEL_NAME,
            "messages": conversation_history,
            "stream": False,
            "tools": NMAP_TOOLS  # Only Nmap tools
        }

        try:
            response = requests.post(OLLAMA_ENDPOINT, json=payload, timeout=300)
            response.raise_for_status()

            response_data = response.json()
            assistant_message = response_data.get('message', {})

            conversation_history.append(assistant_message)

            tool_calls = assistant_message.get('tool_calls', [])

            if not tool_calls:
                final_response = assistant_message.get('content', '')
                print(f"\n[Agent Response]:")
                print(f"{final_response}")
                return final_response, conversation_history

            print(f"\n[Agent is using {len(tool_calls)} tool(s)]")

            for tool_call in tool_calls:
                tool_name = tool_call['function']['name']
                tool_args = tool_call['function']['arguments']

                print(f"\n  🔧 Tool: {tool_name} (Nmap)")
                print(f"  📝 Arguments: {json.dumps(tool_args, indent=2)}")

                tool_result = execute_tool(tool_name, tool_args)

                if isinstance(tool_result, dict):
                    tool_result_str = json.dumps(tool_result, indent=2)
                else:
                    tool_result_str = str(tool_result)

                preview_length = 300
                if len(tool_result_str) > preview_length:
                    print(f"\n  ✅ Result preview: {tool_result_str[:preview_length]}...")
                else:
                    print(f"\n  ✅ Result: {tool_result_str}")

                conversation_history.append({
                    "role": "tool",
                    "content": tool_result_str
                })

        except requests.exceptions.ConnectionError:
            error_msg = f"Error: Cannot connect to Ollama at {OLLAMA_ENDPOINT}"
            print(error_msg)
            return error_msg, conversation_history

        except requests.exceptions.Timeout:
            error_msg = "Error: Request to Ollama timed out"
            print(error_msg)
            return error_msg, conversation_history

        except Exception as e:
            error_msg = f"Unexpected error: {type(e).__name__}: {e}"
            print(error_msg)
            return error_msg, conversation_history

    return "Max iterations reached.", conversation_history


def interactive_mode():
    """Run the agent in interactive mode"""
    print("\n" + "="*60)
    print("🔐 Ollama Security Agent (Nmap Only)")
    print("="*60)
    print("⚠️  Note: This version only uses Nmap tools")
    print("    For web scanning, use nmap_web_scan & nmap_vuln_scan")
    print("\nCommands:")
    print("  'exit' or 'quit' - Exit")
    print("  'clear'         - Clear history")
    print("="*60 + "\n")

    conversation_history = None

    print("Examples:")
    print("  - Scan network 192.168.1.0/24")
    print("  - Check web on example.com (uses Nmap web scripts)")
    print("  - Comprehensive scan of 192.168.1.100")
    print("  - Quét mạng 192.168.1.0/24")
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

            response, conversation_history = chat_with_tools(user_input, conversation_history)

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


def single_prompt_mode(prompt):
    """Run a single prompt and exit"""
    print("\n" + "="*60)
    print("🔐 Ollama Security Agent (Nmap Only) - Single Scan")
    print("="*60 + "\n")

    print(f"[Task]: {prompt}\n")

    response, _ = chat_with_tools(prompt)

    print("\n" + "="*60)
    print("✅ Scan Complete")
    print("="*60 + "\n")


def main():
    print("\n" + "="*60)
    print("🔐 Ollama Security Agent (Nmap Only Version)")
    print("="*60)
    print("Checking Ollama and Nmap...\n")

    is_available, models = check_model_available()

    if not is_available:
        print(f"❌ Error: Model '{MODEL_NAME}' is not available.")
        if models:
            print(f"\n📋 Available: {', '.join(models)}")
            print(f"\nRun: ollama pull {MODEL_NAME}")
        else:
            print(f"\n❌ No models. Run: ollama pull {MODEL_NAME}")
        sys.exit(1)

    print(f"✅ Model '{MODEL_NAME}' ready")
    print(f"✅ Nmap tools: {len(NMAP_TOOLS)} available")
    print(f"⚠️  Nikto tools: Not available (Nmap only version)\n")

    if len(sys.argv) > 1:
        prompt = ' '.join(sys.argv[1:])
        single_prompt_mode(prompt)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
