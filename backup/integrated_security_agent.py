"""
Integrated Security Agent
Combines network reconnaissance (Nmap) and web vulnerability scanning (Nikto)
Provides comprehensive security assessment capabilities with AI-driven analysis
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


def get_cmdb_context(ip):
    """Mock CMDB query to retrieve asset information."""
    db = {
        "192.168.1.100": {"asset_name": "DC-01-PROD", "criticality": "High", "owner": "IT"},
        "10.0.0.5": {"asset_name": "Dev-Workstation-12", "criticality": "Low", "owner": "Ivan"}
    }
    return db.get(ip, {"asset_name": "Unknown Asset", "criticality": "Unknown"})


def get_cti_context(ip):
    """Mock CTI (Cyber Threat Intelligence) query about an IP."""
    db = {
        "1.2.3.4": {"status": "malicious", "type": "Known C2 Server", "confidence": "95%"}
    }
    return db.get(ip, {"status": "clean"})


def create_security_system_message():
    """Create enhanced system message with scanning capabilities"""
    return """⚠️ CRITICAL OUTPUT LANGUAGE RULE:
ALL SCAN RESULTS AND TECHNICAL OUTPUT MUST BE IN ENGLISH!
- You can understand user input in any language (English, Vietnamese, etc.)
- BUT your analysis, scan results, and recommendations MUST be in ENGLISH
- This ensures consistent technical documentation and reporting
- NEVER translate scan output - keep it in English for technical accuracy

Example:
User (any language): "Scan this IP: 192.168.1.100"
You: "I'll scan this IP address 192.168.1.100...
[Scan results in English]
Analysis: The target is running Apache 2.4.41 on port 80..." ✓ CORRECT

You are an advanced autonomous Security Analyst Agent (Tier 2) with comprehensive scanning capabilities.

CRITICAL INSTRUCTIONS:
- You have access to REAL nmap AND nikto tools that you can call directly
- When you need information, CALL the tools - do NOT write code or just describe what to do
- ALWAYS output results in ENGLISH for professional security reporting

Your role combines:
1. Real-time log analysis and threat detection
2. Active network reconnaissance using nmap tools
3. Web vulnerability scanning using nikto tools
4. Asset discovery and vulnerability assessment

Available nmap tools you can CALL (for network/port scanning):
- get_local_network_info: Discover local network ranges (no arguments)
- nmap_ping_scan: Find live hosts (requires: target range)
- nmap_quick_scan: Fast port scan (requires: target IP)
- nmap_port_scan: Scan specific ports (requires: target IP, ports)
- nmap_all_ports: Scan all 65535 ports (requires: target IP)
- nmap_top_ports: Scan top N ports (requires: target IP, num_ports)
- nmap_service_detection: Identify service versions (requires: target IP, optional ports)
- nmap_os_detection: Detect operating system (requires: target IP)
- nmap_aggressive_scan: Comprehensive scan (requires: target IP)
- nmap_vuln_scan: Scan for vulnerabilities (requires: target IP)
- nmap_web_scan: Scan web services (requires: target IP, optional ports)
- nmap_udp_scan: Scan UDP ports (requires: target IP, optional ports)
- nmap_stealth_scan: Stealth SYN scan (requires: target IP, optional ports)
- nmap_traceroute: Trace network path (requires: target IP)
- nmap_no_ping_scan: Scan without ping (requires: target IP, optional ports)
- nmap_scan: Custom nmap (requires: target, optional options)

Available nikto tools you can CALL (for web vulnerability scanning):
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

Security analysis workflow:
1. Analyze the security event/log provided
2. Determine which tools are most appropriate:
   - Use nmap tools for: network discovery, port scanning, service detection, OS detection
   - Use nikto tools for: web server scanning, web vulnerabilities, HTTP/HTTPS security
   - You can use BOTH tools together for comprehensive assessment
3. CALL the appropriate tools immediately to gather information
4. Correlate scan results with CMDB and CTI data
5. Make informed security decisions based on actual data
6. Recommend specific, actionable responses

TOOL SELECTION INTELLIGENCE:
- If user mentions "web", "website", "HTTP", "HTTPS" → Consider using nikto tools
- If user mentions "port", "network", "scan", "hosts" → Consider using nmap tools
- If user wants "comprehensive" or "full" scan → Use BOTH nmap AND nikto
- For IP addresses, first do nmap to find open ports, then nikto for web ports

REMEMBER THESE CRITICAL RULES:
- ⚠️ ALL OUTPUT MUST BE IN ENGLISH - THIS IS MANDATORY FOR TECHNICAL REPORTS
- DO NOT write pseudocode or describe actions - CALL the actual tools
- ALWAYS call the actual tools to get real data
- Be action-oriented and call tools immediately when you need information
- Output all results, analysis, and recommendations in ENGLISH

⚠️ FINAL REMINDER: OUTPUT EVERYTHING IN ENGLISH regardless of user's input language"""


def analyze_security_event_with_scanning(event_description):
    """
    Analyze a security event using AI agent with scanning capabilities

    Args:
        event_description: Description of the security event or task

    Returns:
        dict: Analysis results and recommended actions
    """
    conversation_history = [
        {"role": "system", "content": create_security_system_message()}
    ]

    conversation_history.append({
        "role": "user",
        "content": event_description
    })

    max_iterations = 15
    iteration = 0

    print("\n" + "="*60)
    print("Security Analysis with Active Scanning")
    print("="*60 + "\n")

    while iteration < max_iterations:
        iteration += 1

        print(f"\n--- Iteration {iteration} ---")

        payload = {
            "model": MODEL_NAME,
            "messages": conversation_history,
            "stream": False,
            "tools": ALL_SECURITY_TOOLS
        }

        try:
            response = requests.post(OLLAMA_ENDPOINT, json=payload, timeout=300)
            response.raise_for_status()

            response_data = response.json()
            assistant_message = response_data.get('message', {})

            conversation_history.append(assistant_message)

            # Check for tool calls
            tool_calls = assistant_message.get('tool_calls', [])

            if not tool_calls:
                # Agent has finished analysis
                final_response = assistant_message.get('content', '')
                print(f"\n[Analysis Complete]")
                print(f"\n{final_response}")

                return {
                    "success": True,
                    "analysis": final_response,
                    "conversation_history": conversation_history
                }

            # Execute tool calls
            print(f"\n[Agent performing {len(tool_calls)} security operation(s)]")

            for tool_call in tool_calls:
                tool_name = tool_call['function']['name']
                tool_args = tool_call['function']['arguments']

                print(f"\n  Operation: {tool_name}")
                print(f"  Target: {json.dumps(tool_args, indent=2)}")

                # Execute the scan
                tool_result = execute_tool(tool_name, tool_args)

                if isinstance(tool_result, dict):
                    tool_result_str = json.dumps(tool_result, indent=2)
                else:
                    tool_result_str = str(tool_result)

                print(f"  Status: Complete")

                # Add result to conversation
                conversation_history.append({
                    "role": "tool",
                    "content": tool_result_str
                })

        except requests.exceptions.RequestException as e:
            error_msg = f"Error communicating with Ollama: {e}"
            print(error_msg)
            return {"success": False, "error": error_msg}

        except Exception as e:
            error_msg = f"Unexpected error: {type(e).__name__}: {e}"
            print(error_msg)
            return {"success": False, "error": error_msg}

    return {
        "success": False,
        "error": "Max iterations reached",
        "conversation_history": conversation_history
    }


def investigate_suspicious_ip(ip_address):
    """
    Investigate a suspicious IP address

    Args:
        ip_address: The IP to investigate
    """
    print(f"\n{'='*60}")
    print(f"Investigating Suspicious IP: {ip_address}")
    print(f"{'='*60}\n")

    # Get context
    cmdb = get_cmdb_context(ip_address)
    cti = get_cti_context(ip_address)

    event_description = f"""
A suspicious IP address has been detected: {ip_address}

Asset Information (CMDB):
{json.dumps(cmdb, indent=2)}

Threat Intelligence (CTI):
{json.dumps(cti, indent=2)}

Please:
1. Scan this IP to identify what services are running
2. Check for common vulnerable ports
3. Assess the threat level based on findings
4. Recommend specific security actions

Perform necessary scans and provide a comprehensive security assessment.
"""

    result = analyze_security_event_with_scanning(event_description)
    return result


def scan_network_segment(network_range):
    """
    Scan and assess a network segment

    Args:
        network_range: Network range in CIDR notation (e.g., "192.168.1.0/24")
    """
    print(f"\n{'='*60}")
    print(f"Network Segment Assessment: {network_range}")
    print(f"{'='*60}\n")

    event_description = f"""
Perform a security assessment of network segment: {network_range}

Tasks:
1. Discover all live hosts in this network
2. Identify what services are running on discovered hosts
3. Look for potentially vulnerable or suspicious services
4. Assess overall security posture of this segment
5. Recommend security improvements

Please perform comprehensive scanning and provide a detailed security report.
"""

    result = analyze_security_event_with_scanning(event_description)
    return result


def respond_to_alert(alert_data):
    """
    Respond to a security alert with active investigation

    Args:
        alert_data: Dictionary containing alert information
    """
    print(f"\n{'='*60}")
    print(f"Security Alert Response")
    print(f"{'='*60}\n")

    # Enrich alert with context
    source_ip = alert_data.get("source_ip", "")
    dest_ip = alert_data.get("destination_ip", "")

    enriched_data = {
        "alert": alert_data,
        "source_context": {
            "cmdb": get_cmdb_context(source_ip) if source_ip else {},
            "cti": get_cti_context(source_ip) if source_ip else {}
        },
        "dest_context": {
            "cmdb": get_cmdb_context(dest_ip) if dest_ip else {},
            "cti": get_cti_context(dest_ip) if dest_ip else {}
        }
    }

    event_description = f"""
Security Alert Detected:

{json.dumps(enriched_data, indent=2)}

Please:
1. Analyze the alert context
2. If source or destination IPs are suspicious, scan them to gather more information
3. Assess the threat level
4. Recommend immediate response actions

Use scanning tools as needed to support your analysis.
"""

    result = analyze_security_event_with_scanning(event_description)
    return result


def interactive_mode():
    """Interactive mode for security operations"""
    print("\n" + "="*60)
    print("Integrated Security Agent - Interactive Mode")
    print("="*60)
    print("\nCommands:")
    print("  1. investigate <IP>     - Investigate a suspicious IP")
    print("  2. scan <network/cidr>  - Scan a network segment")
    print("  3. alert <json_file>    - Respond to an alert")
    print("  4. custom <description> - Custom security task")
    print("  exit                    - Exit")
    print("="*60 + "\n")

    while True:
        try:
            user_input = input("\n[Command]: ").strip()

            if not user_input:
                continue

            if user_input.lower() in ['exit', 'quit']:
                print("\nGoodbye!")
                break

            parts = user_input.split(maxsplit=1)
            command = parts[0].lower()

            if command == "investigate" or command == "1":
                if len(parts) < 2:
                    print("Usage: investigate <IP>")
                    continue
                investigate_suspicious_ip(parts[1])

            elif command == "scan" or command == "2":
                if len(parts) < 2:
                    print("Usage: scan <network/cidr>")
                    continue
                scan_network_segment(parts[1])

            elif command == "alert" or command == "3":
                if len(parts) < 2:
                    print("Usage: alert <json_file>")
                    continue
                try:
                    with open(parts[1], 'r') as f:
                        alert_data = json.load(f)
                    respond_to_alert(alert_data)
                except FileNotFoundError:
                    print(f"Error: File {parts[1]} not found")
                except json.JSONDecodeError:
                    print(f"Error: Invalid JSON in {parts[1]}")

            elif command == "custom" or command == "4":
                if len(parts) < 2:
                    print("Usage: custom <description>")
                    continue
                analyze_security_event_with_scanning(parts[1])

            else:
                print("Unknown command. Type 'exit' to quit.")

        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}")


def main():
    """Main entry point"""
    print("\n⚠️  Security Agent Authorization Check ⚠️")
    print("This agent will perform active network scanning.")
    print("Only use on networks you have permission to scan.\n")

    # Check model availability
    print("Checking Ollama and model availability...")
    try:
        response = requests.get(OLLAMA_LIST_ENDPOINT, timeout=5)
        response.raise_for_status()
        data = response.json()
        models = [model['name'] for model in data.get('models', [])]

        if MODEL_NAME not in models:
            print(f"\nError: Model '{MODEL_NAME}' not found.")
            print(f"Available models: {', '.join(models)}")
            print(f"\nPlease run: ollama pull {MODEL_NAME}")
            sys.exit(1)

        print(f"✓ Model '{MODEL_NAME}' is ready\n")

    except:
        print(f"\nError: Cannot connect to Ollama.")
        print("Make sure Ollama is running.")
        sys.exit(1)

    # Parse command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "investigate" and len(sys.argv) > 2:
            investigate_suspicious_ip(sys.argv[2])
        elif sys.argv[1] == "scan" and len(sys.argv) > 2:
            scan_network_segment(sys.argv[2])
        elif sys.argv[1] == "alert" and len(sys.argv) > 2:
            try:
                with open(sys.argv[2], 'r') as f:
                    alert_data = json.load(f)
                respond_to_alert(alert_data)
            except Exception as e:
                print(f"Error loading alert file: {e}")
        else:
            print("Usage:")
            print(f"  {sys.argv[0]} investigate <IP>")
            print(f"  {sys.argv[0]} scan <network/cidr>")
            print(f"  {sys.argv[0]} alert <json_file>")
            print(f"  {sys.argv[0]}  (interactive mode)")
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
