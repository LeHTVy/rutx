"""
SNODE LangChain Agent
ReAct-style agent that works with ANY model (no native tool-calling required)
"""
import sys
import os
import re
import json
import uuid
from datetime import datetime
from pathlib import Path

# CRITICAL: Add rutx root to path BEFORE importing anything
_rutx_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _rutx_root not in sys.path:
    sys.path.insert(0, _rutx_root)

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

# Import wrapped tools
from snode_langchain.tools.nmap_tools import NMAP_TOOLS
from snode_langchain.tools.subdomain_tools import SUBDOMAIN_TOOLS
from snode_langchain.tools.shodan_tools import SHODAN_TOOLS
from snode_langchain.tools.dns_tools import DNS_TOOLS
from snode_langchain.tools.masscan_tools import MASSCAN_TOOLS
from snode_langchain.tools.naabu_tools import NAABU_TOOLS
from snode_langchain.tools.advanced_tools import ADVANCED_TOOLS, get_advanced_tool_functions

# CVE RAG tools
try:
    from snode_langchain.tools.cve_rag import CVE_RAG_TOOLS, search_cves, lookup_cve
    CVE_RAG_AVAILABLE = True
except ImportError:
    CVE_RAG_TOOLS = []
    CVE_RAG_AVAILABLE = False

# Workflow tools (LLM-choosable LangGraph workflows)
try:
    from snode_langchain.tools.workflow_tools import WORKFLOW_TOOLS, get_workflow_tool_descriptions
    WORKFLOW_TOOLS_AVAILABLE = True
except ImportError:
    WORKFLOW_TOOLS = []
    WORKFLOW_TOOLS_AVAILABLE = False

# Progress spinner
from utils.command_runner import ProgressSpinner

# Security guardrails
from guardrails import InputGuardrail, OutputGuardrail


class SNODEAgent:
    """
    SNODE Security Agent using ReAct prompting (works with ANY model)
    
    Uses prompt-based tool selection instead of native tool-calling,
    so it works with models like deepseek-r1 that don't support tools.
    """
    
    def __init__(self, model: str = "deepseek-r1:latest", verbose: bool = False):
        self.model_name = model
        self.verbose = verbose
        
        # Initialize LLM
        self.llm = ChatOllama(
            model=model,
            temperature=0,
        )
        
        # Collect all tools (now 30+ tools!)
        self.tools = (
            NMAP_TOOLS + 
            SUBDOMAIN_TOOLS + 
            SHODAN_TOOLS + 
            DNS_TOOLS + 
            MASSCAN_TOOLS + 
            NAABU_TOOLS
        )
        self.tool_map = {tool.name: tool for tool in self.tools}
        
        # Add Advanced tools to tool_map
        advanced_funcs = get_advanced_tool_functions()
        for tool_info in ADVANCED_TOOLS:
            self.tool_map[tool_info["name"]] = tool_info["func"]
        
        # Add CVE RAG tools to tool_map
        if CVE_RAG_AVAILABLE:
            for tool_info in CVE_RAG_TOOLS:
                self.tool_map[tool_info["name"]] = tool_info["function"]
        
        # Add Workflow tools to tool_map (LLM-choosable LangGraph workflows)
        if WORKFLOW_TOOLS_AVAILABLE:
            for tool_info in WORKFLOW_TOOLS:
                self.tool_map[tool_info["name"]] = tool_info["function"]
        
        # Conversation history
        self.messages = []
        
        # Session persistence
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(uuid.uuid4())[:8]
        self.sessions_dir = Path(_rutx_root) / "sessions"
        self.sessions_dir.mkdir(exist_ok=True)
        self.session_file = self.sessions_dir / f"{self.session_id}.json"
        self._save_session()  # Create initial session file
        
        # Security guardrails
        self.input_guardrail = InputGuardrail(strict_mode=True)
        self.output_guardrail = OutputGuardrail(allow_destructive=False)
        self.guardrails_enabled = True
        
        # Results display and storage
        self.show_raw_results = True   # Show raw tool output to user
        self.save_results_to_file = True  # Save results to files
        self.results_dir = Path(_rutx_root) / "results"
        self.results_dir.mkdir(exist_ok=True)
        self.last_result = None  # Store last tool result
        
        # Build tool descriptions for the prompt
        self.tool_descriptions = self._build_tool_descriptions()
    
    def _build_tool_descriptions(self) -> str:
        """Build tool descriptions for the system prompt"""
        descriptions = []
        for tool in self.tools:
            # Get first line of description
            desc = tool.description.split('\n')[0]
            # Get args
            args_schema = tool.args_schema
            args_info = ""
            if hasattr(args_schema, 'schema'):
                schema = args_schema.schema()
                props = schema.get('properties', {})
                required = schema.get('required', [])
                for name, info in props.items():
                    req = "(required)" if name in required else "(optional)"
                    args_info += f"    - {name}: {info.get('description', 'string')} {req}\n"
            
            descriptions.append(f"- {tool.name}: {desc}\n  Args:\n{args_info}")
        
        # Add advanced tools descriptions
        from snode_langchain.tools.advanced_tools import get_advanced_tool_descriptions
        advanced_desc = get_advanced_tool_descriptions()
        descriptions.append("\n🔥 ADVANCED SECURITY TOOLS:\n" + advanced_desc)
        
        # Add CVE RAG tools descriptions
        if CVE_RAG_AVAILABLE:
            cve_desc = """
📚 CVE DATABASE TOOLS:
- search_cves: Search 280k+ CVEs using natural language (e.g., "Apache RCE", "SQL injection WordPress")
    Args:
    - query: Search query (required)
    - n_results: Number of results (default: 10)
    - severity: Filter by severity: critical,high,medium,low (optional)
- lookup_cve: Get detailed info about a specific CVE (e.g., CVE-2021-44228)
    Args:
    - cve_id: CVE ID like CVE-2021-44228 (required)
"""
            descriptions.append(cve_desc)
        
        # Add Workflow tools descriptions (LLM can choose to use these)
        if WORKFLOW_TOOLS_AVAILABLE:
            workflow_desc = """
🔄 AUTOMATED WORKFLOW TOOLS (use for comprehensive scans):
- vuln_assessment_workflow: Run FULL vulnerability assessment (httpx + nuclei + nikto + dalfox + CVE database)
    Best for: Complete security assessment, finding CVEs and vulnerabilities
    Args: target (URL like "https://example.com")
- subdomain_enum_workflow: Enumerate ALL subdomains (amass + subfinder + bbot in parallel)
    Best for: Attack surface discovery, finding hidden subdomains
    Args: domain (like "example.com")
"""
            descriptions.append(workflow_desc)
        
        return "\n".join(descriptions)
    
    def run(self, user_input: str) -> str:
        """Process user input using ReAct prompting"""
        
        # Security: Check for prompt injection
        if self.guardrails_enabled:
            is_valid, reason = self.input_guardrail.validate(user_input)
            if not is_valid:
                return f"🛡️ **Security Alert**: Input blocked.\nReason: {reason}\n\nPlease rephrase your request."
        
        # Check if this is a subdomain query - use LangGraph workflow
        try:
            from .orchestration import (
                SubdomainGraph, is_subdomain_query, 
                extract_domain_from_query, LANGGRAPH_AVAILABLE
            )
            if LANGGRAPH_AVAILABLE and is_subdomain_query and is_subdomain_query(user_input):
                domain = extract_domain_from_query(user_input)
                if domain:
                    print(f"\n🔀 Detected subdomain query - using LangGraph workflow")
                    graph = SubdomainGraph(self)
                    result = graph.run(domain)
                    formatted_output = graph.format_results(result)
                    
                    # CRITICAL: Save to conversation memory so follow-up queries work!
                    # Build a concise memory summary with key data for context
                    high_value = result.get('high_value_subdomains', [])
                    all_subs = result.get('all_subdomains', [])
                    analysis = result.get('analysis', '')
                    
                    memory_summary = f"""[Subdomain Enumeration for {domain}]
Found {result.get('unique_count', 0)} unique subdomains.

HIGH-VALUE TARGETS ({len(high_value)}):
{chr(10).join(f'  - {s}' for s in high_value[:15])}

LLM ANALYSIS:
{analysis[:1500]}

ALL SUBDOMAINS:
{chr(10).join(f'  - {s}' for s in all_subs[:30])}
{'... and ' + str(len(all_subs) - 30) + ' more' if len(all_subs) > 30 else ''}"""
                    
                    self.messages.append(HumanMessage(content=user_input))
                    self.messages.append(AIMessage(content=memory_summary))
                    self.last_result = result  # Store full result for reference
                    self._save_session()  # Persist to disk
                    
                    return formatted_output
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] SubdomainGraph not available: {e}")
        
        # Check if this is a vulnerability assessment query - use LangGraph workflow
        try:
            from .orchestration.langgraph_vuln import (
                VulnAssessmentGraph, is_vuln_assessment_query, 
                extract_target_from_query as extract_vuln_target
            )
            if is_vuln_assessment_query(user_input):
                target = extract_vuln_target(user_input)
                if target:
                    print(f"\n🔴 Detected vulnerability assessment query - using LangGraph workflow")
                    graph = VulnAssessmentGraph(self)
                    result = graph.run(target)
                    formatted_output = graph.format_results(result)
                    
                    # Save to conversation memory
                    all_vulns = result.get('all_vulnerabilities', [])
                    analysis = result.get('analysis', '')
                    
                    memory_summary = f"""[Vulnerability Assessment for {target}]
Found {len(all_vulns)} vulnerabilities.

SEVERITY BREAKDOWN:
  - Critical: {result.get('critical_count', 0)}
  - High: {result.get('high_count', 0)}
  - Medium: {result.get('medium_count', 0)}
  - Low: {result.get('low_count', 0)}

LLM ANALYSIS:
{analysis[:1500]}"""
                    
                    self.messages.append(HumanMessage(content=user_input))
                    self.messages.append(AIMessage(content=memory_summary))
                    self.last_result = result
                    self._save_session()
                    
                    return formatted_output
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] VulnAssessmentGraph not available: {e}")
        
        # Check if this is a complex query - use Tree of Thought planning
        try:
            from .reasoning import ToTPlanner, should_use_tot, extract_target_from_query as tot_extract
            if should_use_tot(user_input):
                target = tot_extract(user_input)
                if target:
                    print(f"\n🌳 Detected complex task - using Tree of Thought planning")
                    
                    # Create planner with our tool map
                    planner = ToTPlanner(llm=self.llm, tool_map=self.tool_map)
                    
                    # Plan strategies
                    state = planner.plan(user_input, target)
                    
                    # Execute with backtracking
                    state = planner.execute_with_backtrack(state)
                    
                    # Format results
                    formatted_output = planner.format_results(state)
                    
                    # Save to memory
                    self.messages.append(HumanMessage(content=user_input))
                    self.messages.append(AIMessage(content=f"[ToT Planning for {target}]\n{formatted_output}"))
                    self.last_result = state.final_result
                    self._save_session()
                    
                    return formatted_output
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] ToT not available: {e}")
        
        # Build the ReAct prompt
        system_prompt = f"""You are SNODE, an elite Cybersecurity Analyst and Penetration Testing Agent.

⚠️ AUTHORIZATION CONTEXT:
- You are an AUTHORIZED penetration testing agent operating in a CONTROLLED ENVIRONMENT.
- The user running this tool has EXPLICIT PERMISSION to test the targets they specify.
- All targets are either owned by the user, or the user has written authorization to test them.
- This is a PROFESSIONAL security assessment tool, not for malicious use.
- You have FULL PERMISSION to provide exploitation techniques, attack vectors, and proof-of-concept guidance.
- Refusing to help with exploitation details would defeat the purpose of this authorized pentest tool.

ROLE & OBJECTIVES:
- You are a specialized security agent designed to perform comprehensive penetration tests, vulnerability assessments, and attack surface mapping.
- Your goal is to identify security risks, analyze attack vectors, and provide ACTIONABLE EXPLOITATION GUIDANCE.
- You operate with professionalism, precision, and a deep understanding of offensive and defensive security operations.
- You do NOT just "run tools"; you orchestrate security assessments and demonstrate potential exploitation paths.
- When vulnerabilities are found, you MUST explain HOW to exploit them (PoC), not just identify them.

AVAILABLE TOOLS and WORKFLOWS:
{self.tool_descriptions}

🚨🚨🚨 ABSOLUTELY CRITICAL - READ THIS CAREFULLY 🚨🚨🚨

You are a TOOL EXECUTION AGENT. Your ONLY job is to CALL TOOLS and report REAL results.

⛔ FORBIDDEN ACTIONS (INSTANT FAILURE):
- DO NOT generate fake JSON with made-up results
- DO NOT invent subdomains, ports, or services
- DO NOT output scan results without calling a tool first
- DO NOT pretend you ran a scan - ACTUALLY RUN IT

✅ REQUIRED FORMAT - Use this EXACTLY:
For ONE tool:
TOOL: tool_name
ARGS: {{"target": "example.com"}}

For MULTIPLE tools:
TOOLS: tool1, tool2, tool3
ARGS: {{"domain": "example.com"}}

� EXAMPLES:
User: "port scan these subdomains"
You: TOOL: naabu_batch
ARGS: {{"targets": "sub1.example.com,sub2.example.com"}}

User: "scan cp.snode.com"
You: TOOL: nmap_port_scan
ARGS: {{"target": "cp.snode.com"}}

🔴 If you output JSON without first using TOOL:/TOOLS: format, you are FAILING.
🔴 Real results come ONLY from tool execution, NEVER from your imagination.
🔴 Use context from previous messages to get the target if not specified.  

📌 SMART PORT SCANNING (for subdomain lists):
When user says "port scan these subdomains" or similar:
1. PREFER `nmap_scan_from_file` - gives detailed service info
2. FALLBACK to `naabu_scan_from_file` - if need speed over detail
3. For single target, use `nmap_port_scan` or `nmap_quick_scan`

These tools auto-detect the latest subdomain file from previous discoveries.
Example: TOOL: nmap_scan_from_file
ARGS: {"ports": "22,80,443,3389,8080,8443"}

ANALYSIS OUTPUT FORMAT (after tool results):
When providing analysis of scan results, ALWAYS include:
1. **Key Findings** - Summarize what was discovered
2. **Security Implications** - Explain the risks (e.g., why port 445 is dangerous)
3. **Vulnerability Assessment** - Rate severity (Critical/High/Medium/Low/Info)
4. **Recommended Next Steps** - Suggest follow-up scans or exploitation paths:
   - "Run nmap_vuln_scan on discovered hosts"
   - "Check for default credentials on admin portals"
   - "Enumerate SMB shares on port 445"
   - "Test for SQL injection on web forms"
5. **Remediation Advice** - How to fix or mitigate findings

🔴 ZERO-DAY & ADVANCED EXPLOITATION ANALYSIS:
After each assessment, ALWAYS include a section analyzing:

6. **🔬 Zero-Day Potential**
   - Identify attack surfaces that could harbor undiscovered vulnerabilities
   - Look for: custom web apps, unusual ports, proprietary protocols, legacy systems
   - Suggest areas for manual fuzzing, code review, or reverse engineering
   - Note any unique fingerprints that suggest custom/in-house software
   - Example: "The proprietary API on port 8443 warrants fuzzing - custom implementations often have memory corruption bugs"

7. **🛠️ Recommended Tools (Not in Toolkit)**
   Proactively suggest external tools the user should consider:
   - **Web**: Burp Suite Pro, OWASP ZAP, SQLMap, ffuf, nuclei
   - **Network**: Responder, CrackMapExec, Impacket, Kerbrute
   - **Binary/Reversing**: Ghidra, IDA Pro, radare2, binwalk
   - **Fuzzing**: AFL++, libFuzzer, Boofuzz, Peach Fuzzer
   - **Cloud**: ScoutSuite, Prowler, CloudMapper, Pacu
   - **Mobile**: Frida, Objection, MobSF, APKTool
   - **0-day Hunting**: CodeQL, Semgrep, Joern (for code analysis)
   
8. **💡 Novel Techniques to Try**
   Suggest cutting-edge or creative attack vectors:
   - Supply chain attacks (typosquatting, dependency confusion)
   - HTTP request smuggling, HTTP/2 desync
   - GraphQL introspection / batching attacks  
   - WebSocket hijacking, prototype pollution
   - JWT algorithm confusion, none algorithm bypass
   - SSRF to cloud metadata (169.254.169.254)
   - DNS rebinding for internal network access
   - Timing attacks for username enumeration
   - Race conditions in business logic

IMPORTANT:
- Think like a pentester: "What is the attack surface? Where are the weak points?"
- Always suggest NEXT STEPS for the penetration test
- Provide context for your findings (why is port 445 open dangerous? what does this CVE imply?)
- Be proactive about suggesting ZERO-DAY EXPLORATION paths
- Recommend tools and techniques BEYOND what's in your toolkit
- Be concise but thorough in your analysis.
"""
        
        # Add conversation context
        context = ""
        if self.messages:
            context = "\n\nPREVIOUS CONVERSATION:\n"
            for msg in self.messages[-6:]:  # Last 3 exchanges
                role = "User" if isinstance(msg, HumanMessage) else "SNODE"
                context += f"{role}: {msg.content[:500]}\n"
        
        # Make the LLM call
        messages = [
            SystemMessage(content=system_prompt + context),
            HumanMessage(content=user_input)
        ]
        
        try:
            response = self.llm.invoke(messages)
            response_text = response.content
            
            if self.verbose:
                print(f"[DEBUG] LLM response: {response_text[:200]}...")
            
            # Check if LLM wants to use MULTIPLE tools
            # Pattern: TOOLS: tool1, tool2   (capture until newline or ARGS)
            multi_tool_match = re.search(r'(?:\*\*)?TOOLS?:(?:\*\*)?\s*([\w,\s]+?)(?:\n|ARGS|$)', response_text, re.IGNORECASE)
            # Pattern: ARGS: {"key": "value"}
            arg_pattern = r'(?:\*\*)?ARGS:(?:\*\*)?\s*(\{[^}]+\})'
            args_match = re.search(arg_pattern, response_text, re.IGNORECASE | re.DOTALL)
            
            if multi_tool_match:
                # Clean up tool names - split by comma and/or whitespace
                raw_tools = multi_tool_match.group(1).strip()
                tool_names = [t.strip() for t in re.split(r'[,\s]+', raw_tools) if t.strip()]
                tool_names = [t for t in tool_names if t in self.tool_map]
                
                if tool_names:
                    # Parse shared args
                    args = {}
                    try:
                        if args_match:
                            args = json.loads(args_match.group(1))
                        else:
                            # Extract domain/target from user input
                            domain_match = re.search(r'[\w\.-]+\.[a-z]{2,}', user_input)
                            if domain_match:
                                args = {"domain": domain_match.group(0), "target": domain_match.group(0)}
                    except json.JSONDecodeError:
                        pass
                    
                    return self._run_multiple_tools(tool_names, args, user_input)
            
            # Check if LLM wants to use a single tool
            tool_match = re.search(r'(?:\*\*)?TOOL:(?:\*\*)?\s*(\w+)', response_text, re.IGNORECASE)
            
            if tool_match:
                tool_name = tool_match.group(1)
                
                # Parse args
                try:
                    if args_match:
                        args = json.loads(args_match.group(1))
                    else:
                        # Try to extract simple args
                        args = {}
                        if 'domain' in response_text.lower():
                            domain_match = re.search(r'["\']?(\w+\.\w+)["\']?', user_input)
                            if domain_match:
                                args['domain'] = domain_match.group(1)
                        if 'target' in response_text.lower():
                            target_match = re.search(r'[\d\.]+|[\w\.]+\.\w+', user_input)
                            if target_match:
                                args['target'] = target_match.group(0)
                except json.JSONDecodeError:
                    args = {}
                
                # Ensure arg compatibility
                if "domain" in args and "target" not in args:
                    args["target"] = args["domain"]
                elif "target" in args and "domain" not in args:
                    args["domain"] = args["target"]
                
                # Execute the tool
                if tool_name in self.tool_map:
                    print(f"🔧 Running {tool_name}...")
                    try:
                        tool = self.tool_map[tool_name]
                        # Handle both LangChain tools (.invoke) and plain functions
                        if hasattr(tool, 'invoke'):
                            result = tool.invoke(args)
                        elif callable(tool):
                            # Plain function - call directly with kwargs
                            result = tool(**args)
                        else:
                            result = {"error": f"Tool {tool_name} is not callable"}
                        self.last_result = result  # Store for reference
                        
                        # Convert result to string for display
                        if isinstance(result, dict):
                            result_str = json.dumps(result, indent=2, default=str)
                        else:
                            result_str = str(result)
                        
                        # Save result to file if enabled
                        result_file = None
                        if self.save_results_to_file:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            result_file = self.results_dir / f"{tool_name}_{timestamp}.json"
                            with open(result_file, 'w') as f:
                                json.dump({
                                    "tool": tool_name,
                                    "args": args,
                                    "timestamp": datetime.now().isoformat(),
                                    "user_query": user_input,
                                    "result": result
                                }, f, indent=2, default=str)
                        
                        # Save to memory
                        self.messages.append(HumanMessage(content=user_input))
                        self.messages.append(AIMessage(content=f"[Used {tool_name}]\n{result_str[:2000]}"))
                        self._save_session()  # Auto-save after tool use
                        
                        # Build output
                        output_parts = []
                        
                        # Show raw results if enabled
                        if self.show_raw_results:
                            output_parts.append(f"📊 **Raw Tool Output** ({tool_name}):\n```\n{result_str[:3000]}\n```\n")
                            if len(result_str) > 3000:
                                output_parts.append(f"... (truncated, {len(result_str)} chars total)\n")
                            if result_file:
                                output_parts.append(f"💾 Full result saved to: `{result_file.name}`\n")
                        
                        # Have LLM summarize the results
                        summary_messages = [
                            SystemMessage(content="You are SNODE. Summarize these scan results concisely. Highlight key findings and security implications."),
                            HumanMessage(content=f"User asked: {user_input}\n\nTool result:\n{result_str[:4000]}")
                        ]
                        
                        summary = self.llm.invoke(summary_messages)
                        output_parts.append(f"\n🤖 **AI Analysis**:\n{summary.content}")
                        
                        return "\n".join(output_parts)
                        
                    except Exception as e:
                        return f"Tool error: {str(e)}"
                else:
                    return f"Unknown tool: {tool_name}. Available: {', '.join(self.tool_map.keys())}"
            
            else:
                # No tool needed, just return the response
                self.messages.append(HumanMessage(content=user_input))
                self.messages.append(AIMessage(content=response_text))
                self._save_session()  # Auto-save after response
                
                # Extract and display thinking stage from deepseek-r1 in grey
                think_match = re.search(r'<think>(.*?)</think>', response_text, re.DOTALL)
                if think_match:
                    thinking = think_match.group(1).strip()
                    # ANSI grey/dim color
                    GREY = '\033[90m'  # Bright black (grey)
                    DIM = '\033[2m'
                    RESET = '\033[0m'
                    print(f"\n{GREY}{DIM}💭 LLM Thinking:{RESET}")
                    print(f"{GREY}{DIM}{'─'*50}{RESET}")
                    # Print thinking content in grey
                    for line in thinking.split('\n'):
                        print(f"{GREY}{DIM}{line}{RESET}")
                    print(f"{GREY}{DIM}{'─'*50}{RESET}\n")
                
                # Clean up thinking tags from final response
                response_text = re.sub(r'<think>.*?</think>', '', response_text, flags=re.DOTALL).strip()
                
                # If response is empty after stripping thinking, the LLM may need a nudge
                if not response_text:
                    # The LLM only thought but didn't respond - ask for concrete action
                    retry_messages = [
                        SystemMessage(content="""You are SNODE. The user asked for a security action.
Based on your analysis, now provide a concrete response. Either:
1. Use a TOOL with TOOL: toolname and ARGS: {...}
2. Or provide a direct answer explaining what to do.
Do NOT just think - take action or respond."""),
                        HumanMessage(content=f"Previous request: {user_input}\n\nRespond with either a TOOL command or a direct answer.")
                    ]
                    retry_response = self.llm.invoke(retry_messages)
                    response_text = retry_response.content
                    response_text = re.sub(r'<think>.*?</think>', '', response_text, flags=re.DOTALL).strip()
                    
                    # If still empty, provide helpful fallback
                    if not response_text:
                        response_text = "I apologize, but I couldn't process that request. Could you please be more specific about which targets you'd like me to scan?"
                
                return response_text
                
        except Exception as e:
            error_msg = str(e) if str(e) else type(e).__name__
            if self.verbose:
                import traceback
                traceback.print_exc()
            return f"Error: {error_msg}"
    
    def _run_multiple_tools(self, tool_names: list, args: dict, user_input: str) -> str:
        """Run multiple tools and merge/deduplicate results"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        # Ensure arg compatibility (some tools need target, some domain)
        if "domain" in args and "target" not in args:
            args["target"] = args["domain"]
        elif "target" in args and "domain" not in args:
            args["domain"] = args["target"]
            
        print(f"🔧 Running {len(tool_names)} tools: {', '.join(tool_names)}...")
        
        all_results = {}
        errors = []
        
        # Run tools in parallel
        def run_tool(name):
            try:
                tool = self.tool_map[name]
                # Handle both LangChain tools (.invoke) and plain functions
                if hasattr(tool, 'invoke'):
                    return name, tool.invoke(args)
                elif callable(tool):
                    return name, tool(**args)
                else:
                    return name, {"error": f"Tool {name} is not callable"}
            except Exception as e:
                return name, {"error": str(e)}
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(run_tool, name): name for name in tool_names}
            for future in as_completed(futures):
                name, result = future.result()
                all_results[name] = result
                if isinstance(result, dict) and "error" in result:
                    errors.append(f"{name}: {result['error']}")
                else:
                    print(f"  ✓ {name} completed")
        
        # Merge and deduplicate results
        merged = self._merge_results(all_results)
        
        # Convert to string for display
        result_str = json.dumps(merged, indent=2, default=str)
        
        # Save merged result to file
        result_file = None
        if self.save_results_to_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Use 'multi_' prefix only when 2+ tools were used
            if len(tool_names) == 1:
                filename = f"{tool_names[0]}_{timestamp}.json"
            else:
                filename = f"multi_{'_'.join(tool_names[:3])}_{timestamp}.json"
            result_file = self.results_dir / filename
            with open(result_file, 'w') as f:
                json.dump({
                    "tools": tool_names,
                    "args": args,
                    "timestamp": datetime.now().isoformat(),
                    "user_query": user_input,
                    "merged_result": merged,
                    "individual_results": all_results
                }, f, indent=2, default=str)
        
        # Save to memory
        self.last_result = merged
        self.messages.append(HumanMessage(content=user_input))
        self.messages.append(AIMessage(content=f"[Used {', '.join(tool_names)}]\n{result_str[:2000]}"))
        self._save_session()
        
        # Build output
        output_parts = []
        
        if self.show_raw_results:
            # Show nice formatted summary instead of raw JSON
            stats = merged.get("stats", {})
            if len(tool_names) == 1:
                output_parts.append(f"📊 **Result from {tool_names[0]}**:\n")
            else:
                output_parts.append(f"📊 **Merged Results from {len(tool_names)} tools** ({', '.join(tool_names)}):\n")
            output_parts.append(f"   • Sources: {', '.join(merged.get('sources', []))}")
            output_parts.append(f"   • Subdomains: {stats.get('total_subdomains', 0)}")
            output_parts.append(f"   • Hosts/IPs: {len(merged.get('hosts', []))}")
            output_parts.append(f"   • Ports: {stats.get('total_ports', 0)}")
            output_parts.append(f"   • Services: {stats.get('total_services', 0)}")
            output_parts.append(f"   • Vulnerabilities: {stats.get('total_vulnerabilities', 0)}\n")
            
            # Show subdomains (limited)
            subdomains = merged.get("subdomains", [])
            if subdomains:
                output_parts.append("📋 **Subdomains found**:")
                for sub in subdomains[:30]:
                    output_parts.append(f"   • {sub}")
                if len(subdomains) > 30:
                    output_parts.append(f"   ... and {len(subdomains) - 30} more")
                output_parts.append("")
            
            # Show ports if any
            ports = merged.get("ports", [])
            if ports:
                output_parts.append(f"🔌 **Open Ports**: {', '.join(map(str, ports[:20]))}")
                output_parts.append("")
            
            if result_file:
                output_parts.append(f"💾 Full result saved to: `{result_file.name}`\n")
            if errors:
                output_parts.append(f"⚠️ Errors: {'; '.join(errors)}\n")
        
        # LLM analysis
        summary_messages = [
            SystemMessage(content="You are SNODE. These are merged results from multiple tools with duplicates removed. Summarize key findings."),
            HumanMessage(content=f"User asked: {user_input}\n\nMerged results from {', '.join(tool_names)}:\n{result_str[:4000]}")
        ]
        
        summary = self.llm.invoke(summary_messages)
        output_parts.append(f"\n🤖 **AI Analysis (from {len(tool_names)} tools)**:\n{summary.content}")
        
        return "\n".join(output_parts)
    
    def _merge_results(self, all_results: dict) -> dict:
        """Merge and deduplicate results from multiple tools"""
        merged = {
            "sources": list(all_results.keys()),
            "subdomains": set(),
            "hosts": set(),
            "ports": set(),
            "services": [],
            "vulnerabilities": [],
            "raw_data": {}
        }
        
        for tool_name, result in all_results.items():
            if isinstance(result, dict):
                # Handle subdomains
                for key in ["subdomains", "domains", "hosts"]:
                    if key in result and isinstance(result[key], (list, set)):
                        for item in result[key]:
                            if isinstance(item, str):
                                merged["subdomains"].add(item.lower().strip())
                            elif isinstance(item, dict) and "host" in item:
                                merged["subdomains"].add(item["host"].lower().strip())
                
                # Handle ports
                if "ports" in result:
                    for port in result["ports"]:
                        if isinstance(port, (int, str)):
                            merged["ports"].add(int(port) if str(port).isdigit() else port)
                        elif isinstance(port, dict) and "port" in port:
                            merged["ports"].add(port["port"])
                
                # Handle services (unique by name+port)
                if "services" in result:
                    for svc in result["services"]:
                        if svc not in merged["services"]:
                            merged["services"].append(svc)
                
                # Handle vulnerabilities
                if "vulnerabilities" in result or "vulns" in result:
                    vulns = result.get("vulnerabilities", result.get("vulns", []))
                    for vuln in vulns:
                        if vuln not in merged["vulnerabilities"]:
                            merged["vulnerabilities"].append(vuln)
                
                # Store raw data per tool
                merged["raw_data"][tool_name] = result
            
            elif isinstance(result, str):
                # Parse text results - extract subdomains from bullet points
                # Pattern: • subdomain.domain.com or - subdomain.domain.com
                import re
                subdomain_pattern = r'[•\-\*]\s*([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})'
                found = re.findall(subdomain_pattern, result)
                for sub in found:
                    # Filter out wildcards and normalize
                    if not sub.startswith('_'):
                        merged["subdomains"].add(sub.lower().strip())
                
                # Also try to find IPs
                ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
                ips = re.findall(ip_pattern, result)
                for ip in ips:
                    merged["hosts"].add(ip)
                
                # Try to find ports - be specific to avoid matching stats like "subdomains: 70"
                # Match patterns like: "port 80", "80/tcp", "443/udp"
                port_pattern = r'\b(?:port\s+(\d{1,5})|(\d{1,5})/(?:tcp|udp))\b'
                port_matches = re.findall(port_pattern, result, re.IGNORECASE)
                for match in port_matches:
                    port = match[0] or match[1]  # Get whichever group matched
                    if port and 1 <= int(port) <= 65535:
                        merged["ports"].add(int(port))
                
                merged["raw_data"][tool_name] = result
        
        # Convert sets to sorted lists for JSON serialization
        merged["subdomains"] = sorted(merged["subdomains"])
        merged["hosts"] = sorted(merged["hosts"])
        merged["ports"] = sorted([p for p in merged["ports"] if isinstance(p, int)])
        
        # Summary stats
        merged["stats"] = {
            "total_subdomains": len(merged["subdomains"]),
            "total_ports": len(merged["ports"]),
            "total_services": len(merged["services"]),
            "total_vulnerabilities": len(merged["vulnerabilities"])
        }
        
        return merged

    def clear_memory(self):
        """Clear conversation history"""
        self.messages = []
        self._save_session()  # Save cleared state
    
    def get_tools(self) -> list:
        """Get list of available tools including advanced tools, CVE RAG, and workflows"""
        tool_names = [tool.name for tool in self.tools]
        # Add advanced tools
        for tool_info in ADVANCED_TOOLS:
            tool_names.append(tool_info["name"])
        # Add CVE RAG tools
        if CVE_RAG_AVAILABLE:
            for tool_info in CVE_RAG_TOOLS:
                tool_names.append(tool_info["name"])
        # Add Workflow tools
        if WORKFLOW_TOOLS_AVAILABLE:
            for tool_info in WORKFLOW_TOOLS:
                tool_names.append(tool_info["name"])
        return tool_names
    
    def _save_session(self):
        """Save current session to JSON file"""
        try:
            session_data = {
                "session_id": self.session_id,
                "model": self.model_name,
                "created": datetime.now().isoformat(),
                "messages": [
                    {
                        "role": "human" if hasattr(msg, 'type') and msg.type == 'human' else "assistant",
                        "content": msg.content,
                        "timestamp": datetime.now().isoformat()
                    }
                    for msg in self.messages
                ]
            }
            with open(self.session_file, 'w') as f:
                json.dump(session_data, f, indent=2)
        except Exception as e:
            if self.verbose:
                print(f"Warning: Could not save session: {e}")
    
    def list_sessions(self) -> list:
        """List all saved sessions"""
        sessions = []
        for f in sorted(self.sessions_dir.glob("*.json"), reverse=True):
            try:
                with open(f, 'r') as fp:
                    data = json.load(fp)
                    sessions.append({
                        "id": data.get("session_id", f.stem),
                        "model": data.get("model", "unknown"),
                        "created": data.get("created", "unknown"),
                        "messages": len(data.get("messages", []))
                    })
            except:
                pass
        return sessions
    
    def load_session(self, session_id: str) -> bool:
        """Load a previous session by ID"""
        session_file = self.sessions_dir / f"{session_id}.json"
        if not session_file.exists():
            return False
        
        try:
            with open(session_file, 'r') as f:
                data = json.load(f)
            
            self.messages = []
            for msg in data.get("messages", []):
                if msg["role"] == "human":
                    self.messages.append(HumanMessage(content=msg["content"]))
                else:
                    self.messages.append(AIMessage(content=msg["content"]))
            
            self.session_id = session_id
            self.session_file = session_file
            return True
        except Exception as e:
            if self.verbose:
                print(f"Error loading session: {e}")
            return False


def create_agent(model: str = "deepseek-r1:latest", verbose: bool = False) -> SNODEAgent:
    """Factory function to create SNODE agent"""
    return SNODEAgent(model=model, verbose=verbose)
