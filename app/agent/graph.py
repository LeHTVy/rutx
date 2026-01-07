"""
LangGraph Agent - State Machine for Pentest Agent
==================================================

Proper agentic flow:
1. Intent Node (LLM) - Classify user input
2. Planner Node (LLM) - Suggest tools, NO auto-execution
3. Confirm Node - Wait for user approval
4. Executor Node (CODE) - Run tools via registry
5. Analyzer Node (LLM) - Decide DONE/CONTINUE

Key principle: LLM plans, CODE executes, LLM analyzes.
"""
from typing import TypedDict, List, Dict, Any, Literal, Optional, Annotated
from enum import Enum
import operator
import json
import re

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from app.llm import get_llm_config
from app.tools.registry import get_registry


# ============================================================
# STATE SCHEMA
# ============================================================

class Message(TypedDict):
    """A message in the conversation."""
    role: str  # "user" or "assistant"
    content: str


class AgentState(TypedDict):
    """State passed between nodes in the graph."""
    
    # User input
    query: str
    
    # Conversation history (persisted across turns)
    messages: List[Message]
    
    # Intent classification
    intent: str  # "security_task", "question", "confirm", "tool_select"
    
    # Planning
    suggested_tools: List[str]
    suggested_commands: Dict[str, str]  # {tool_name: command_name} from semantic search
    suggestion_message: str
    tool_params: Dict[str, Any]
    
    # Execution
    confirmed: bool
    selected_tools: List[str]
    execution_results: Dict[str, Any]
    
    # Memory/Context (accumulated)
    context: Annotated[Dict[str, Any], operator.or_]
    
    # Output
    response: str
    
    # Flow control
    next_action: str  # "plan", "confirm", "execute", "analyze", "respond", "end"


# ============================================================
# LLM CLIENT (LangChain-Ollama)
# ============================================================

# Global model setting for switching
_current_model = None

def get_current_model() -> str:
    """Get current model, defaulting to config."""
    global _current_model
    if _current_model:
        return _current_model
    config = get_llm_config()
    return config.get_model()

def set_current_model(model: str):
    """Set the global model for all LLM calls."""
    global _current_model
    _current_model = model
    print(f"  🔄 Model switched to: {model}")


class OllamaClient:
    """LangChain-Ollama client for LLM calls."""
    
    def __init__(self, model: str = None):
        self.model = model or get_current_model()
        self._llm = None
    
    def _get_llm(self):
        """Lazy initialization of ChatOllama."""
        if self._llm is None:
            from langchain_ollama import ChatOllama
            self._llm = ChatOllama(
                model=self.model,
                temperature=0.3,
                num_ctx=4096,
            )
        return self._llm
    
    def generate(self, prompt: str, system: str = None, timeout: int = 120) -> str:
        """Generate response using LangChain-Ollama."""
        try:
            import sys
            import threading
            import time
            
            # Spinner animation
            spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            spinner_running = True
            
            def spin():
                i = 0
                while spinner_running:
                    sys.stdout.write(f"\r  {spinner_chars[i % len(spinner_chars)]} Thinking ({self.model})...")
                    sys.stdout.flush()
                    time.sleep(0.1)
                    i += 1
            
            # Start spinner in background
            spinner_thread = threading.Thread(target=spin, daemon=True)
            spinner_thread.start()
            
            llm = self._get_llm()
            
            # Build messages
            from langchain_core.messages import HumanMessage, SystemMessage
            messages = []
            if system:
                messages.append(SystemMessage(content=system))
            messages.append(HumanMessage(content=prompt))
            
            # Invoke
            response = llm.invoke(messages)
            result = response.content if response else ""
            
            # Stop spinner
            spinner_running = False
            spinner_thread.join(timeout=0.5)
            
            if result:
                # Strip thinking tags from deepseek-r1
                import re
                result = re.sub(r'<think>.*?</think>', '', result, flags=re.DOTALL).strip()
                print(f"  ✅ LLM responded ({len(result)} chars)")
            return result
            
        except Exception as e:
            print(f"  ❌ LLM error: {e}")
            return ""


# ============================================================
# NODE IMPLEMENTATIONS
# ============================================================

def intent_node(state: AgentState) -> AgentState:
    """
    Classify user intent using LLM.
    
    Returns:
    - security_task: Needs tool execution (scan, exploit, enumerate, etc.)
    - memory_query: User wants to see stored data (subdomains, results, findings)
    - question: Simple question, answer directly
    - confirm: User confirming/denying previous suggestion
    """
    # Sanitize input - remove box-drawing characters and extra whitespace
    query = state["query"]
    # Remove common terminal box-drawing and special characters
    query = re.sub(r'[│┌┐└┘├┤┬┴┼─═║╔╗╚╝╠╣╦╩╬]', '', query)
    query = re.sub(r'\s+', ' ', query)  # Collapse whitespace
    query = query.lower().strip()
    
    suggested_tools = state.get("suggested_tools", [])
    context = state.get("context", {})
    
    # Quick confirmations (exact matches - no LLM needed)
    if query in ["yes", "y", "ok", "go", "run", "execute", "proceed"]:
        return {**state, "intent": "confirm", "confirmed": True}

    if suggested_tools and ("yes" in query or query.endswith(" y")):
        print(f"  📋 Confirming pending suggestion: {suggested_tools}")
        return {**state, "intent": "confirm", "confirmed": True}
    
    if query in ["no", "n", "cancel", "stop", "abort"]:
        return {**state, "intent": "confirm", "confirmed": False}
    
    if query.startswith(("yes", "ok", "let's", "lets", "go with")):
        is_short_confirmation = len(query) < 20
        
        selected = []
        for tool in suggested_tools:
            if tool.lower() in query:
                selected.append(tool)
        
        if selected:
            return {
                **state,
                "intent": "confirm",
                "confirmed": True,
                "selected_tools": selected
            }
        
        # Only confirm if we have pending tools AND query is short
        if suggested_tools and is_short_confirmation:
            return {**state, "intent": "confirm", "confirmed": True}
    
    # ============================================================
    # LLM-BASED INTENT CLASSIFICATION
    # ============================================================
    llm = OllamaClient()
    
    # Build context summary
    context_summary = ""
    if context.get("tools_run"):
        context_summary += f"Tools already run: {', '.join(context.get('tools_run', []))}\n"
    if context.get("subdomain_count"):
        context_summary += f"Subdomains found: {context.get('subdomain_count')}\n"
    if context.get("has_ports"):
        context_summary += "Port scan completed\n"
    if context.get("detected_tech"):
        context_summary += f"Technologies detected: {', '.join(context.get('detected_tech', [])[:5])}\n"
    if context.get("subdomains"):
        context_summary += f"Subdomains stored in memory: {len(context.get('subdomains', []))}\n"
    
    # Check if query contains a domain/IP - strong signal for SECURITY_TASK
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    has_domain = bool(re.search(domain_pattern, state["query"]))
    
    prompt = f'''Classify this user message for a penetration testing assistant.

USER MESSAGE: "{state["query"]}"

CONTEXT:
{context_summary if context_summary else "No prior context"}
{"NOTE: Message contains a domain/IP address" if has_domain else ""}

CLASSIFY AS ONE OF:
- SECURITY_TASK: User wants to RUN NEW SCANS or use security tools
  Examples: "scan the domain", "find vulnerabilities", "use nuclei", "run nmap"
  If the message mentions a domain/IP AND wants a NEW scan → SECURITY_TASK

- MEMORY_QUERY: User wants to SEE/RETRIEVE STORED DATA from previous scans
  Examples: "show me the subdomains", "list the results", "what did we find",
  "show the scan data", "display stored subdomains", "show me what's in database",
  "list findings", "what vulnerabilities were found", "show me the data",
  "show me emails", "list emails", "show hosts", "list IPs", "show ports",
  "show open ports", "list the emails", "what emails did we find",
  "show me the scan results", "list discovered paths", "show credentials"
  If user asks to SHOW/LIST/DISPLAY existing data → MEMORY_QUERY

- QUESTION: User is asking a conceptual question or needs explanation (no action)
  Examples: "what is XSS", "explain this CVE", "who are you", "how does SQL injection work"

Respond with ONLY one word: SECURITY_TASK or MEMORY_QUERY or QUESTION'''

    # ─────────────────────────────────────────────────────────
    # KEYWORD-BASED MEMORY QUERY DETECTION (before LLM call)
    # ─────────────────────────────────────────────────────────
    query_lower = state["query"].lower()
    
    # Check for memory query keywords
    memory_keywords = [
        "show me email", "list email", "show email",
        "show me subdomain", "list subdomain", "show subdomain",
        "show me host", "list host", "show host",
        "show me ip", "list ip", "show ip",
        "show me port", "list port", "show port", "show open port",
        "show me vuln", "list vuln", "show vuln",
        "show me path", "list path", "discovered path",
        "show me cred", "list cred", "cracked",
        "show me data", "show the data", "list data",
        "show me result", "show result", "list result",
        "show me finding", "list finding",
        "what did we find", "what was found",
        "show me asn", "list asn",
        "show me url", "list url", "interesting url",
        "show me exploit", "list exploit",
        "show me smb", "list smb", "smb share", "smb user",
        "show me wordpress", "wp user", "wp plugin",
        "show me technolog", "list technolog",
        "show me waf",
    ]
    
    for keyword in memory_keywords:
        if keyword in query_lower:
            print(f"  → Intent: MEMORY_QUERY (keyword: '{keyword}')")
            return {**state, "intent": "memory_query"}
    
    print("  🧠 LLM classifying intent...")
    
    try:
        response = llm.generate(prompt, timeout=30)
        response_clean = response.strip().upper().replace("_", "_")
        
        # Extract intent from response
        if "MEMORY" in response_clean or "QUERY" in response_clean:
            print("  → Intent: MEMORY_QUERY")
            return {**state, "intent": "memory_query"}
        elif "SECURITY" in response_clean or "TASK" in response_clean:
            print("  → Intent: SECURITY_TASK")
            return {**state, "intent": "security_task"}
        elif "QUESTION" in response_clean:
            print("  → Intent: QUESTION")
            return {**state, "intent": "question"}
        else:
            # Default to security_task if ambiguous (action-oriented)
            print(f"  → Intent: SECURITY_TASK (default, LLM said: {response[:50]})")
            return {**state, "intent": "security_task"}
    except Exception as e:
        print(f"  ⚠️ Intent LLM failed: {e}, defaulting to security_task")
        return {**state, "intent": "security_task"}


def infer_phase(context: dict, llm) -> dict:
    """
    LLM infers the current pentest phase based on context.
    
    Returns: {"phase": 1-4, "reason": "..."}
    
    Phase 1: Reconnaissance - No data yet, gathering info
    Phase 2: Scanning - Have targets, finding vulnerabilities
    Phase 3: Exploitation - Have vulns, attempting access
    Phase 4: Reporting - Have findings, documenting results
    """
    # Build context summary for LLM
    has_subdomains = context.get("has_subdomains", False)
    subdomain_count = context.get("subdomain_count", 0)
    has_ports = context.get("has_ports", False)
    open_ports = context.get("open_ports", [])
    vulns_found = context.get("vulns_found", [])
    services = context.get("services", [])
    tools_run = context.get("tools_run", [])
    exploits_run = context.get("exploits_run", [])
    
    # Quick heuristic first (no LLM call needed for obvious cases)
    if exploits_run or "sqlmap" in tools_run or "hydra" in tools_run or "msfconsole" in tools_run:
        return {"phase": 3, "reason": "Exploitation tools have been run"}
    
    if vulns_found or "nuclei" in tools_run or "nikto" in tools_run:
        return {"phase": 2, "reason": "Vulnerability scanning in progress"}
    
    if has_ports or open_ports or "nmap" in tools_run or "masscan" in tools_run:
        return {"phase": 2, "reason": "Port scanning completed, in scanning phase"}
    
    if has_subdomains or subdomain_count > 0:
        return {"phase": 2, "reason": "Subdomains found, ready for scanning"}
    
    if not tools_run:
        return {"phase": 1, "reason": "No tools run yet, starting reconnaissance"}
    
    # For ambiguous cases, ask LLM
    prompt = f'''You are a penetration testing expert. Analyze this context and determine the current pentest phase.

CURRENT CONTEXT:
- Subdomains found: {subdomain_count}
- Ports scanned: {has_ports}
- Open ports: {open_ports[:5] if open_ports else "none"}
- Vulnerabilities found: {len(vulns_found)} 
- Services detected: {services[:5] if services else "none"}
- Tools already run: {tools_run[-5:] if tools_run else "none"}
- Exploitation attempted: {bool(exploits_run)}

PENTEST PHASES:
1 = Reconnaissance (gathering info, OSINT, subdomains)
2 = Scanning & Enumeration (ports, services, vulnerabilities)
3 = Exploitation (exploiting vulns, gaining access)
4 = Reporting (documenting findings)

Return ONLY a JSON: {{"phase": 1, "reason": "brief explanation"}}'''

    try:
        response = llm.generate(prompt, timeout=30)
        # Clean response
        clean = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
        
        # Parse JSON
        import json
        match = re.search(r'\{[^}]+\}', clean)
        if match:
            result = json.loads(match.group())
            return {
                "phase": int(result.get("phase", 1)),
                "reason": result.get("reason", "LLM inference")
            }
    except Exception:
        pass
    
    # Default to phase 1 if inference fails
    return {"phase": 1, "reason": "Default - starting reconnaissance"}


def planner_node(state: AgentState) -> AgentState:
    """
    LLM suggests tools using SEMANTIC SEARCH + CONSTRAINED OUTPUT.
    
    Architecture:
    1. Infer current pentest phase from context
    2. Semantic search finds candidate tools from ToolIndex
    3. LLM chooses from candidates ONLY (constrained by phase)
    4. No keyword detection - pure semantic + LLM reasoning
    """
    from app.rag.tool_index import ToolIndex
    from app.rag.tool_metadata import PHASE_NAMES, get_tool_phase
    
    llm = OllamaClient()
    context = state.get("context", {})
    
    # Extract domain/IP from user query if not in context
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    url_pattern = r'https?://[^\s]+'
    
    # First check for full URL
    url_match = re.search(url_pattern, state["query"])
    if url_match:
        context["url_target"] = url_match.group()
        print(f"  🔗 Extracted URL: {url_match.group()}")
    
    # Check for IP address
    ip_match = re.search(ip_pattern, state["query"])
    if ip_match:
        ip = ip_match.group()
        context["target_ip"] = ip
        context["last_domain"] = ip  # Use IP as domain for tools
        print(f"  🎯 Extracted IP address: {ip}")
        domain = ip
    else:
        domain_match = re.search(domain_pattern, state["query"])
        if domain_match:
            domain = domain_match.group()
            # Filter provider domains from context, but keep for targeting
            provider_domains = ['windows.net', 'azure.', 'microsoft.', 'amazonaws.', 'cloudfront.', 'google.', 'facebook.']
            if not any(x in domain.lower() for x in provider_domains):
                context["last_domain"] = domain
                print(f"  🎯 Extracted domain from query: {domain}")
            else:
                # It's a provider URL - still use it as target but don't save to context
                if not context.get("last_domain"):
                    context["target_domain"] = domain  # Temporary target
                domain = context.get("last_domain", domain)  # Fallback to provider domain if no context
                print(f"  ℹ️ Provider URL detected, using: {domain}")
        else:
            domain = context.get("last_domain", "")
    
    # === STEP 0: DETECT USER-MENTIONED TOOLS ===
    from app.tools.registry import get_registry
    registry = get_registry()
    all_tools = registry.list_tools()
    user_mentioned_tools = []
    query_lower = state["query"].lower()
    for tool in all_tools:
        if tool.lower() in query_lower:
            user_mentioned_tools.append(tool)
    
    if user_mentioned_tools:
        print(f"  🎯 User mentioned tools: {user_mentioned_tools}")
    
    # === STEP 0.5: INFER CURRENT PENTEST PHASE ===
    phase_info = infer_phase(context, llm)
    current_phase = phase_info.get("phase", 1)
    phase_reason = phase_info.get("reason", "")
    context["current_phase"] = current_phase
    print(f"  📊 Phase {current_phase} ({PHASE_NAMES.get(current_phase, 'Unknown')}): {phase_reason}")
    
    # === STEP 1: SEMANTIC SEARCH FOR CANDIDATE TOOLS + COMMANDS ===
    tool_command_map = {}  # {tool_name: best_command}
    try:
        tool_index = ToolIndex()
        candidates = tool_index.search(state["query"], n_results=10)  # Get more for command variety
        
        # Extract tool:command mappings from semantic search
        for c in candidates:
            tool_name = c.get("name", "")
            command_name = c.get("command", "")
            # Keep first (best scoring) command for each tool
            if tool_name and tool_name not in tool_command_map:
                tool_command_map[tool_name] = command_name
        
        print(f"  🔍 Semantic search found: {list(tool_command_map.keys())}")
        if any(tool_command_map.values()):
            print(f"  📋 Commands: {tool_command_map}")
    except Exception as e:
        print(f"  ⚠️ Tool index error: {e}, using fallback")
        candidates = []
    
    # FORCE user-mentioned tools into candidates if not already there
    candidate_names = [c["name"] for c in candidates]
    for tool in user_mentioned_tools:
        if tool not in candidate_names:
            # Add user-mentioned tool to candidates
            spec = registry.tools.get(tool)
            if spec:
                candidates.insert(0, {"name": tool, "description": spec.description})
                print(f"  ➕ Added user-requested tool: {tool}")
    
    # If no candidates found, ask user to clarify
    if not candidates:
        return {
            **state,
            "response": "❓ I couldn't find matching tools for your request.\n\nPlease be more specific (e.g., 'scan for vulnerabilities' or 'find subdomains').",
            "next_action": "end"
        }
    
    # Build candidate list for LLM
    candidate_names = [c["name"] for c in candidates]
    candidate_str = "\n".join([f"- {c['name']}: {c['description']}" for c in candidates])
    
    # === SHORTCUT: If user explicitly named tools, use them directly (skip LLM) ===
    if user_mentioned_tools:
        # Get commands for user-mentioned tools from semantic search
        user_commands = {t: tool_command_map.get(t, "") for t in user_mentioned_tools}
        print(f"  ✅ Using user-requested tools directly: {user_mentioned_tools}")
        if any(user_commands.values()):
            print(f"  📋 With commands: {user_commands}")
        return {
            **state,
            "suggested_tools": user_mentioned_tools,
            "suggested_commands": user_commands,
            "suggestion_message": f"Running {', '.join(user_mentioned_tools)} as requested.",
            "tool_params": {"domain": domain} if domain else {},
            "context": context,
            "next_action": "confirm"
        }
    
    # === STEP 2: CONSTRAINED LLM SELECTION (only if user didn't specify tools) ===
    context_str = ""
    if context.get("has_subdomains"):
        count = context.get("subdomain_count", 0)
        context_str += f"• Found {count} subdomains\n"
    if context.get("has_ports"):
        context_str += "• Port scan completed\n"
    if context.get("subdomains"):
        subs = context.get("subdomains", [])[:5]
        context_str += f"• Subdomains: {', '.join(subs)}...\n"
    
    # Add OPEN PORTS information for intelligent brute-force tool selection
    open_ports_raw = context.get("open_ports", [])
    # Extract port numbers (could be dicts with 'port' key or raw ints)
    open_ports = []
    for p in open_ports_raw:
        if isinstance(p, dict):
            open_ports.append(p.get("port", 0))
        else:
            open_ports.append(int(p) if str(p).isdigit() else 0)
    open_ports = [p for p in open_ports if p > 0]
    
    if open_ports:
        context_str += f"• OPEN PORTS: {', '.join(str(p) for p in open_ports[:20])}\n"
        # Map ports to services for LLM
        port_services = {
            22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 445: "SMB",
            3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle",
            80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 2082: "cPanel", 2083: "cPanel-SSL",
            2086: "WHM", 2087: "WHM-SSL", 25: "SMTP", 110: "POP3", 143: "IMAP"
        }
        detected_services = [port_services.get(p) for p in open_ports if p in port_services]
        if detected_services:
            context_str += f"• SERVICES AVAILABLE: {', '.join(set(detected_services))}\n"
    else:
        context_str += "• NO PORT SCAN completed yet (run nmap first before brute-force)\n"
    
    tools_run = context.get("tools_run", [])
    if tools_run:
        context_str += f"• Already ran: {', '.join(tools_run)}\n"
    
    # === CVE-AWARE CONTEXT ENHANCEMENT ===
    cve_context = ""
    detected_tech = context.get("detected_tech", [])
    if detected_tech:
        try:
            from app.rag.unified_memory import get_unified_rag
            rag = get_unified_rag()
            relevant_cves = rag.search_cves_for_tech(detected_tech[:3])
            
            if relevant_cves:
                cve_context = "\n• Relevant CVEs for detected technologies:\n"
                for cve in relevant_cves[:3]:
                    cve_id = cve.get("cve_id", "Unknown")
                    desc = cve.get("description", "")[:80]
                    cve_context += f"  - {cve_id}: {desc}...\n"
                print(f"  🔐 Found {len(relevant_cves)} relevant CVEs for {detected_tech[:3]}")
        except Exception as e:
            pass  # CVE enhancement is optional
    
    # === CONVERSATION CONTEXT ENHANCEMENT ===
    conv_context = ""
    try:
        from app.rag.unified_memory import get_unified_rag
        rag = get_unified_rag()
        past_context = rag.get_relevant_context(state["query"], domain)
        
        if past_context.get("tool_executions"):
            conv_context = "\n• Recent relevant tool executions:\n"
            for exec_info in past_context["tool_executions"][:2]:
                conv_context += f"  - {exec_info.get('tool', 'unknown')}: {exec_info.get('content', '')[:60]}...\n"
    except Exception:
        pass  # Conversation context is optional
    
    prompt = f'''Choose the best tool(s) for this security task.

USER REQUEST: {state["query"]}

CURRENT PENTEST PHASE: {current_phase} - {PHASE_NAMES.get(current_phase, "Unknown")}
(1=Recon, 2=Scanning, 3=Exploitation, 4=Reporting)

CANDIDATE TOOLS (choose ONLY from these):
{candidate_str}

CONTEXT:
{context_str if context_str else "No prior data"}{cve_context}{conv_context}

RULES:
- Choose ONLY from the candidate tools listed above
- Prioritize tools appropriate for the current phase
- Phase 1 (Recon): subdomain discovery, OSINT, DNS enumeration
- Phase 2 (Scanning): port scanning, vulnerability scanning, service detection
- Phase 3 (Exploitation): exploiting vulns, brute-force, gaining access
- **CRITICAL: If user explicitly names tools, include ALL requested tools**
- If user doesn't specify tools, pick the single best one for the current phase
- If CVEs are mentioned, prefer tools that can detect them (like nuclei)

**BRUTE-FORCE RULES (CRITICAL):**
- ONLY suggest hydra/medusa for SSH if port 22 is in OPEN PORTS
- ONLY suggest hydra/medusa for FTP if port 21 is in OPEN PORTS
- ONLY suggest hydra/medusa for RDP if port 3389 is in OPEN PORTS
- ONLY suggest cpanelbrute if port 2083/2087 is in OPEN PORTS
- If no port scan done yet, suggest nmap FIRST before brute-force tools
- DO NOT suggest brute-force tools for services that are not confirmed open!

- Return JSON: {{"tools": ["tool1", "tool2"], "message": "I suggest..."}}
- "tools" should be an ARRAY, even if only one tool

Return ONLY valid JSON, no extra text.'''

    response = llm.generate(prompt, timeout=60)
    
    # Remove thinking tags (deepseek-r1)
    clean_response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
    
    # === STEP 3: PARSE AND VALIDATE ===
    tools = []
    message = ""
    params = {"domain": domain} if domain else {}
    
    # Try JSON extraction
    try:
        json_match = re.search(r'\{[^{}]*\}', clean_response, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            
            # Handle both "tools" (array) and "tool" (string) for compatibility
            raw_tools = data.get("tools") or data.get("tool", [])
            if isinstance(raw_tools, str):
                raw_tools = [raw_tools]
            
            message = data.get("message", "")
            
            # Validate all tools are in candidates
            valid_tools = [t for t in raw_tools if t in candidate_names]
            if valid_tools:
                tools = valid_tools
                print(f"  ✅ LLM selected: {tools} (validated)")
            else:
                print(f"  ⚠️ LLM selected '{raw_tools}' but not in candidates, using top candidate")
                tools = [candidate_names[0]]
                message = f"I suggest using {candidate_names[0]} for this task."
    except json.JSONDecodeError:
        print(f"  ⚠️ JSON parse error")
    
    # NO FALLBACK - If LLM didn't return valid tools, fail clearly
    if tools:
        # Get commands for selected tools from semantic search results
        selected_commands = {t: tool_command_map.get(t, "") for t in tools}
        if any(selected_commands.values()):
            print(f"  📋 With commands: {selected_commands}")
        return {
            **state,
            "suggested_tools": tools,
            "suggested_commands": selected_commands,
            "suggestion_message": message or f"I suggest using {tools[0]} for this task.",
            "tool_params": params,
            "context": context,
            "next_action": "confirm"
        }
    
    # LLM failed to respond properly - clear error, no hardcoded fallback
    return {
        **state,
        "response": "⚠️ LLM failed to select a tool. Please try again or specify a tool directly (e.g., 'run nmap on example.com').",
        "next_action": "end"
    }



def confirm_node(state: AgentState) -> AgentState:
    """
    Handle user confirmation.
    
    This node is reached when user responds to a suggestion.
    User can say "yes lets use amass" to select specific tools.
    """
    if state.get("confirmed", False):
        selected = state.get("selected_tools") or state.get("tools") or state.get("suggested_tools", [])
        
        print(f"  ✓ User confirmed. Running: {selected}")
        
        return {
            **state,
            "selected_tools": selected,
            "next_action": "executor"
        }
    else:
        # User declined
        return {
            **state,
            "response": "Cancelled. What would you like to do instead?",
            "next_action": "respond"
        }


def validate_tool_params(tool_name: str, command: str, params: dict, registry) -> tuple:
    """
    Validate that all required parameters are available for a tool command.
    Returns (is_valid, missing_params, error_message).
    """
    spec = registry.tools.get(tool_name)
    if not spec:
        return False, [], f"Tool not found: {tool_name}"
    
    template = spec.commands.get(command) if command else None
    if not template:
        # Try default command
        default_cmds = ["scan", "quick", "quick_scan", "enum", "default"]
        for cmd in default_cmds:
            if cmd in spec.commands:
                template = spec.commands[cmd]
                break
    
    if not template:
        return False, [], f"No command found for {tool_name}"
    
    # Extract required params from args template
    import re
    missing = []
    for arg in template.args:
        placeholders = re.findall(r'\{(\w+)\}', arg)
        for p in placeholders:
            if not params.get(p):
                missing.append(p)
    
    if missing:
        return False, missing, f"Missing parameters: {', '.join(missing)}"
    
    return True, [], ""


def get_adaptive_timeout(base_timeout: int, context: dict, tool_name: str) -> int:
    """
    Scale timeout based on number of targets and tool type.
    """
    n_subdomains = len(context.get("subdomains", []))
    n_ports = len(context.get("open_ports", []))
    
    # Base scaling factor
    scale = 1
    
    # Scale for multi-target scans
    if n_subdomains > 10:
        scale = max(scale, n_subdomains // 10)
    
    # Minimum timeouts for slow tools
    min_timeouts = {
        "nmap": 300,
        "nuclei": 600,
        "wpscan": 300,
        "nikto": 300,
        "amass": 600,
        "masscan": 300,
    }
    
    min_t = min_timeouts.get(tool_name, base_timeout)
    scaled = max(min_t, base_timeout * scale)
    
    # Cap at 30 minutes
    return min(scaled, 1800)

def executor_node(state: AgentState) -> AgentState:
    """
    Execute tools via registry.
    
    This is PURE CODE - no LLM involvement.
    Auditable, safe, controlled.
    """
    registry = get_registry()
    results = {}
    context = state.get("context", {})
    
    tools = state.get("selected_tools", [])
    params = state.get("tool_params", {})
    
    # CRITICAL: Ensure domain is in params from context
    if not params.get("domain") and context.get("last_domain"):
        params["domain"] = context.get("last_domain")
    if not params.get("domain") and context.get("target_domain"):
        params["domain"] = context.get("target_domain")
        
    if not params.get("target") and context.get("last_domain"):
        params["target"] = context.get("last_domain")
    if not params.get("target") and context.get("target_domain"):
        params["target"] = context.get("target_domain")
    
    # Use full URL if available (for web-based attacks)
    if not params.get("url") and context.get("url_target"):
        params["url"] = context.get("url_target")
        # Also extract domain from URL for target
        url = context.get("url_target")
        if url and not params.get("target"):
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            params["target"] = parsed.netloc
            params["domain"] = parsed.netloc
    
    # Also build URL for web tools if needed
    domain = params.get("domain") or params.get("target")
    if domain and not params.get("url"):
        params["url"] = f"https://{domain}"
    
    # Also set host for tools that need it
    if domain and not params.get("host"):
        params["host"] = domain
    
    # ============================================================
    # DEFAULT PARAMETERS FOR COMMON TOOLS
    # ============================================================
    
    # Default wordlist paths (common Kali/SecLists locations)
    if not params.get("wordlist"):
        # Try common wordlist locations
        import os
        wordlist_paths = [
            "wordlists/common.txt", 
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ]
        for wl in wordlist_paths:
            if os.path.exists(wl):
                params["wordlist"] = wl
                break
        if not params.get("wordlist"):
            # Fallback - use local wordlist
            params["wordlist"] = "wordlists/common.txt"
    
    # For brute-force tools, use password wordlist instead of directory wordlist
    if any(t in ["hydra", "medusa", "john", "hashcat"] for t in tools):
        import os
        password_lists = [
            "wordlists/passwords.txt",
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        ]
        for pwl in password_lists:
            if os.path.exists(pwl):
                params["wordlist"] = pwl
                break
    
    # Default user for brute-force tools (hydra, medusa)
    if not params.get("user"):
        params["user"] = "admin"  # Most common default username
    
    # Default port for nikto if not specified
    if not params.get("port"):
        params["port"] = "443"
    
    # Default ports for port scanners (masscan, nmap)
    # Based on 18 critical hacker ports + common web ports
    if not params.get("ports"):
        # Organized by category:
        # "Dinosaur" (legacy clear-text): 21 FTP, 23 Telnet, 80 HTTP
        # "Steel Door" (secure): 22 SSH, 443 HTTPS
        # "Mail": 25 SMTP, 110 POP3, 143 IMAP, 993 IMAPS, 995 POP3S
        # "Infrastructure": 53 DNS, 67-68 DHCP, 123 NTP
        # "Treasure" (control+data): 139 NetBIOS, 445 SMB, 3389 RDP
        # "Database": 1433 MSSQL, 1521 Oracle, 3306 MySQL, 5432 PostgreSQL
        # "Web Alt": 8080, 8443, 8888
        params["ports"] = "21,22,23,25,53,67,68,80,110,123,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443,8888"
    
    # Default query for searchsploit (use domain/tech if available)
    if not params.get("query"):
        detected_tech = context.get("detected_tech", [])
        if detected_tech:
            params["query"] = detected_tech[0]  # Use first detected tech
        else:
            params["query"] = params.get("domain") or params.get("target") or "apache"
    
    # Clean, simplified output - only show what matters
    target_display = params.get("url") or params.get("target") or params.get("domain") or "unknown"
    
    # TODO: Parallel execution - requires refactoring executor into _execute_tool helper
    # For now, run tools sequentially
    if len(tools) > 1:
        print(f"  🚀 Executing {len(tools)} tools SEQUENTIALLY: {', '.join(tools)} on {target_display}")
    else:
        print(f"  🚀 Executing: {', '.join(tools)} on {target_display}")
    
    for tool_name in tools:
        if not registry.is_available(tool_name):
            results[tool_name] = {
                "success": False,
                "output": f"Tool not available: {tool_name}"
            }
            continue
        
        spec = registry.tools.get(tool_name)
        if not spec or not spec.commands:
            results[tool_name] = {
                "success": False,
                "output": f"No commands for: {tool_name}"
            }
            continue
        
        # ============================================================
        # CLATSCOPE OSINT - Python-based, not CLI
        # ============================================================
        if tool_name == "clatscope":
            from app.tools.specs.osint import execute_clatscope, format_clatscope_result
            
            # Determine which OSINT command to run based on params/query
            osint_command = params.get("command", "whois")  # Default to whois
            
            # Auto-detect command from params
            if params.get("ip") or params.get("target"):
                if params.get("ip"):
                    osint_command = "ip"
            if params.get("phone"):
                osint_command = "phone"
            if params.get("email"):
                osint_command = "breach" if "breach" in str(params) else "email"
            
            print(f"  🔍 OSINT: {osint_command}")
            
            osint_result = execute_clatscope(osint_command, params)
            formatted = format_clatscope_result(osint_command, osint_result)
            
            results[tool_name] = {
                "success": osint_result.get("success", False),
                "output": formatted,
                "data": osint_result.get("data")
            }
            
            # Update context with OSINT findings
            if osint_result.get("success"):
                data = osint_result.get("data", {})
                if osint_command == "subdomain" and data.get("subdomains"):
                    context["subdomains"] = data["subdomains"]
                    context["subdomain_count"] = len(data["subdomains"])
                    context["has_subdomains"] = True
            
            continue
        
        tool_params = params.copy()
        domain = params.get("domain", params.get("target", ""))
        subdomains = context.get("subdomains", [])
        
        # PRIORITY 1: Use command from semantic search (via suggested_commands)
        suggested_commands = state.get("suggested_commands", {})
        command = suggested_commands.get(tool_name)
        if command:
            print(f"  📋 Using semantic command: {tool_name}:{command}")
        
        BATCH_SIZE = 50 
        
        if tool_name in ["nmap", "masscan", "nuclei"] and subdomains:
            total_targets = len(subdomains)
            all_outputs = []
            
            num_batches = (total_targets + BATCH_SIZE - 1) // BATCH_SIZE
            
            if num_batches > 1:
                print(f"  📋 Scanning {total_targets} targets in {num_batches} batches")
            
            for batch_num in range(num_batches):
                start_idx = batch_num * BATCH_SIZE
                end_idx = min(start_idx + BATCH_SIZE, total_targets)
                batch_targets = subdomains[start_idx:end_idx]
                
                # Write batch to temp file
                target_file = f"/tmp/snode_targets_{domain.replace('.', '_')}_batch{batch_num+1}.txt"
                with open(target_file, 'w') as f:
                    f.write('\n'.join(batch_targets))
                
                # Only show batch progress for multiple batches
                if num_batches > 1:
                    print(f"  📦 Batch {batch_num+1}/{num_batches}: {len(batch_targets)} targets")
                
                # Configure tool for batch
                batch_params = tool_params.copy()
                if tool_name == "nmap":
                    command = "from_file"
                    batch_params["file"] = target_file
                    batch_params["ports"] = "22,80,443,8080,8443"
                elif tool_name == "nuclei":
                    # Use scan_list for batch targets
                    batch_params["file"] = target_file
                    command = "scan_list"
                elif tool_name == "masscan":
                    batch_params["target"] = target_file
                    command = "scan"
                
                # Execute batch
                batch_result = registry.execute(tool_name, command, batch_params)
                
                if batch_result.success:
                    all_outputs.append(f"=== Batch {batch_num+1} ({len(batch_targets)} targets) ===\n{batch_result.output}")
                else:
                    all_outputs.append(f"=== Batch {batch_num+1} FAILED ===\n{batch_result.error}")
            
            # Combine all batch results
            combined_output = "\n\n".join(all_outputs)
            results[tool_name] = {
                "success": True,
                "output": combined_output,
                "batches": num_batches,
                "total_targets": total_targets
            }
            
            # Update context with scan info
            context["has_ports"] = True
            context["last_scan"] = {"tool": tool_name, "targets": total_targets}
            continue  # Skip the normal execution below
            
        else:
            # Single target mode
            if tool_name in ["nuclei", "nmap", "masscan"]:
                tool_params["target"] = domain
            if tool_name in ["wpscan", "nikto", "httpx", "katana", "wafw00f", "whatweb", "arjun", "dirsearch", "feroxbuster"]:
                tool_params["url"] = f"https://{domain}" if domain and not domain.startswith("http") else domain
            if tool_name in ["subfinder", "amass", "bbot", "dig"]:
                tool_params["domain"] = domain
            
            # SHODAN: Smart command selection based on target type
            if tool_name == "shodan":
                import re
                target = domain or params.get("target", "")
                # Check if target is an IP address
                ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                if re.match(ip_pattern, target):
                    command = "host"
                    tool_params["target"] = target
                    print(f"  🔍 Shodan: Using 'host' for IP {target}")
                else:
                    # Use search with hostname: filter (works on free tier)
                    # domain command requires paid API
                    command = "search"
                    tool_params["query"] = f"hostname:{target}"
                    print(f"  🔍 Shodan: Using 'search hostname:{target}'")
            
            # Exploit tools need special handling
            if tool_name == "msfconsole":
                # Build search command based on detected tech or ports
                detected_tech = context.get("detected_tech", [])
                if detected_tech:
                    search_term = detected_tech[0] if detected_tech else "apache"
                else:
                    search_term = "apache"  # Default search
                tool_params["command"] = f"search {search_term}; exit"
                print(f"  🔴 MSF command: search {search_term}")
            
            if tool_name == "searchsploit":
                # Use domain or detected tech as search query
                query = tool_params.get("query", "")
                if not query:
                    detected_tech = context.get("detected_tech", [])
                    if detected_tech:
                        tool_params["query"] = detected_tech[0]
                    else:
                        tool_params["query"] = domain or "apache"
            
        # ============================================================
        # COMMAND SELECTION: Trust semantic search, use default as fallback
        # ============================================================
        # The semantic search already picked the best command for the context.
        # No hardcoded keyword matching - pure semantic + LLM reasoning.
        
        if command is None:
            available_commands = list(spec.commands.keys())
            # Use first available command as default
            command = available_commands[0] if available_commands else None
        
        print(f"  🔧 Executing {tool_name}:{command}")
        
        # ============================================================
        # VALIDATE PARAMETERS BEFORE EXECUTION
        # ============================================================
        is_valid, missing, error_msg = validate_tool_params(tool_name, command, tool_params, registry)
        if not is_valid and missing:
            # Try to auto-fill missing params with defaults
            for param in missing:
                if param == "wordlist" and not tool_params.get("wordlist"):
                    tool_params["wordlist"] = "wordlists/common.txt"
                elif param == "user" and not tool_params.get("user"):
                    tool_params["user"] = "admin"
                elif param == "ports" and not tool_params.get("ports"):
                    tool_params["ports"] = "22,80,443,8080,8443"
                elif param == "target" and not tool_params.get("target"):
                    tool_params["target"] = params.get("domain", "")
            
            # Re-validate after auto-fill
            is_valid, still_missing, _ = validate_tool_params(tool_name, command, tool_params, registry)
            if not is_valid and still_missing:
                results[tool_name] = {
                    "success": False,
                    "output": f"Missing required params: {', '.join(still_missing)}"
                }
                print(f"  ⚠️ Skipping {tool_name}: missing {', '.join(still_missing)}")
                continue
        
        # Get adaptive timeout based on target count
        spec = registry.tools.get(tool_name)
        template = spec.commands.get(command) if spec and command else None
        base_timeout = template.timeout if template else 300
        timeout = get_adaptive_timeout(base_timeout, context, tool_name)
        
        # Define callback for streaming output
        import sys
        def stream_callback(line: str):
            """Print each line of output in real-time."""
            if line.strip():
                # Use ANSI colors for immediate output
                GREEN = "\033[32m"
                RED = "\033[31m"
                YELLOW = "\033[33m"
                DIM = "\033[2m"
                RESET = "\033[0m"
                
                if "open" in line.lower() or "found" in line.lower():
                    sys.stdout.write(f"    {GREEN}{line}{RESET}\n")
                elif "error" in line.lower() or "failed" in line.lower():
                    sys.stdout.write(f"    {RED}{line}{RESET}\n")
                elif "warning" in line.lower():
                    sys.stdout.write(f"    {YELLOW}{line}{RESET}\n")
                else:
                    sys.stdout.write(f"    {DIM}{line}{RESET}\n")
                sys.stdout.flush()
        
        # Use streaming execution with adaptive timeout
        result = registry.execute_stream(
            tool_name, 
            command, 
            tool_params,
            timeout_override=timeout,
            line_callback=stream_callback
        )
        
        results[tool_name] = {
            "success": result.success,
            "output": result.output,
            "error": result.error
        }
        
        # Update context
        if result.success:
            output = result.output
            
            # ─────────────────────────────────────────────────────────
            # SUBDOMAIN ENUMERATION TOOLS
            # ─────────────────────────────────────────────────────────
            if tool_name in ["subfinder", "amass", "bbot"]:
                context["has_subdomains"] = True
                context["last_domain"] = params.get("domain", "")
                # Store actual subdomains - filter out garbage
                lines = output.strip().split("\n")
                import re
                # Valid subdomain pattern: alphanumeric with dots, no spaces
                subdomain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$')
                subdomains = []
                for line in lines:
                    line = line.strip()
                    # Skip empty lines, lines with spaces (not subdomains), IP ranges, URLs
                    if not line or ' ' in line or '/' in line or 'http' in line.lower():
                        continue
                    # Must look like a valid subdomain
                    if subdomain_pattern.match(line) and len(line) > 4:
                        subdomains.append(line)
                context["subdomain_count"] = len(subdomains)
                context["subdomains"] = subdomains[:50]  # Store up to 50
            
            # ─────────────────────────────────────────────────────────
            # PORT SCANNING TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "nmap":
                context["has_ports"] = True
                context["last_target"] = params.get("target", "")
                
                # Parse open ports with service info
                open_ports = []
                import re
                # Match lines like: 22/tcp   open  ssh     OpenSSH 8.2
                port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?'
                for match in re.finditer(port_pattern, output):
                    port_info = {
                        "port": int(match.group(1)),
                        "protocol": match.group(2),
                        "service": match.group(3),
                        "version": match.group(4).strip() if match.group(4) else ""
                    }
                    open_ports.append(port_info)
                
                if open_ports:
                    context["open_ports"] = open_ports
                    context["port_count"] = len(open_ports)
                
                # Parse OS detection
                os_match = re.search(r'OS details?:\s*(.+)', output)
                if os_match:
                    context["os_detected"] = os_match.group(1).strip()
            
            elif tool_name == "masscan":
                context["has_ports"] = True
                context["last_target"] = params.get("target", "")
                
                # Parse masscan output: "open tcp 80 192.168.1.1"
                import re
                open_ports = []
                port_pattern = r'open\s+(tcp|udp)\s+(\d+)\s+(\S+)'
                for match in re.finditer(port_pattern, output):
                    open_ports.append({
                        "port": int(match.group(2)),
                        "protocol": match.group(1),
                        "ip": match.group(3)
                    })
                if open_ports:
                    context["open_ports"] = open_ports
                    context["port_count"] = len(open_ports)
            
            elif tool_name == "httpx":
                context["has_http_probes"] = True
                # Parse httpx output with status codes and tech
                http_probes = []
                for line in output.strip().split("\n"):
                    if line.strip() and ("http://" in line or "https://" in line):
                        http_probes.append(line.strip())
                if http_probes:
                    context["http_probes"] = http_probes[:50]
                
                # Detect WAF/CDN from response patterns
                try:
                    from app.rag.security_tech import SECURITY_TECH_DB
                    detected_security = []
                    output_lower = output.lower()
                    
                    for tech_id, tech in SECURITY_TECH_DB.items():
                        for pattern in tech.detection_patterns:
                            if pattern.lower() in output_lower:
                                detected_security.append(tech_id)
                                break
                    
                    if detected_security:
                        context["detected_security_tech"] = list(set(detected_security))
                        print(f"  🛡️ Security tech detected: {', '.join(detected_security)}")
                except Exception:
                    pass
            
            # ─────────────────────────────────────────────────────────
            # VULNERABILITY SCANNING TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "nuclei":
                context["has_nuclei"] = True
                context["vuln_scan_done"] = True
                
                # Parse nuclei findings: [severity] [template-id] matched
                import re
                vulnerabilities = []
                # Match: [critical] [cve-2021-xxxx] http://target
                vuln_pattern = r'\[(critical|high|medium|low|info)\]\s*\[([^\]]+)\]\s*(.+)'
                for match in re.finditer(vuln_pattern, output, re.IGNORECASE):
                    vulnerabilities.append({
                        "severity": match.group(1).lower(),
                        "template": match.group(2),
                        "matched": match.group(3).strip()
                    })
                if vulnerabilities:
                    context["vulnerabilities"] = vulnerabilities
                    context["vuln_count"] = len(vulnerabilities)
                    # Count by severity
                    context["critical_vulns"] = len([v for v in vulnerabilities if v["severity"] == "critical"])
                    context["high_vulns"] = len([v for v in vulnerabilities if v["severity"] == "high"])
            
            elif tool_name == "nikto":
                context["has_nikto"] = True
                context["vuln_scan_done"] = True
                
                # Parse nikto findings: + OSVDB-xxxx: /path: Description
                nikto_findings = []
                for line in output.strip().split("\n"):
                    if line.strip().startswith("+") and ":" in line:
                        nikto_findings.append(line.strip()[2:])  # Remove "+ "
                if nikto_findings:
                    context["nikto_findings"] = nikto_findings[:50]
            
            elif tool_name == "sqlmap":
                context["has_sqlmap"] = True
                # Check if vulnerable
                if "is vulnerable" in output.lower() or "sqli" in output.lower():
                    context["sqli_vulnerable"] = True
                # Parse databases if found
                import re
                db_match = re.search(r'available databases \[(\d+)\]:', output)
                if db_match:
                    context["databases_found"] = int(db_match.group(1))
            
            # ─────────────────────────────────────────────────────────
            # WEB DISCOVERY TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name in ["gobuster", "katana"]:
                context["has_web_discovery"] = True
                
                # Parse discovered paths
                discovered_paths = []
                for line in output.strip().split("\n"):
                    line = line.strip()
                    # gobuster: /admin (Status: 200) or just paths
                    if line and ("/" in line or "http" in line):
                        # Extract just the path/URL
                        import re
                        path_match = re.search(r'(https?://[^\s]+|/[^\s\(]+)', line)
                        if path_match:
                            discovered_paths.append(path_match.group(1))
                if discovered_paths:
                    context["discovered_paths"] = list(set(discovered_paths))[:100]
                    context["path_count"] = len(context["discovered_paths"])
            
            elif tool_name == "ffuf":
                context["has_web_discovery"] = True
                # Parse ffuf output
                discovered_paths = []
                for line in output.strip().split("\n"):
                    if line.strip() and not line.startswith("["):
                        # ffuf shows: path [Status: 200, Size: 1234]
                        import re
                        path_match = re.search(r'^(\S+)', line.strip())
                        if path_match:
                            discovered_paths.append(path_match.group(1))
                if discovered_paths:
                    context["discovered_paths"] = context.get("discovered_paths", []) + discovered_paths
                    context["discovered_paths"] = list(set(context["discovered_paths"]))[:100]
            
            elif tool_name == "feroxbuster":
                context["has_web_discovery"] = True
                discovered_paths = []
                for line in output.strip().split("\n"):
                    if "http" in line:
                        import re
                        url_match = re.search(r'(https?://[^\s]+)', line)
                        if url_match:
                            discovered_paths.append(url_match.group(1))
                if discovered_paths:
                    context["discovered_paths"] = list(set(discovered_paths))[:100]
            
            elif tool_name == "dirsearch":
                context["has_web_discovery"] = True
                discovered_paths = []
                for line in output.strip().split("\n"):
                    if line.strip() and ("200" in line or "301" in line or "302" in line or "403" in line):
                        import re
                        path_match = re.search(r'(https?://[^\s]+|/[^\s]+)', line)
                        if path_match:
                            discovered_paths.append(path_match.group(1))
                if discovered_paths:
                    context["discovered_paths"] = list(set(discovered_paths))[:100]
            
            # ─────────────────────────────────────────────────────────
            # WEB TECHNOLOGY DETECTION
            # ─────────────────────────────────────────────────────────
            elif tool_name == "wpscan":
                context["has_wpscan"] = True
                
                # Parse WordPress version
                import re
                ver_match = re.search(r'WordPress version:\s*(\S+)', output)
                if ver_match:
                    context["wordpress_version"] = ver_match.group(1)
                
                # Parse users
                users = []
                user_pattern = r'\[i\] User\(s\) Identified:.*?(?=\[\+\]|\[!\]|$)'
                user_section = re.search(user_pattern, output, re.DOTALL)
                if user_section:
                    for line in user_section.group(0).split("\n"):
                        if "| - " in line:
                            users.append(line.replace("| - ", "").strip())
                if users:
                    context["wp_users"] = users
                
                # Parse vulnerable plugins
                vuln_plugins = re.findall(r'\[!\].*vulnerable.*?:\s*(\S+)', output, re.IGNORECASE)
                if vuln_plugins:
                    context["wp_vulnerable_plugins"] = vuln_plugins
            
            elif tool_name == "whatweb":
                context["has_whatweb"] = True
                
                # Parse technologies from whatweb output
                technologies = []
                import re
                # WhatWeb shows: [tech1] [tech2] [tech3]
                tech_pattern = r'\[([^\]]+)\]'
                for match in re.finditer(tech_pattern, output):
                    tech = match.group(1)
                    if tech and len(tech) < 50:  # Avoid long descriptions
                        technologies.append(tech)
                if technologies:
                    context["web_technologies"] = list(set(technologies))[:30]
            
            elif tool_name == "wafw00f":
                context["has_waf_check"] = True
                
                # Parse WAF detection
                if "is behind" in output.lower():
                    context["waf_detected"] = True
                    import re
                    waf_match = re.search(r'is behind\s+(.+?)(?:\s+WAF|\s*$)', output, re.IGNORECASE)
                    if waf_match:
                        context["waf_name"] = waf_match.group(1).strip()
                elif "no waf" in output.lower():
                    context["waf_detected"] = False
            
            # ─────────────────────────────────────────────────────────
            # BRUTE FORCE TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "hydra":
                context["has_hydra"] = True
                
                # Parse cracked credentials: [port][service] host login: user password: pass
                cracked = []
                import re
                cred_pattern = r'\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)'
                for match in re.finditer(cred_pattern, output):
                    cracked.append({
                        "port": match.group(1),
                        "service": match.group(2),
                        "host": match.group(3),
                        "username": match.group(4),
                        "password": match.group(5)
                    })
                if cracked:
                    context["cracked_credentials"] = cracked
                    context["creds_count"] = len(cracked)
            
            # ─────────────────────────────────────────────────────────
            # EXPLOIT TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "searchsploit":
                context["has_searchsploit"] = True
                
                # Parse exploits: Title | Path
                exploits = []
                for line in output.strip().split("\n"):
                    if "|" in line and "/" in line:
                        parts = line.split("|")
                        if len(parts) >= 2:
                            title = parts[0].strip()
                            path = parts[1].strip()
                            if title and path and not title.startswith("-"):
                                exploits.append({
                                    "title": title,
                                    "path": path
                                })
                if exploits:
                    context["exploits_found"] = exploits
                    context["exploit_count"] = len(exploits)
            
            # ─────────────────────────────────────────────────────────
            # NETWORK/SMB TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "enum4linux":
                context["has_enum4linux"] = True
                
                # Parse SMB shares
                shares = []
                import re
                share_pattern = r'^\s*(\S+)\s+Disk\s+(.*)$'
                for match in re.finditer(share_pattern, output, re.MULTILINE):
                    shares.append(match.group(1))
                if shares:
                    context["smb_shares"] = shares
                
                # Parse users
                users = []
                user_pattern = r'user:\[([^\]]+)\]'
                for match in re.finditer(user_pattern, output):
                    users.append(match.group(1))
                if users:
                    context["smb_users"] = list(set(users))
            
            elif tool_name == "smbclient":
                context["has_smbclient"] = True
                
                # Parse shares from smbclient -L output
                shares = []
                for line in output.strip().split("\n"):
                    if "Disk" in line or "IPC" in line or "Print" in line:
                        parts = line.strip().split()
                        if parts:
                            shares.append(parts[0])
                if shares:
                    context["smb_shares"] = shares
            
            # ─────────────────────────────────────────────────────────
            # OSINT TOOLS
            # ─────────────────────────────────────────────────────────
            elif tool_name == "theHarvester":
                # Parse theHarvester output to store emails, hosts, IPs, subdomains
                context["last_domain"] = params.get("domain", "")
                
                # Parse emails
                if "[*] Emails found:" in output:
                    email_section = output.split("[*] Emails found:")[1]
                    # Find next section marker or end
                    for marker in ["[*] Hosts found:", "[*] IPs found:", "[*] No ", "[*] Performing"]:
                        if marker in email_section:
                            email_section = email_section.split(marker)[0]
                            break
                    emails = [line.strip() for line in email_section.strip().split("\n") 
                              if line.strip() and "@" in line and not line.startswith("-")]
                    if emails:
                        context["emails"] = emails
                        context["email_count"] = len(emails)
                
                # Parse hosts/subdomains
                if "[*] Hosts found:" in output:
                    hosts_section = output.split("[*] Hosts found:")[1]
                    for marker in ["[*] Performing", "[*] No ", "Read "]:
                        if marker in hosts_section:
                            hosts_section = hosts_section.split(marker)[0]
                            break
                    hosts = [line.strip() for line in hosts_section.strip().split("\n") 
                             if line.strip() and "." in line and not line.startswith("-") and not line.startswith("[")]
                    if hosts:
                        context["hosts"] = hosts[:100]  # Store up to 100
                        context["host_count"] = len(hosts)
                        # Also extract unique subdomains (host before colon if present)
                        subdomains = list(set([h.split(":")[0] for h in hosts if "." in h.split(":")[0]]))
                        context["subdomains"] = subdomains[:50]
                        context["subdomain_count"] = len(subdomains)
                        context["has_subdomains"] = True
                
                # Parse IPs
                if "[*] IPs found:" in output:
                    ips_section = output.split("[*] IPs found:")[1]
                    for marker in ["[*] Emails found:", "[*] Hosts found:", "[*] No ", "[*] Performing"]:
                        if marker in ips_section:
                            ips_section = ips_section.split(marker)[0]
                            break
                    ips = [line.strip() for line in ips_section.strip().split("\n") 
                           if line.strip() and (line.strip()[0].isdigit() or line.strip().startswith("2"))]
                    if ips:
                        context["ips"] = ips
                        context["ip_count"] = len(ips)
                
                # Parse ASNs
                if "[*] ASNS found:" in output or "[*] ASNs found:" in output:
                    asn_marker = "[*] ASNS found:" if "[*] ASNS found:" in output else "[*] ASNs found:"
                    asn_section = output.split(asn_marker)[1]
                    for marker in ["[*] Interesting", "[*] IPs", "[*] Emails", "[*] Hosts"]:
                        if marker in asn_section:
                            asn_section = asn_section.split(marker)[0]
                            break
                    asns = [line.strip() for line in asn_section.strip().split("\n") 
                            if line.strip() and line.strip().upper().startswith("AS")]
                    if asns:
                        context["asns"] = asns
                
                # Parse interesting URLs
                if "[*] Interesting Urls found:" in output:
                    urls_section = output.split("[*] Interesting Urls found:")[1]
                    for marker in ["[*] No ", "[*] IPs", "[*] Emails", "[*] Hosts", "[*] LinkedIn"]:
                        if marker in urls_section:
                            urls_section = urls_section.split(marker)[0]
                            break
                    urls = [line.strip() for line in urls_section.strip().split("\n") 
                            if line.strip() and line.strip().startswith("http")]
                    if urls:
                        context["interesting_urls"] = urls
    
    # Track which tools have been run (prevent loops)
    tools_run = context.get("tools_run", [])
    tools_run.extend(tools)
    context["tools_run"] = list(set(tools_run))  # Deduplicate
    
    # ============================================================
    # UNIVERSAL SECURITY TECH DETECTION (all tool outputs)
    # ============================================================
    try:
        from app.rag.security_tech import SECURITY_TECH_DB
        
        # Combine all outputs for scanning
        all_output = ""
        for tool, data in results.items():
            if data.get("output"):
                all_output += data["output"].lower()
        
        detected_security = context.get("detected_security_tech", [])
        for tech_id, tech in SECURITY_TECH_DB.items():
            for pattern in tech.detection_patterns:
                if pattern.lower() in all_output:
                    if tech_id not in detected_security:
                        detected_security.append(tech_id)
                        print(f"  🛡️ {tech.name} detected in output")
                    break
        
        if detected_security:
            context["detected_security_tech"] = list(set(detected_security))
    except Exception:
        pass
    
    return {
        **state,
        "execution_results": results,
        "context": context,
        "next_action": "analyze"
    }


def _get_security_tech_context(context: dict) -> str:
    """Generate security tech bypass context for the LLM."""
    detected_security = context.get("detected_security_tech", [])
    if not detected_security:
        return ""
    
    try:
        from app.rag.security_tech import SECURITY_TECH_DB
        
        security_context = "\n- **SECURITY DEFENSES DETECTED:**\n"
        for tech_id in detected_security[:3]:  # Top 3
            tech = SECURITY_TECH_DB.get(tech_id)
            if tech:
                security_context += f"  * {tech.name} ({tech.category}): {tech.description[:80]}...\n"
                security_context += f"    BYPASS METHODS:\n"
                for method in tech.bypass_methods[:2]:  # Top 2 methods
                    security_context += f"      - {method['method']}: {method['description'][:60]}...\n"
                if tech.origin_discovery and tech.category == "cdn_waf":
                    security_context += f"    ORIGIN IP DISCOVERY: {', '.join(tech.origin_discovery[:2])}\n"
        
        # Add live web research for latest bypass techniques
        try:
            from app.tools.custom.web_research import research_bypass
            for tech_id in detected_security[:1]:  # Research top 1 only (rate limit)
                tech = SECURITY_TECH_DB.get(tech_id)
                if tech:
                    research_result = research_bypass(tech.name)
                    if research_result and "No research" not in research_result:
                        security_context += f"\n    🌐 WEB RESEARCH:\n"
                        for line in research_result.split("\n")[:5]:
                            security_context += f"      {line}\n"
        except Exception:
            pass  # Web research is optional
        
        return security_context
    except Exception:
        return ""


def analyzer_node(state: AgentState) -> AgentState:
    """
    LLM analyzes execution results.
    
    NEW: Enriches results with CVE data from RAG.
    
    Decides:
    - DONE: Goal achieved, format and return results
    - CONTINUE: Suggest next step
    - ASK_USER: Need clarification
    """
    llm = OllamaClient()
    results = state.get("execution_results", {})
    context = state.get("context", {})
    
    # === CHECK IF ANY TOOLS SUCCEEDED ===
    successful_tools = [t for t, d in results.items() if d.get("success")]
    failed_tools = [t for t, d in results.items() if not d.get("success")]
    
    if not successful_tools:
        # ALL tools failed - provide INTELLIGENT REASONING about why
        detected_security = context.get("detected_security_tech", [])
        
        error_msg = "⚠️ **All scans failed or timed out:**\n\n"
        
        # Analyze each failed tool
        failure_reasons = []
        for tool, data in results.items():
            error = data.get("error", "") or data.get("output", "")
            error_lower = error.lower()
            error_msg += f"- **{tool}**: {error[:100]}...\n" if len(error) > 100 else f"- **{tool}**: {error}\n"
            
            # Categorize failure reasons
            if "timeout" in error_lower or "timed out" in error_lower:
                failure_reasons.append("timeout")
            if "connection refused" in error_lower or "no route" in error_lower:
                failure_reasons.append("connection")
            if "could not connect" in error_lower:
                failure_reasons.append("connection")
        
        # Generate intelligent analysis
        error_msg += "\n**🧠 Failure Analysis:**\n"
        
        # Check if security tech is causing issues - use SECURITY_TECH_DB dynamically
        security_explained = False
        if detected_security:
            try:
                from app.rag.security_tech import SECURITY_TECH_DB
                
                for tech_id in detected_security:
                    tech = SECURITY_TECH_DB.get(tech_id)
                    if tech:
                        security_explained = True
                        error_msg += f"\n🛡️ **{tech.name} Detected!** ({tech.category})\n"
                        error_msg += f"{tech.description}\n\n"
                        
                        # Show bypass methods
                        error_msg += "**Bypass Methods:**\n"
                        for method in tech.bypass_methods[:3]:
                            error_msg += f"- {method['method']}: {method['description']}\n"
                        
                        # For CDN/WAF, show origin discovery
                        if tech.category == "cdn_waf" and tech.origin_discovery:
                            error_msg += "\n**Find Origin IP:**\n"
                            for od in tech.origin_discovery[:3]:
                                error_msg += f"- {od}\n"
                        error_msg += "\n"
            except Exception:
                pass
        
        # If no security tech detected, check for timeout/connection issues
        if not security_explained:
            if "timeout" in failure_reasons or "connection" in failure_reasons:
                error_msg += """
⏱️ **Connection/Timeout Issues:**
- Target may be offline or unreachable
- Port is filtered/closed (not open on target)
- Firewall blocking your IP
- CDN/WAF may be protecting the target

**Try:**
1. Run `httpx` first to confirm target is up
2. Do port scan with `nmap` to find open ports
3. Check if target has CDN protection with `httpx -title -tech-detect`
"""
            else:
                error_msg += """
🔧 **Possible Tool Issues:**
- Missing required parameters
- Wrong target format
- Tool not installed properly

Check tool installation with `/tools`
"""
        
        return {
            **state,
            "response": error_msg,
            "next_action": "respond"
        }
    
    # Format results for LLM - use more context for better analysis
    results_str = ""
    for tool, data in results.items():
        if data.get("success"):
            output = data.get("output", "")[:4000]
            results_str += f"\n{tool}: SUCCESS\n{output}\n"
        else:
            results_str += f"\n{tool}: FAILED - {data.get('error', 'Unknown error')}\n"
    
    # ============================================================
    cve_context = ""
    try:
        from app.rag.cve_rag import search_cves
        
        # ONLY look for actual technology keywords in results
        # Don't search for domain names - they won't match CVEs
        tech_keywords = [
            "wordpress", "apache", "nginx", "php", "mysql", "ssh", "openssh",
            "ftp", "rdp", "smb", "tomcat", "jenkins", "redis", "mongodb",
            "postgresql", "mariadb", "iis", "exchange", "sharepoint",
            "drupal", "joomla", "magento", "cpanel", "plesk", "webmin",
            "proftpd", "vsftpd", "openssl", "cloudflare", "ubuntu", "debian",
            "centos", "windows", "fortios", "fortigate", "cisco", "mikrotik"
        ]
        
        detected_tech = []
        results_lower = results_str.lower()
        for tech in tech_keywords:
            if tech in results_lower:
                detected_tech.append(tech)
        
        # Also look for version patterns like "Apache/2.4.41"
        import re
        version_pattern = r'([a-zA-Z]+)[/\s](\d+\.\d+(?:\.\d+)?)'
        versions = re.findall(version_pattern, results_str)
        for name, ver in versions:
            # Exclude common false positives from nmap/tool output
            exclude = ["http", "www", "ssl", "tls", "tcp", "udp", "port", "about", 
                       "nmap", "version", "time", "rate", "host", "scan", "open",
                       "filtered", "closed", "service", "state", "reason", "latency",
                       "for", "and", "the", "not", "owasp", "amass", "github", "com",
                       "names", "discovered", "routed", "subdomain", "enumeration"]
            if name.lower() not in exclude and len(name) > 2:
                detected_tech.append(f"{name} {ver}")
        
        # Store detected tech for exploit tools to use
        if detected_tech:
            context["detected_tech"] = list(set(detected_tech))[:10]
            search_query = " ".join(detected_tech[:3])
            cve_results = search_cves(search_query, n_results=5, severity="high")
            
            if cve_results.get("cves"):
                # Store CVEs in context for later display (/cve command)
                context["last_cves"] = cve_results["cves"]
                context["cve_query"] = search_query
                
                cve_context = "\n\nRELEVANT CVEs:\n"
                for cve in cve_results["cves"][:3]:
                    cve_id = cve.get("cve_id", "Unknown")
                    desc = cve.get("description", "")[:100]
                    severity = cve.get("severity", "Unknown")
                    cve_context += f"- {cve_id} ({severity}): {desc}...\n"
                print(f"  🔍 CVE RAG: {len(cve_results['cves'])} CVEs for detected tech: {detected_tech[:3]}")
        else:
            print(f"  ℹ️ CVE RAG: No technologies detected in results (need port/service scan first)")
    except Exception as e:
        print(f"  ⚠️ CVE RAG: {e}")
    
    # ============================================================
    # PURE LLM ANALYSIS - Attack Chain Focus
    # ============================================================
    
    prompt = f'''You are an offensive security expert analyzing scan results. Your goal is to find the FASTEST PATH TO EXPLOITATION.

SCAN RESULTS:
{results_str}
{cve_context}

CONTEXT:
- Target domain: {context.get('last_domain', 'unknown')}
- Subdomains found: {context.get('subdomain_count', 0)}
- Ports scanned: {context.get('has_ports', False)}
- Technologies detected: {context.get('detected_tech', [])}
- Tools already run: {context.get('tools_run', [])}
{_get_security_tech_context(context)}

YOUR ANALYSIS MUST:

1. **IDENTIFY ATTACK VECTORS** - What can be exploited on the ACTUAL TARGET?
   - Exposed admin panels (cPanel, WHM, phpMyAdmin) → Default creds / Brute force
   - Open SSH/FTP/RDP → Brute force with hydra
   - Web forms/login pages → SQL injection with sqlmap
   - Known CVEs in detected versions → Search exploits with searchsploit
   - File upload endpoints → Web shell upload
   - API endpoints → Parameter fuzzing with ffuf

2. **PRIORITIZE BY EXPLOITABILITY** (most likely to succeed first)
   - Critical: Known CVEs with public exploits
   - High: Default credentials, unauthenticated access
   - Medium: Requires brute force or fuzzing
   - Low: Information disclosure only

3. **RECOMMEND NEXT ATTACK STEP** - What tool gets us closer to shell?
   - Found login page? → Use hydra for brute force
   - Found web form with parameters? → Use sqlmap for SQL injection
   - Found old software version? → Use searchsploit for exploits
   - Found open ports? → Use nmap scripts for vuln scan
   - Need to find endpoints? → Use gobuster or katana first

CRITICAL DISTINCTION - UNDERSTAND TOOL OUTPUT TYPES:
- **searchsploit** results are from Exploit-DB database. The paths in exploit titles (like /music/ajax.php) 
  are examples from the VULNERABLE SOFTWARE, NOT paths that exist on the target domain!
- If searchsploit found MySQL exploits, it means MySQL software has known vulnerabilities.
  You must FIRST discover actual endpoints using gobuster/katana, THEN apply exploitation.
- **nuclei/nmap** results ARE from the actual target and can be exploited directly.
- **subdomain/port scans** show what's actually accessible on the target.

RESPOND IN JSON FORMAT:
{{
    "findings": [
        {{"issue": "Specific vulnerability", "attack": "How to exploit it", "severity": "Critical/High/Medium/Low"}}
    ],
    "best_attack_vector": "The most promising attack path",
    "summary": "Brief summary of attack surface",
    "next_tool": "tool_name",
    "next_target": "specific URL or host FROM THE ACTUAL TARGET (use {context.get('last_domain', 'target.com')})",
    "next_reason": "Why this tool will get us closer to exploitation"
}}

IMPORTANT:
- Focus on ACTIONABLE findings that lead to exploitation
- Suggest ONE specific next tool (not a list)
- Use ACTUAL target URLs/hosts, not example paths from exploit database entries
- If searchsploit was just run, suggest gobuster/katana to find real endpoints before sqlmap
- Prioritize quick wins: default creds, known CVEs, misconfigurations
'''
    
    response = llm.generate(prompt, timeout=60)
    
    try:
        # Robust JSON extraction with multiple repair strategies
        clean_response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL)
        
        # Try to extract JSON
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', clean_response, re.DOTALL)
        
        data = None
        if json_match:
            json_str = json_match.group()
            
            # Strategy 1: Direct parse
            try:
                data = json.loads(json_str)
            except json.JSONDecodeError:
                pass
            
            # Strategy 2: Fix single quotes to double quotes
            if data is None:
                try:
                    # Replace single quotes with double (carefully)
                    fixed = re.sub(r"'([^']*)':", r'"\1":', json_str)
                    fixed = re.sub(r": '([^']*)'", r': "\1"', fixed)
                    data = json.loads(fixed)
                except json.JSONDecodeError:
                    pass
            
            # Strategy 3: Fix unescaped characters
            if data is None:
                try:
                    # Remove control characters
                    fixed = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_str)
                    # Fix trailing commas
                    fixed = re.sub(r',\s*}', '}', fixed)
                    fixed = re.sub(r',\s*]', ']', fixed)
                    data = json.loads(fixed)
                except json.JSONDecodeError:
                    pass
            
            # Strategy 4: Extract just the key fields manually
            if data is None:
                data = {}
                # Try to extract next_tool
                tool_match = re.search(r'"next_tool"\s*:\s*"([^"]+)"', clean_response)
                if tool_match:
                    data["next_tool"] = tool_match.group(1)
                # Try to extract best_attack
                attack_match = re.search(r'"best_attack"\s*:\s*"([^"]+)"', clean_response)
                if attack_match:
                    data["best_attack"] = attack_match.group(1)
                # Try to extract summary
                summary_match = re.search(r'"summary"\s*:\s*"([^"]+)"', clean_response)
                if summary_match:
                    data["summary"] = summary_match.group(1)
        
        if data:
            
            findings = data.get("findings", [])
            findings_str = ""
            if findings:
                findings_str = "\n\n## 🎯 Attack Vectors Identified\n\n"
                for f in findings:
                    severity = f.get("severity", "Unknown")
                    badge = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                    findings_str += f"{badge} **{f.get('issue')}** ({severity})\n"
                    # Show attack method if present
                    attack = f.get("attack") or f.get("risk", "")
                    if attack:
                        findings_str += f"   → Exploit: {attack}\n\n"
            
            # Best attack vector
            best_attack = data.get("best_attack_vector", "")
            
            # Next step recommendation
            next_tool = data.get("next_tool") or (data.get("next_tools", [None])[0] if data.get("next_tools") else None)
            next_target = data.get("next_target", "")
            next_reason = data.get("next_reason", "")
            summary = data.get("summary", "")
            
            # Build response with attack-focused analysis
            response_text = ""
            
            # Show attack vectors first
            if findings_str:
                response_text += findings_str
            
            # Show best attack vector
            if best_attack:
                response_text += f"\n## ⚡ Best Attack Vector\n{best_attack}\n"
            
            # Show analysis summary
            if summary:
                response_text += f"\n## 📊 Analysis\n{summary}\n"
            
            # NOTE: Removed "Scan Details" section since live streaming 
            # now shows all tool output in real-time. No need to duplicate.
            
            # Show next step with specific target
            if next_tool:
                next_step = f"Use **{next_tool}**"
                if next_target:
                    next_step += f" on `{next_target}`"
                if next_reason:
                    next_step += f" - {next_reason}"
                response_text += f"\n\n**💡 Next Attack Step:** {next_step}"
            elif next_reason:
                response_text += f"\n\n**💡 Recommended next step:** {next_reason}"
            
            return {
                **state,
                "response": response_text,
                "context": context,
                "next_action": "respond"
            }
        else:
            print(f"  ⚠️ No JSON in analyzer response, showing raw results")
    except Exception as e:
        print(f"  ⚠️ Analyzer parse error: {e}")
    
    # Fallback - show formatted results (LLM failed to parse)
    formatted = ""
    raw_results = _format_results(results)
    if not raw_results or raw_results == "No results":
        formatted = f"**Scan completed**\n\n"
        for tool, data in results.items():
            if data.get("success"):
                output = data.get("output", "")[:2000]
                formatted += f"### {tool}\n```\n{output}\n```\n\n"
            else:
                formatted += f"### {tool}\n❌ {data.get('error', 'Unknown error')}\n\n"
    else:
        formatted = raw_results
    
    # Clear message that LLM analysis failed - no hardcoded guidance
    llm_failure_notice = "\n\n⚠️ **LLM analysis failed to parse.** Raw tool output shown above. Please interpret the results and decide next steps yourself."
    
    return {
        **state,
        "response": formatted + llm_failure_notice,
        "next_action": "respond"
    }


def respond_node(state: AgentState) -> AgentState:
    """Format and return final response."""
    # If we have a suggestion waiting for confirmation
    if state.get("suggestion_message") and state.get("suggested_tools"):
        return {
            **state,
            "response": state["suggestion_message"],
            "next_action": "end"
        }
    
    # If there's already a response, use it
    if state.get("response"):
        return {**state, "next_action": "end"}
    
    # Fallback if no response
    return {
        **state,
        "response": "I couldn't process that request. Please try again with more details.",
        "next_action": "end"
    }


def question_node(state: AgentState) -> AgentState:
    """Answer using LLM knowledge + scan context + web research."""
    llm = OllamaClient()
    context = state.get("context", {})
    query = state["query"]
    
    context_str = f"""Target: {context.get('last_domain', 'Not set')}
Technologies: {context.get('detected_tech', [])}"""
    
    # Try web research for questions that might need fresh info
    web_context = ""
    needs_research = any(kw in query.lower() for kw in [
        "latest", "new", "recent", "2024", "2025", "2026",
        "how to", "what is", "explain", "tutorial", "guide",
        "bypass", "exploit", "vulnerability", "cve-", "poc"
    ])
    
    if needs_research:
        try:
            from app.tools.custom.web_research import search_and_format
            research = search_and_format(query)
            if research:
                web_context = f"\n\nWEB RESEARCH RESULTS:\n{research}"
                print(f"  🌐 Searched web for: {query[:50]}...")
        except Exception:
            pass
    
    prompt = f"""You are an expert cybersecurity professional with access to web search.

QUESTION: {query}

SESSION: {context_str}
{web_context}

INSTRUCTIONS:
1. For general questions (cPanel, ASN, CVE, tools) - USE YOUR KNOWLEDGE!
2. If WEB RESEARCH RESULTS are provided above, USE them to give accurate answers.
3. For scan results, use the session context.
4. Cite sources from web research when applicable.
5. Be specific and actionable in your answers.

Answer:"""
    
    response = llm.generate(prompt, timeout=60)
    
    return {
        **state,
        "response": response or "Please rephrase.",
        "next_action": "end"
    }


def memory_query_node(state: AgentState) -> AgentState:
    """
    Retrieve and display stored data from memory/context.
    
    Handles requests like:
    - "show me the subdomains"
    - "list the findings"
    - "what did we find"
    - "show me emails"
    """
    context = state.get("context", {})
    query = state.get("query", "").lower()
    
    response_parts = []
    
    # Get domain
    domain = context.get("last_domain", "Unknown target")
    response_parts.append(f"## 📊 Stored Data for {domain}\n")
    
    # Emails
    emails = context.get("emails", [])
    if emails:
        response_parts.append(f"### 📧 Emails ({len(emails)} found)\n")
        for email in emails:
            response_parts.append(f"  • {email}")
        response_parts.append("")
    
    # Subdomains
    subdomains = context.get("subdomains", [])
    subdomain_count = context.get("subdomain_count", len(subdomains))
    
    if subdomains:
        response_parts.append(f"### 🌐 Subdomains ({subdomain_count} found)\n")
        for sub in subdomains:
            response_parts.append(f"  • {sub}")
        response_parts.append("")
    elif subdomain_count > 0:
        response_parts.append(f"### 🌐 Subdomains\n  {subdomain_count} subdomains discovered (list not in memory)\n")
    
    # Hosts
    hosts = context.get("hosts", [])
    if hosts:
        response_parts.append(f"### 🖥️ Hosts ({len(hosts)} found)\n")
        for host in hosts:
            response_parts.append(f"  • {host}")
        response_parts.append("")
    
    # IPs
    ips = context.get("ips", [])
    if ips:
        response_parts.append(f"### 🔢 IP Addresses ({len(ips)} found)\n")
        for ip in ips:
            response_parts.append(f"  • {ip}")
        response_parts.append("")
    
    # ASNs
    asns = context.get("asns", [])
    if asns:
        response_parts.append(f"### 🏢 ASNs ({len(asns)} found)\n")
        for asn in asns:
            response_parts.append(f"  • {asn}")
        response_parts.append("")
    
    # Interesting URLs
    interesting_urls = context.get("interesting_urls", [])
    if interesting_urls:
        response_parts.append(f"### 🔗 Interesting URLs ({len(interesting_urls)} found)\n")
        for url in interesting_urls:
            response_parts.append(f"  • {url}")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # PORT SCAN RESULTS
    # ─────────────────────────────────────────────────────────
    open_ports = context.get("open_ports", [])
    if open_ports:
        response_parts.append(f"### 🔌 Open Ports ({len(open_ports)} found)\n")
        for port in open_ports:
            if isinstance(port, dict):
                port_str = f"{port.get('port')}/{port.get('protocol', 'tcp')}"
                service = port.get('service', '')
                version = port.get('version', '')
                if service:
                    port_str += f"  {service}"
                if version:
                    port_str += f" ({version})"
                response_parts.append(f"  • {port_str}")
            else:
                response_parts.append(f"  • {port}")
        response_parts.append("")
    
    # OS Detection
    if context.get("os_detected"):
        response_parts.append(f"### 💻 OS Detected\n  {context['os_detected']}\n")
    
    # ─────────────────────────────────────────────────────────
    # VULNERABILITY RESULTS
    # ─────────────────────────────────────────────────────────
    vulnerabilities = context.get("vulnerabilities", [])
    if vulnerabilities:
        critical = context.get("critical_vulns", 0)
        high = context.get("high_vulns", 0)
        response_parts.append(f"### 🔓 Vulnerabilities ({len(vulnerabilities)} found)")
        if critical or high:
            response_parts.append(f"  🔴 Critical: {critical} | 🟠 High: {high}\n")
        else:
            response_parts.append("")
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown")
            template = vuln.get("template", "unknown")
            matched = vuln.get("matched", "")
            badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(severity, "⚪")
            response_parts.append(f"  {badge} [{template}] {matched}")
        response_parts.append("")
    
    # Nikto Findings
    nikto_findings = context.get("nikto_findings", [])
    if nikto_findings:
        response_parts.append(f"### 🕷️ Nikto Findings ({len(nikto_findings)} found)\n")
        for finding in nikto_findings:
            response_parts.append(f"  • {finding}")
        response_parts.append("")
    
    # SQLi Results
    if context.get("sqli_vulnerable"):
        dbs = context.get("databases_found", 0)
        response_parts.append(f"### � SQL Injection\n  ⚠️ Target is VULNERABLE to SQL injection!")
        if dbs:
            response_parts.append(f"  📁 {dbs} databases discovered")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # WEB DISCOVERY RESULTS
    # ─────────────────────────────────────────────────────────
    discovered_paths = context.get("discovered_paths", [])
    if discovered_paths:
        response_parts.append(f"### 📂 Discovered Paths ({len(discovered_paths)} found)\n")
        for path in discovered_paths:
            response_parts.append(f"  • {path}")
        response_parts.append("")
    
    # HTTP Probes
    http_probes = context.get("http_probes", [])
    if http_probes:
        response_parts.append(f"### 🌍 HTTP Probes ({len(http_probes)} found)\n")
        for probe in http_probes:
            response_parts.append(f"  • {probe}")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # WORDPRESS INFO
    # ─────────────────────────────────────────────────────────
    if context.get("wordpress_version"):
        response_parts.append(f"### 📦 WordPress Info")
        response_parts.append(f"  Version: {context['wordpress_version']}")
        if context.get("wp_users"):
            response_parts.append(f"  Users: {', '.join(context['wp_users'][:10])}")
        if context.get("wp_vulnerable_plugins"):
            response_parts.append(f"  ⚠️ Vulnerable Plugins: {', '.join(context['wp_vulnerable_plugins'])}")
        response_parts.append("")
    
    # WAF Detection
    if context.get("has_waf_check"):
        if context.get("waf_detected"):
            waf_name = context.get("waf_name", "Unknown")
            response_parts.append(f"### �️ WAF Detected\n  ⚠️ {waf_name}\n")
        else:
            response_parts.append("### 🛡️ WAF Detection\n  ✅ No WAF detected\n")
    
    # ─────────────────────────────────────────────────────────
    # CREDENTIALS & EXPLOITS
    # ─────────────────────────────────────────────────────────
    cracked_creds = context.get("cracked_credentials", [])
    if cracked_creds:
        response_parts.append(f"### 🔑 Cracked Credentials ({len(cracked_creds)} found)\n")
        for cred in cracked_creds:
            user = cred.get("username", "?")
            passwd = cred.get("password", "?")
            service = cred.get("service", "")
            host = cred.get("host", "")
            response_parts.append(f"  • {user}:{passwd} ({service}@{host})")
        response_parts.append("")
    
    exploits_found = context.get("exploits_found", [])
    if exploits_found:
        response_parts.append(f"### 💣 Exploits Found ({len(exploits_found)})\n")
        for exp in exploits_found:
            title = exp.get("title", "Unknown")
            response_parts.append(f"  • {title}")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # SMB/NETWORK INFO
    # ─────────────────────────────────────────────────────────
    smb_shares = context.get("smb_shares", [])
    if smb_shares:
        response_parts.append(f"### 📁 SMB Shares ({len(smb_shares)} found)\n")
        for share in smb_shares:
            response_parts.append(f"  • {share}")
        response_parts.append("")
    
    smb_users = context.get("smb_users", [])
    if smb_users:
        response_parts.append(f"### 👤 SMB Users ({len(smb_users)} found)\n")
        for user in smb_users:
            response_parts.append(f"  • {user}")
        response_parts.append("")
    
    # ─────────────────────────────────────────────────────────
    # TECHNOLOGY & TOOLS
    # ─────────────────────────────────────────────────────────
    # Web Technologies (from whatweb)
    web_tech = context.get("web_technologies", [])
    if web_tech:
        response_parts.append(f"### 🔧 Web Technologies ({len(web_tech)} found)\n")
        for tech in web_tech[:20]:
            response_parts.append(f"  • {tech}")
        response_parts.append("")
    
    # Detected Technologies (from analyzer)
    detected_tech = context.get("detected_tech", [])
    if detected_tech and not web_tech:
        response_parts.append("### 🔧 Detected Technologies\n")
        for tech in detected_tech[:20]:
            response_parts.append(f"  • {tech}")
        response_parts.append("")
    
    # Tools run
    tools_run = context.get("tools_run", [])
    if tools_run:
        response_parts.append("### 🛠️ Tools Executed\n")
        for tool in tools_run:
            response_parts.append(f"  • {tool}")
        response_parts.append("")
    
    # If nothing found
    if len(response_parts) <= 1:
        response_parts.append("No data stored yet. Run some scans first!")
    
    response = "\n".join(response_parts)
    
    return {
        **state,
        "response": response,
        "next_action": "end"
    }


def _format_results(results: Dict[str, Any]) -> str:
    """Format tool results for display."""
    from app.cli.display import format_tool_result
    
    parts = []
    for tool, data in results.items():
        if data.get("success"):
            formatted = format_tool_result(tool, data.get("output", ""), True)
            parts.append(formatted)
        else:
            parts.append(f"**{tool}**: Error - {data.get('error', 'Unknown')}")
    
    return "\n\n".join(parts) if parts else "No results"


# ============================================================
# GRAPH ROUTING
# ============================================================

def route_after_intent(state: AgentState) -> str:
    """Route based on intent classification."""
    intent = state.get("intent", "question")
    
    if intent == "security_task":
        return "planner"
    elif intent == "confirm":
        return "confirm"
    elif intent == "memory_query":
        return "memory_query"
    elif intent == "question":
        return "question"
    else:
        return "question"


def route_after_action(state: AgentState) -> str:
    """Route based on next_action field."""
    action = state.get("next_action", "end")
    
    # Map actions to node names
    routes = {
        "plan": "planner",
        "planner": "planner",
        "confirm": "respond",
        "executor": "executor",
        "execute": "executor",
        "analyzer": "analyzer",
        "analyze": "analyzer",
        "respond": "respond"
    }
    
    return routes.get(action, END)


# ============================================================
# BUILD GRAPH
# ============================================================

def build_graph():
    """Build the LangGraph state machine."""
    
    # Create graph
    graph = StateGraph(AgentState)
    
    # Add nodes
    graph.add_node("intent", intent_node)
    graph.add_node("planner", planner_node)
    graph.add_node("confirm", confirm_node)
    graph.add_node("executor", executor_node)
    graph.add_node("analyzer", analyzer_node)
    graph.add_node("respond", respond_node)
    graph.add_node("question", question_node)
    graph.add_node("memory_query", memory_query_node)
    
    # Set entry point
    graph.set_entry_point("intent")
    
    # Add conditional edges
    graph.add_conditional_edges(
        "intent",
        route_after_intent,
        {
            "planner": "planner",
            "confirm": "confirm",
            "memory_query": "memory_query",
            "question": "question"
        }
    )
    
    graph.add_conditional_edges(
        "planner",
        route_after_action,
        {
            "confirm": "respond",
            "respond": "respond",
            END: END
        }
    )
    
    graph.add_conditional_edges(
        "confirm",
        route_after_action,
        {
            "executor": "executor",
            "respond": "respond",
            END: END
        }
    )
    
    graph.add_conditional_edges(
        "executor",
        route_after_action,
        {
            "analyze": "analyzer",
            "analyzer": "analyzer",
            "respond": "respond",
            END: END
        }
    )
    
    graph.add_conditional_edges(
        "analyzer",
        route_after_action,
        {
            "confirm": "respond",
            "respond": "respond",
            "planner": "planner",
            END: END
        }
    )
    
    graph.add_edge("respond", END)
    graph.add_edge("question", END)
    graph.add_edge("memory_query", END)
    
    # Compile with memory
    memory = MemorySaver()
    return graph.compile(checkpointer=memory)


# ============================================================
# AGENT CLASS
# ============================================================

class LangGraphAgent:
    """
    LangGraph-powered SNODE agent.
    
    Proper flow:
    1. LLM classifies intent
    2. LLM suggests tools
    3. User confirms
    4. Code executes
    5. LLM analyzes
    
    Key feature: Uses LangChain ConversationSummaryBufferMemory for smart context.
    """
    
    def __init__(self):
        self.graph = build_graph()
        self.context = {}
        self.thread_id = "snode-session"
        self.pending_confirmation = False
        self.last_suggestion = None
        self.last_results = {}  # Store for report generation
        
        # Initialize AttackMemory with LangChain conversation memory
        try:
            from app.agent.memory import AttackMemory
            self.memory = AttackMemory(persist=True, model=get_current_model())
        except Exception as e:
            print(f"⚠️ Memory init failed: {e}")
            self.memory = None
        
        # Backward compatibility - keep messages list
        self.messages = []
    
    def run(self, query: str, context: Dict[str, Any] = None) -> tuple[str, Dict[str, Any], bool]:
        """
        Process user input.
        
        Returns:
            (response, context, needs_confirmation)
        """
        if context:
            self.context.update(context)
        
        # Add user message to history (both old and new memory)
        self.messages.append({"role": "user", "content": query})
        
        # If we have a pending confirmation and user says yes/no
        suggested_tools = []
        tool_params = {}
        if self.pending_confirmation and self.last_suggestion:
            suggested_tools = self.last_suggestion.get("tools", [])
            tool_params = self.last_suggestion.get("params", {})
        
        # Initial state
        state = AgentState(
            query=query,
            messages=self.messages.copy(),
            intent="",
            suggested_tools=suggested_tools,  # Pass from last suggestion
            suggestion_message="",
            tool_params=tool_params,  # Pass from last suggestion
            confirmed=False,
            selected_tools=[],
            execution_results={},
            context=self.context,
            response="",
            next_action=""
        )
        
        # Config with thread
        config = {"configurable": {"thread_id": self.thread_id}}
        
        # Run graph
        result = self.graph.invoke(state, config)
        
        # Update context
        self.context = result.get("context", self.context)
        
        # Store execution results for report generation
        if result.get("execution_results"):
            self.last_results.update(result.get("execution_results", {}))
        
        # Get response
        response = result.get("response", "No response")
        
        # Add assistant message to history (old system)
        self.messages.append({"role": "assistant", "content": response})
        
        # Save to LangChain memory (new system)
        if self.memory:
            self.memory.save_conversation_turn(query, response)
        
        # Keep last 20 messages to avoid memory bloat
        if len(self.messages) > 20:
            self.messages = self.messages[-20:]
        
        # Check if awaiting confirmation
        needs_confirmation = (
            len(result.get("suggested_tools", [])) > 0 and
            result.get("next_action") == "end" and
            not result.get("execution_results")
        )
        
        if needs_confirmation:
            self.pending_confirmation = True
            self.last_suggestion = {
                "tools": result.get("suggested_tools"),
                "params": result.get("tool_params")
            }
        else:
            self.pending_confirmation = False
            self.last_suggestion = None
        
        return response, self.context, needs_confirmation
    
    def clear_history(self):
        """Clear conversation history."""
        self.messages = []
        self.context = {}


# Factory function
def create_langgraph_agent() -> LangGraphAgent:
    return LangGraphAgent()
