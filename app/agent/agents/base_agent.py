"""
Base Agent - Shared Logic for All Specialized Agents
=====================================================

All specialized agents (Recon, Exploit, Report) inherit from this base.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import re

# Import hierarchy support
try:
    from app.agent.orchestration.hierarchy import HierarchicalAgentMixin, SubordinateAgent
    _HIERARCHY_AVAILABLE = True
except ImportError:
    _HIERARCHY_AVAILABLE = False
    HierarchicalAgentMixin = object
    SubordinateAgent = None


class BaseAgent(ABC):
    """Base class for all specialized agents."""
    
    # Override in subclasses
    AGENT_NAME = "base"
    AGENT_DESCRIPTION = "Base agent"
    SPECIALIZED_TOOLS: List[str] = []
    PENTEST_PHASES: List[int] = [1, 2, 3, 4]  # Phases this agent handles
    
    def __init__(self, llm=None):
        """Initialize agent with optional LLM client."""
        self._llm = llm
        self._tool_index = None
        self._registry = None
        
        # Initialize hierarchy support if available
        if _HIERARCHY_AVAILABLE:
            self._subordinates: List[SubordinateAgent] = []
    
    @property
    def llm(self):
        """Lazy-load LLM client (avoid circular import with graph.py)."""
        if self._llm is None:
            try:
                from langchain_ollama import ChatOllama
                from app.llm import get_llm_config
                config = get_llm_config()
                self._llm = ChatOllama(model=config.model, base_url=config.host)
            except ImportError:
                # Fallback: try simple import
                from app.agent.graph import OllamaClient
                self._llm = OllamaClient()
        return self._llm
    
    @property
    def tool_index(self):
        """Lazy-load tool index."""
        if self._tool_index is None:
            from app.rag.tool_index import ToolIndex
            self._tool_index = ToolIndex()
        return self._tool_index
    
    @property
    def registry(self):
        """Lazy-load tool registry."""
        if self._registry is None:
            from app.tools.registry import get_registry
            self._registry = get_registry()
        return self._registry
    
    @abstractmethod
    def plan(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan tools and actions for the given query.
        
        Returns:
            Dict with keys:
                - tools: List[str] - Tools to execute
                - commands: Dict[str, str] - Command for each tool
                - reasoning: str - Why these tools were chosen
        """
        pass
    
    @abstractmethod
    def analyze_results(self, results: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Analyze execution results and provide insights."""
        pass
    
    def extract_user_tools(self, query: str) -> List[str]:
        """
        Extract tools explicitly mentioned by user in the query.
        
        PRIORITIZE USER CHOICE - if user says "use bbot and theHarvester",
        we should use those tools, not override with our selection.
        
        Returns:
            List of tool names mentioned in query (preserves original case)
        """
        all_tools = list(self.registry.tools.keys())
        
        query_lower = query.lower()
        
        user_tools = []
        for tool in all_tools:
            pattern = rf'\b{re.escape(tool.lower())}\b'
            if re.search(pattern, query_lower, re.IGNORECASE):
                user_tools.append(tool)  
        
        return user_tools
    
    def _discover_tools_via_rag(
        self, 
        query: str, 
        context: Dict[str, Any],
        n_results: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Discover tools using ChromaDB vector search.
        
        Uses UnifiedRAG to semantically search for tools based on user query.
        Filters results based on agent's specialized_tools and context.
        
        Returns:
            List of tool:command pairs with metadata (tool, command, score, description)
        """
        try:
            from app.rag.unified_memory import get_unified_rag
            rag = get_unified_rag()
            
            # Build enhanced query with context
            enhanced_query = query
            
            # Add context hints to query for better matching
            if context.get("has_subdomains"):
                enhanced_query += " subdomain enumeration"
            if context.get("has_ports"):
                enhanced_query += " port scanning"
            if context.get("detected_tech"):
                tech = context.get("detected_tech", [])[:2]
                enhanced_query += f" technology: {', '.join(tech)}"
            
            filters = {
                "min_score": 0.3,  
            }
            
            if self.SPECIALIZED_TOOLS:
                categories = set()
                for tool_name in self.SPECIALIZED_TOOLS:
                    spec = self.registry.tools.get(tool_name)
                    if spec:
                        categories.add(spec.category.value)
                
                if len(categories) == 1:
                    filters["category"] = list(categories)[0]
            
            tools_run = context.get("tools_run", [])
            if tools_run:
                filters["exclude_tools"] = tools_run
            
            matches = rag.query_tools(enhanced_query, n_results=n_results, filters=filters)
            
            if self.SPECIALIZED_TOOLS:
                filtered_matches = [
                    m for m in matches 
                    if m["tool"] in self.SPECIALIZED_TOOLS
                ]
                # If we have matches in specialized tools, use those
                # Otherwise, use all matches (agent might discover new tools)
                if filtered_matches:
                    return filtered_matches[:n_results]
            
            return matches[:n_results]
            
        except Exception as e:
            print(f"  ⚠️ RAG tool discovery failed: {e}")
            return []
    
    def plan_with_user_priority(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan tools, prioritizing user-specified tools over agent selection.
        
        If user explicitly mentions tools, use those.
        Otherwise, fall back to agent's intelligent selection.
        """
        user_requested_tool = context.get("user_requested_tool")
        
        # First, check if user mentioned specific tools
        user_tools = self.extract_user_tools(query)
        
        # Also check if user requested tool from analyzer (for "do the next step")
        if user_requested_tool and not user_tools:
            user_tools = [user_requested_tool]
        
        if user_tools:
            # User specified tools - validate and use them
            valid_tools = [t for t in user_tools if self.registry.is_available(t)]
            unavailable = [t for t in user_tools if t not in valid_tools]
            
            # Warn about unavailable tools
            if unavailable:
                print(f"  ⚠️ Requested tools not available: {', '.join(unavailable)}")
                # If this is from analyzer recommendation, try to suggest alternatives
                if user_requested_tool and user_requested_tool in unavailable:
                    print(f"  💡 Analyzer recommended '{user_requested_tool}' but it's not available. Suggesting alternatives...")
                    # Try to find similar tools
                    from app.tools.registry import ToolCategory
                    try:
                        recommended_spec = self.registry.tools.get(user_requested_tool)
                        if recommended_spec:
                            # Find tools in same category
                            category = recommended_spec.category
                            alternatives = [t for t in self.registry.list_tools(category) 
                                          if t != user_requested_tool and self.registry.is_available(t)]
                            if alternatives:
                                print(f"  💡 Alternative tools in same category: {', '.join(alternatives[:3])}")
                                # Use first available alternative
                                valid_tools = [alternatives[0]]
                                unavailable = []  # Clear unavailable since we have alternative
                    except Exception:
                        pass
            
            if valid_tools:
                # Get commands for user's tools
                commands = self._get_commands_for_tools(valid_tools, context)
                
                reasoning = f"Using your requested tools: {', '.join(valid_tools)}"
                if unavailable:
                    reasoning += f" (skipped unavailable: {', '.join(unavailable)})"
                
                return {
                    "agent": getattr(self, 'name', self.AGENT_NAME),
                    "tools": valid_tools,
                    "commands": commands,
                    "reasoning": reasoning,
                    "user_specified": True,
                    "unavailable_tools": unavailable
                }
            elif user_requested_tool and user_requested_tool in unavailable:
                # Analyzer recommended tool is unavailable, but still try to use agent's plan
                # but pass the recommendation info so agent can consider it
                print(f"  ⚠️ Analyzer recommended '{user_requested_tool}' but it's not available. Using agent's selection instead.")
                # Still call plan() but with recommendation in context for agent to consider
                context["_analyzer_recommended_unavailable"] = user_requested_tool
                return self.plan(query, context)
        
        # No user-specified tools, use normal planning
        return self.plan(query, context)
    
    def _get_commands_for_tools(self, tools: List[str], context: Dict[str, Any]) -> Dict[str, str]:
        """Get recommended commands for a list of tools."""
        commands = {}
        for tool in tools:
            spec = self.registry.tools.get(tool)
            if spec and spec.commands:
                # Use first available command
                commands[tool] = list(spec.commands.keys())[0]
        return commands
    
    def is_complete(self, context: Dict[str, Any]) -> tuple:
        """
        Use LLM to determine if this phase has enough data to proceed.
        
        Returns: (is_complete: bool, reason: str, next_action: str)
        """
        from app.agent.prompts import PHASE_COMPLETION_PROMPTS
        from app.llm.client import OllamaClient
        
        # Get phase number for this agent
        phase = self.PENTEST_PHASES[0] if self.PENTEST_PHASES else 1
        
        # Build context for prompt
        prompt_template = PHASE_COMPLETION_PROMPTS.get(phase, PHASE_COMPLETION_PROMPTS[1])
        
        try:
            prompt = prompt_template.format(
                subdomain_count=context.get("subdomain_count", 0),
                ip_count=len(context.get("ips", [])),
                asn_count=context.get("asn_count", 0),
                tech_list=", ".join(context.get("detected_tech", [])[:5]) or "None",
                tools_run=", ".join(context.get("tools_run", [])[-5:]) or "None",
                port_count=context.get("port_count", 0),
                services=", ".join(s.get("service", "") for s in context.get("open_ports", [])[:5]) or "None",
                web_count=len([p for p in context.get("open_ports", []) if p.get("port") in [80, 443, 8080, 8443]]),
                dir_count=len(context.get("directories", [])),
                vuln_count=len(context.get("vulns_found", [])),
                critical_count=len([v for v in context.get("vulns_found", []) if v.get("severity") == "critical"]),
                high_count=len([v for v in context.get("vulns_found", []) if v.get("severity") == "high"]),
                cve_list=", ".join(v.get("cve_id", "") for v in context.get("vulns_found", [])[:3]) or "None",
                exploit_count=len(context.get("exploits_run", [])),
                success_count=len([e for e in context.get("exploits_run", []) if e.get("success")]),
                shell_obtained="Yes" if context.get("shell_obtained") else "No",
                access_level=context.get("access_level", "None"),
                privesc_done="Yes" if context.get("privesc_done") else "No",
                cred_count=len(context.get("credentials", [])),
                lateral_done="Yes" if context.get("lateral_done") else "No",
                data_collected=", ".join(context.get("loot", [])[:3]) or "None"
            )
        except KeyError:
            # If template has unmatched keys, use simpler approach
            prompt = prompt_template
        
        # Ask LLM (use planner model for phase completion analysis)
        llm = OllamaClient(model="planner")
        response = llm.generate(prompt, timeout=30, stream=False)
        
        # Parse response
        is_complete = "COMPLETE" in response.upper() and "INCOMPLETE" not in response.upper()
        
        # Extract reason
        reason = "Phase analysis complete"
        if "REASON:" in response.upper():
            try:
                reason_start = response.upper().index("REASON:") + 7
                reason_end = response.find("\n", reason_start)
                reason = response[reason_start:reason_end if reason_end > 0 else len(response)].strip()
            except:
                pass
        
        # Extract next action
        next_action = ""
        if "NEXT_ACTION:" in response.upper():
            try:
                action_start = response.upper().index("NEXT_ACTION:") + 12
                next_action = response[action_start:].strip().split("\n")[0]
            except:
                pass
        
        return (is_complete, reason, next_action)
    
    def search_tools(self, query: str, n_results: int = 5) -> List[Dict]:
        """Search for relevant tools using semantic search."""
        return self.tool_index.search(query, n_results=n_results)
    
    def filter_by_specialty(self, tools: List[str]) -> List[str]:
        """Filter tools to only those in this agent's specialty."""
        if not self.SPECIALIZED_TOOLS:
            return tools  # No filter if not specified
        return [t for t in tools if t in self.SPECIALIZED_TOOLS]
    
    def prepare_tool_params(
        self,
        tool_name: str,
        command: str,
        context: Dict[str, Any],
        targets: List[str] = None
    ) -> Dict[str, Any]:
        """
        Prepare tool-specific parameters including target handling.
        
        Handles:
        - Batch file creation for tools that accept file input (nmap, masscan, nuclei)
        - Target list formatting
        - Tool-specific parameter defaults
        
        Args:
            tool_name: Name of the tool
            command: Command to execute
            context: Current context
            targets: Optional list of targets (if None, will be collected from context)
        
        Returns:
            Dict of tool parameters ready for execution
        """
        from app.agent.core import get_target_collector
        
        tool_params = {}
        domain = context.get("last_domain") or context.get("target_domain") or ""
        user_mods = context.get("user_modifications", {})
        
        # Get targets if not provided
        if targets is None:
            target_collector = get_target_collector()
            query = context.get("query", "")
            target_params = target_collector.prepare_targets_for_tool(
                tool_name, domain, context, user_mods, query
            )
            tool_params.update(target_params)
            targets = target_params.get("targets", [target_params.get("target", domain)])
        
        # Tool-specific parameter preparation
        if tool_name in ["nmap", "masscan", "nuclei"] and len(targets) > 1:
            # Batch processing: create temp file for target list
            import tempfile
            import os
            
            try:
                temp_dir = tempfile.gettempdir()
                safe_domain = domain.replace('.', '_').replace('/', '_') if domain else "unknown"
                target_file = os.path.join(temp_dir, f"snode_targets_{safe_domain}_batch.txt")
                
                # Ensure directory is writable
                if not os.access(temp_dir, os.W_OK):
                    target_file = f"./snode_targets_{safe_domain}_batch.txt"
                
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                
                # Set file parameter based on tool
                if tool_name == "nmap":
                    tool_params["file"] = target_file
                    tool_params["_command_override"] = "from_file"
                elif tool_name == "nuclei":
                    tool_params["file"] = target_file
                    tool_params["_command_override"] = "scan_list"
                elif tool_name == "masscan":
                    tool_params["target"] = target_file
                    tool_params["_command_override"] = "scan"
                
                tool_params["_batch_file"] = target_file  # Store for cleanup if needed
                
            except Exception as e:
                print(f"  ⚠️ Failed to create batch file: {e}")
                # Fallback: use targets directly
                tool_params["target"] = " ".join(targets[:20])
                tool_params["targets"] = targets[:50]
        
        # Default parameters for common tools
        if tool_name in ["nuclei", "nmap", "masscan"]:
            tool_params["target"] = tool_params.get("target") or domain
        if tool_name in ["wpscan", "nikto", "httpx", "katana", "wafw00f", "whatweb", "arjun", "dirsearch", "feroxbuster"]:
            tool_params["url"] = tool_params.get("url") or (f"https://{domain}" if domain and not domain.startswith("http") else domain)
        if tool_name in ["subfinder", "amass", "bbot", "dig"]:
            tool_params["domain"] = tool_params.get("domain") or domain
        
        # Default wordlist paths (common Kali/SecLists locations)
        if not tool_params.get("wordlist"):
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
                    tool_params["wordlist"] = wl
                    break
            if not tool_params.get("wordlist"):
                # Fallback - use local wordlist
                tool_params["wordlist"] = "wordlists/common.txt"
        
        # For brute-force tools, use password wordlist instead of directory wordlist
        if tool_name in ["hydra", "medusa", "john", "hashcat"]:
            import os
            password_lists = [
                "wordlists/passwords.txt",
                "/usr/share/wordlists/rockyou.txt",
                "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
            ]
            for pwl in password_lists:
                if os.path.exists(pwl):
                    tool_params["wordlist"] = pwl
                    break
        
        # Default user for brute-force tools (hydra, medusa)
        if tool_name in ["hydra", "medusa"] and not tool_params.get("user"):
            tool_params["user"] = "admin"  # Most common default username
        
        # Default port for nikto if not specified
        if tool_name == "nikto" and not tool_params.get("port"):
            tool_params["port"] = "443"
        
        # Default ports for port scanners (masscan, nmap)
        if tool_name in ["nmap", "masscan", "rustscan"] and not tool_params.get("ports"):
            from app.rag.port_metadata import PORT_PROFILES
            tool_params["ports"] = PORT_PROFILES["critical"]
        
        # Apply port modifications from user
        if user_mods.get("ports"):
            port_setting = user_mods["ports"]
            if port_setting == "100":
                tool_params["ports"] = "--top-ports 100"
            elif port_setting == "1000":
                tool_params["ports"] = "--top-ports 1000"
            elif port_setting == "1-65535":
                tool_params["ports"] = "-p-"
        
        # Update command if it was changed (for batch processing)
        if "_command_override" in tool_params:
            command = tool_params.pop("_command_override")
        
        return tool_params
    
    def create_subordinate(
        self,
        task: str,
        specialized_agent: str = None,
        context: Dict[str, Any] = None
    ) -> Optional[Any]:
        """
        Create a subordinate agent to handle a subtask.
        
        Requires hierarchy support to be available.
        
        Args:
            task: The task to delegate
            specialized_agent: Optional agent name (recon, scan, vuln, etc.)
            context: Optional context to pass to subordinate
            
        Returns:
            SubordinateAgent instance or None if hierarchy not available
        """
        if not _HIERARCHY_AVAILABLE:
            return None
        
        from app.agent.orchestration.hierarchy import HierarchicalAgentMixin
        mixin = HierarchicalAgentMixin()
        return mixin.create_subordinate(task, specialized_agent, context)
    
    def execute_tool(self, tool_name: str, command: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single tool and return results."""
        if not self.registry.is_available(tool_name):
            return {
                "success": False,
                "error": f"Tool not available: {tool_name}"
            }
        
        result = self.registry.execute(tool_name, command, params)
        
        return {
            "success": result.success,
            "output": result.output if result.success else result.error,
            "error": result.error if not result.success else None
        }
    
    def execute_tool_chain(self, chain: List[Dict[str, Any]], stop_on_failure: bool = False) -> List[Dict[str, Any]]:
        """
        Execute multiple tools in sequence.
        
        Merged from specialized/base.py - useful for multi-step operations.
        
        Args:
            chain: List of dicts with keys: tool, command, params
            stop_on_failure: If True, stop chain on first failure
            
        Returns:
            List of results for each tool
        """
        results = []
        for item in chain:
            tool = item.get('tool')
            command = item.get('command', 'default')
            params = item.get('params', {})
            
            result = self.execute_tool(tool, command, params)
            results.append({
                "tool": tool,
                **result
            })
            
            # Stop chain on failure if configured
            if not result.get("success") and (stop_on_failure or item.get('stop_on_failure', False)):
                break
        
        return results
    
    def generate_response(self, prompt: str, timeout: int = 60) -> str:
        """Generate LLM response."""
        return self.llm.generate(prompt, timeout=timeout)
    
    def get_agent_info(self) -> Dict[str, Any]:
        """Return agent metadata."""
        return {
            "name": self.AGENT_NAME,
            "description": self.AGENT_DESCRIPTION,
            "specialized_tools": self.SPECIALIZED_TOOLS,
            "phases": self.PENTEST_PHASES
        }
    
    def _analyze_output_semantic(self, tool_name: str, output: str) -> Dict[str, Any]:
        """
        Semantic analysis of tool output using LLM.
        
        HYBRID APPROACH:
        - Fast path: Quick pattern checks for obvious cases
        - LLM path: Semantic understanding for complex output
        
        Returns:
            Dict with has_findings, severity, summary, key_items, next_step
        """
        import re
        import json
        
        # FAST PATH: Quick checks for common patterns (no LLM needed)
        output_lower = output.lower()
        
        # Obvious failures
        if not output or len(output) < 10:
            return {"has_findings": False, "severity": "none", "summary": "No output", "next_step": "Try different options"}
        
        if any(err in output_lower for err in ["error:", "failed", "timeout", "connection refused"]):
            return {"has_findings": False, "severity": "none", "summary": "Tool execution failed", "next_step": "Check target accessibility"}
        
        # Quick severity detection (common patterns)
        quick_severity = "info"
        if re.search(r'\[critical\]|\bcritical\b', output_lower):
            quick_severity = "critical"
        elif re.search(r'\[high\]|\bhigh\b.*severity', output_lower):
            quick_severity = "high"
        elif re.search(r'\[medium\]|\bmedium\b.*severity', output_lower):
            quick_severity = "medium"
        
        # If output is short and simple, use fast path result
        if len(output) < 500 and quick_severity in ["info", "none"]:
            has_findings = "open" in output_lower or "found" in output_lower or "200" in output
            return {
                "has_findings": has_findings,
                "severity": quick_severity if has_findings else "none",
                "summary": f"{tool_name} completed" + (" with findings" if has_findings else ""),
                "next_step": "Continue with next phase" if has_findings else "Try different approach"
            }
        
        # LLM PATH: Complex output needs semantic understanding
        try:
            from app.llm.client import OllamaClient
            from app.agent.prompt_loader import format_prompt
            
            # Get tool metadata
            spec = self.registry.tools.get(tool_name)
            tool_category = spec.category.value if spec and spec.category else "unknown"
            tool_description = spec.description if spec else f"Security tool: {tool_name}"
            
            # Truncate output if too long
            truncated_output = output[:3000] + "..." if len(output) > 3000 else output
            
            prompt = format_prompt("tool_output_analyzer",
                tool_name=tool_name,
                tool_category=tool_category,
                tool_description=tool_description,
                output=truncated_output
            )
            
            # Use planner model for tool selection
            llm = OllamaClient(model="planner")
            response = llm.generate(prompt, timeout=15, stream=False)
            
            # Parse JSON response
            json_match = re.search(r'\{[^{}]+\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
                
        except Exception as e:
            print(f"  ⚠️ LLM analysis skipped: {e}")
        
        # Fallback
        return {
            "has_findings": quick_severity != "none",
            "severity": quick_severity,
            "summary": f"{tool_name} output analyzed",
            "next_step": "Review output manually"
        }
    
    def can_handle(self, phase: int, query: str) -> bool:
        """
        Check if this agent can handle the given phase/query.
        
        Override in subclasses for more specific logic.
        """
        return phase in self.PENTEST_PHASES
    
    def suggest_next_agent(self, context: Dict[str, Any]) -> Optional[str]:
        """
        Suggest next agent based on current findings.
        
        Merged from specialized/base.py - enables agent handoff.
        Override in subclasses for specific handoff logic.
        
        Returns:
            Agent name to hand off to, or None to continue with current
        """
        # Default handoff based on phase progression
        from app.agent.core import get_phase_manager
        
        phase_mgr = get_phase_manager()
        current_phase = phase_mgr.get_current_phase(context)
        
        # Suggest next phase agent if current phase is complete
        is_complete, _, _ = self.is_complete(context)
        
        if is_complete and current_phase < 6:
            next_agents = {
                1: "scan",      # Recon → Scan
                2: "vuln",      # Scan → Vuln
                3: "exploit",   # Vuln → Exploit
                4: "postexploit",  # Exploit → Post-Exploit
                5: "report",    # Post-Exploit → Report
            }
            return next_agents.get(current_phase)
        
        return None
    
    def __repr__(self):
        return f"<{self.__class__.__name__} tools={len(self.SPECIALIZED_TOOLS)}>"

