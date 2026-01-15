"""
Analyzer Tool

Extracts and encapsulates logic from analyzer_node().
LLM analyzes execution results and suggests next steps.
"""
import re
import json
import time
from typing import Dict, Any, Optional, List
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient
from app.ui import get_logger, format_analysis

logger = get_logger()


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


class AnalyzerTool(AgentTool):
    """Tool for analyzing execution results and suggesting next steps."""
    
    def execute(self, results: Dict[str, Any] = None, context: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """
        LLM analyzes execution results.
        
        Args:
            results: Execution results from tools
            context: Current context dictionary
            
        Returns:
            Dictionary with analysis response and context updates
        """
        if results is None:
            results = self.state.get("execution_results", {}) if self.state else {}
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        
        # Extension hook: analyzer_start
        try:
            from app.extensions import call_extensions_sync
            call_extensions_sync("analyzer_start", agent=None, state=self.state)
        except Exception:
            pass
        
        # Use analyzer model for analyzing tool outputs
        llm = OllamaClient(model="analyzer")
        
        # === CHECK IF ANY TOOLS SUCCEEDED ===
        # #region agent log
        try:
            import json
            with open("snode_debug.log", "a") as f:
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H2","location":"analyzer_tool.py:87","message":"Analyzer entry - check results","data":{"results_keys":list(results.keys()),"results_count":len(results)},"timestamp":int(__import__("time").time()*1000)})+"\n")
        except: pass
        # #endregion
        
        successful_tools = [t for t, d in results.items() if d.get("success")]
        failed_tools = [t for t, d in results.items() if not d.get("success")]
        
        # #region agent log
        try:
            import json
            with open("snode_debug.log", "a") as f:
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H2","location":"analyzer_tool.py:90","message":"Tools classification","data":{"successful_tools":successful_tools,"failed_tools":failed_tools,"all_tools":list(results.keys())},"timestamp":int(__import__("time").time()*1000)})+"\n")
        except: pass
        # #endregion
        
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
                "response": error_msg,
                "next_action": "respond"
            }
        
        # Format results for LLM - use more context for better analysis
        # CRITICAL: Only include results from CURRENT execution, not from previous runs
        results_str = ""
        for tool, data in results.items():
            if data.get("success"):
                output = data.get("output", "")[:4000]
                results_str += f"\n{tool}: SUCCESS\n{output}\n"
            else:
                results_str += f"\n{tool}: FAILED - {data.get('error', 'Unknown error')}\n"
        
        # Debug: Log what tools are in results
        if not results_str.strip():
            logger.warning(f"WARNING: No results to analyze! Tools in results: {list(results.keys())}")
        else:
            tools_in_results = [t for t in results.keys() if results[t].get("success")]
            logger.info(f"Analyzing results from: {', '.join(tools_in_results) if tools_in_results else 'no successful tools'}")
            
            # CRITICAL DEBUG: Check if results_str contains unexpected tools
            if len(tools_in_results) > 0:
                mentioned_tools = re.findall(r'\b(nmap|nikto|nuclei|sqlmap|masscan|httpx|subfinder|amass)\b', results_str.lower())
                mentioned_tools = list(set(mentioned_tools))
                unexpected = [t for t in mentioned_tools if t not in [tool.lower() for tool in tools_in_results]]
                if unexpected:
                    logger.warning(f"WARNING: Results string mentions tools not in current execution: {unexpected}")
                    print(f"     Current tools: {tools_in_results}")
                    print(f"     This may indicate stale data or cross-contamination")
        
        # NEW: Append specialized agent analysis
        try:
            from app.agent.orchestration import get_coordinator
            
            agent_name = context.get("current_agent", "base")
            agent = get_coordinator().get_agent(agent_name)
            if agent:
                # Pass context to analyze_results
                agent_analysis = agent.analyze_results(results, context)
                if agent_analysis:
                    results_str += f"\n\nAGENCY ANALYSIS ({agent.AGENT_NAME}):\n{agent_analysis}\n"
                    print(f"  🧠 Included insights from {agent.AGENT_NAME} agent")
        except Exception as e:
            logger.error(f"Agent analysis failed: {e}")
        
        # ============================================================
        cve_context = ""
        try:
            from app.rag.cve_web_lookup import search_cves_with_fallback
            from app.agent.prompt_loader import format_prompt
            from datetime import datetime
            
            # Use LLM to extract technologies (replaces brittle regex)
            tech_prompt = format_prompt("tech_extractor", results_str=results_str)
            try:
                # Quick extraction call (low temp for precision) - silent, no spinner
                tech_response = llm.generate(tech_prompt, timeout=30, stream=False, show_content=False, verbose=False)
                
                detected_tech = []
                if tech_response and "None" not in tech_response:
                    # Clean up response (handle potential newlines or bullets)
                    clean_response = re.sub(r'[\n\r]+', ', ', tech_response)
                    # Split by comma
                    items = [t.strip() for t in clean_response.split(',')]
                    detected_tech = [t for t in items if t and len(t) > 2]
                    
                logger.info(f"Detected Tech (LLM): {detected_tech}")
            
            except Exception as e:
                logger.warning(f"Tech extraction failed: {e}")
                detected_tech = []
            
            # Store detected tech for exploit tools to use
            if detected_tech:
                context["detected_tech"] = list(set(detected_tech))[:10]
                
                # Search CVEs using the extracted terms (with web fallback for recent CVEs)
                search_query = ", ".join(detected_tech[:5])  # Search for top 5 terms
                primary_tech = detected_tech[0] if detected_tech else None
                current_year = datetime.now().year
                
                cve_results = search_cves_with_fallback(
                    query=search_query,
                    technology=primary_tech,
                    year=current_year  # Include current year for web search
                )
                
                if cve_results.get("cves"):

                    filtered_cves = []
                    detected_tech_lower = [t.lower() for t in detected_tech]
                    
                    for cve in cve_results["cves"]:
                        # Check if CVE products/vendors match any detected tech
                        products = cve.get("products", "").lower()
                        vendors = cve.get("vendors", "").lower()
                        title = cve.get("title", "").lower()
                        description = cve.get("description", "").lower()
                        
                        # Check if any detected tech appears in CVE metadata
                        matches = False
                        for tech in detected_tech_lower:
                            # Normalize tech name (remove version numbers, common suffixes)
                            tech_normalized = re.sub(r'\s*(v?\d+\.?\d*|latest|unspecific)', '', tech).strip()
                            if len(tech_normalized) < 3:  # Skip very short tech names
                                continue
                            
                            # Check if tech appears in products, vendors, title, or description
                            if (tech_normalized in products or 
                                tech_normalized in vendors or 
                                tech_normalized in title or 
                                tech_normalized in description):
                                matches = True
                                break
                        
                        if matches:
                            filtered_cves.append(cve)
                    
                    # Only use filtered CVEs if we found matches, otherwise skip CVE context
                    if filtered_cves:
                        context["last_cves"] = filtered_cves
                        context["cve_query"] = search_query
                        
                        cve_context = "\n\n⚠️ POTENTIAL CVEs (Found via RAG matching):\n"
                        cve_context += "Verify if these actually apply to the target version:\n"
                        for cve in filtered_cves[:3]:
                            cve_id = cve.get("cve_id", "Unknown")
                            desc = cve.get("description", "")[:100]
                            severity = cve.get("severity", "Unknown")
                            products = cve.get("products", "Unknown product")
                            cve_context += f"- {cve_id} ({severity}) {products}: {desc}...\n"
                        
                        # Log source info if available
                        sources = cve_results.get("sources", {})
                        source_info = ""
                        if sources:
                            local_count = sources.get("local", 0)
                            web_count = sources.get("web", 0)
                            if web_count > 0:
                                source_info = f" ({local_count} local, {web_count} from web)"
                        
                        logger.info(f"CVE RAG: found {len(filtered_cves)} relevant CVEs{source_info}")
                    else:
                        # No matching CVEs found - don't add CVE context to avoid false positives
                        logger.info(f"CVE RAG: found {len(cve_results['cves'])} CVEs but none match detected technologies")
            else:
                logger.info("CVE RAG: No technologies detected in output")
                
        except Exception as e:
            logger.error(f"CVE RAG Error: {e}")
        
        # ============================================================
        # PURE LLM ANALYSIS - Attack Chain Focus
        # ============================================================
        
        # CRITICAL: Update tools_run BEFORE analyzer runs so it knows what tools were just executed
        tools_run = context.get("tools_run", [])
        tools_to_add = successful_tools if successful_tools else []
        if tools_to_add:
            tools_run.extend(tools_to_add)
            context["tools_run"] = list(set(tools_run))  # Deduplicate
        
        # Load prompt from external file
        from app.agent.prompt_loader import format_prompt
        
        # Format tools_run as comma-separated string for prompt (now includes current tools)
        tools_run_list = context.get('tools_run', [])
        tools_run_str = ", ".join(tools_run_list) if tools_run_list else "none"
        
        # #region agent log
        try:
            import json
            with open("snode_debug.log", "a") as f:
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H3","location":"analyzer_tool.py:354","message":"Before building analyzer prompt","data":{"subdomain_count":context.get('subdomain_count',0),"has_subdomains":context.get('has_subdomains',False),"results_keys":list(results.keys()),"amass_in_results":'amass' in results,"amass_success":results.get('amass',{}).get('success',False) if 'amass' in results else False},"timestamp":int(__import__("time").time()*1000)})+"\n")
        except: pass
        # #endregion
        
        prompt = format_prompt("analyzer",
            results_str=results_str,
            cve_context=cve_context,
            domain=context.get('last_domain', 'unknown'),
            subdomain_count=context.get('subdomain_count', 0),
            has_ports=context.get('has_ports', False),
            detected_tech=context.get('detected_tech', []),
            tools_run=tools_run_str,  # Pass as string, not list
            security_tech_context=_get_security_tech_context(context)
        )
        
        # #region agent log
        try:
            import json
            with open("snode_debug.log", "a") as f:
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H3","location":"analyzer_tool.py:349","message":"Before LLM generate call","data":{"timeout":90,"prompt_length":len(prompt),"tools_in_results":len(successful_tools)},"timestamp":int(__import__("time").time()*1000)})+"\n")
        except: pass
        # #endregion
        
        # Stream the analysis - user wants to see this thinking process
        response = llm.generate(prompt, timeout=90, stream=True, show_thinking=True, show_content=True)
        
        # #region agent log
        try:
            import json
            with open("snode_debug.log", "a") as f:
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H3","location":"analyzer_tool.py:355","message":"After LLM generate call","data":{"response_length":len(response) if response else 0,"response_preview":response[:200] if response else ""},"timestamp":int(__import__("time").time()*1000)})+"\n")
        except: pass
        # #endregion
        
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
                        fixed = re.sub(r"'([^']*)':", r'"\1":', json_str)
                        fixed = re.sub(r": '([^']*)'", r': "\1"', fixed)
                        data = json.loads(fixed)
                    except json.JSONDecodeError:
                        pass
                
                # Strategy 3: Fix unescaped characters
                if data is None:
                    try:
                        fixed = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_str)
                        fixed = re.sub(r',\s*}', '}', fixed)
                        fixed = re.sub(r',\s*]', ']', fixed)
                        data = json.loads(fixed)
                    except json.JSONDecodeError:
                        pass
                
                # Strategy 4: Extract just the key fields manually
                if data is None:
                    data = {}
                    tool_match = re.search(r'"next_tool"\s*:\s*"([^"]+)"', clean_response)
                    if tool_match:
                        data["next_tool"] = tool_match.group(1)
                    attack_match = re.search(r'"best_attack"\s*:\s*"([^"]+)"', clean_response)
                    if attack_match:
                        data["best_attack"] = attack_match.group(1)
                    summary_match = re.search(r'"summary"\s*:\s*"([^"]+)"', clean_response)
                    if summary_match:
                        data["summary"] = summary_match.group(1)
            
            # #region agent log
            try:
                import json
                with open("snode_debug.log", "a") as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H4","location":"analyzer_tool.py:400","message":"JSON parsing result","data":{"data_is_none":data is None,"has_findings":bool(data.get("findings")) if data else False,"has_next_tool":bool(data.get("next_tool")) if data else False},"timestamp":int(__import__("time").time()*1000)})+"\n")
            except: pass
            # #endregion
            
            if data:
                findings = data.get("findings", [])
                findings_str = ""
                if findings:
                    findings_str = "\n\n## 🎯 Attack Vectors Identified\n\n"
                    for f in findings:
                        severity = f.get("severity", "Unknown")
                        badge = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                        findings_str += f"{badge} **{f.get('issue')}** ({severity})\n"
                        attack = f.get("attack") or f.get("risk", "")
                        if attack:
                            findings_str += f"   → Exploit: {attack}\n\n"
                
                # Best attack vector
                best_attack = data.get("best_attack_vector", "")
                
                # Next step recommendation
                next_tool = data.get("next_tool") or (data.get("next_tools", [None])[0] if data.get("next_tools") else None)
                next_target_raw = data.get("next_target", "")
                next_reason = data.get("next_reason", "")
                summary = data.get("summary", "")
                
                # CRITICAL: Validate that next_tool is not already in tools_run
                rejected_tool = None
                if next_tool and tools_run_list:
                    if next_tool in tools_run_list:
                        rejected_tool = next_tool
                        logger.warning(f"LLM suggested '{next_tool}' but it's already in tools_run: {tools_run_list}. Rejecting suggestion.")
                        # Clear next_tool to force user/planner to suggest something else
                        next_tool = None
                        next_reason = None  # Clear reason too since tool was rejected
                        # Update summary to reflect this
                        if summary:
                            summary += f" Note: {rejected_tool} was already executed in this session. Need a different tool for next step."
                
                # Normalize next_target - never allow "None" string
                domain = context.get("last_domain") or context.get("domain", "")
                
                if not next_target_raw or next_target_raw.lower() in ["none", "null", "n/a", ""]:
                    next_target = domain if domain else ""
                else:
                    if "." in next_target_raw and len(next_target_raw) > 3:
                        next_target = next_target_raw
                    else:
                        next_target = domain if domain else ""
                
                # Build response with attack-focused analysis
                # Use UI components for better formatting (separate panels)
                response_text = ""
                use_ui_components = False
                
                try:
                    from app.ui.components import AnalyzerResultCard
                    from app.ui.console import get_console
                    analyzer_card = AnalyzerResultCard(get_console())
                    panels = analyzer_card.render(
                        findings=findings,
                        best_attack=best_attack,
                        summary=summary,
                        next_tool=next_tool,
                        next_target=next_target if next_target else domain,
                        next_reason=next_reason
                    )
                    
                    # Render panels immediately if we have them
                    if panels:
                        use_ui_components = True
                        console = get_console()
                        for panel in panels:
                            console.print(panel)
                            console.print()  # Spacing between panels
                        # Keep response_text empty since we already rendered via UI
                        response_text = ""
                except (ImportError, Exception) as e:
                    # Fallback to markdown format if UI components fail
                    logger.warning(f"UI components not available, using markdown: {e}")
                
                # Fallback: Build markdown response if UI components not available
                if not use_ui_components:
                    if findings_str:
                        response_text += findings_str
                    
                    if best_attack:
                        response_text += f"\n## ⚡ Best Attack Vector\n{best_attack}\n"
                    
                    if summary:
                        response_text += f"\n## 📊 Analysis\n{summary}\n"
                    
                    # Show next step with specific target
                    if next_tool:
                        next_step = f"Use **{next_tool}**"
                        if next_target:
                            next_step += f" on `{next_target}`"
                        elif domain:
                            next_step += f" on `{domain}`"
                        if next_reason:
                            next_step += f" - {next_reason}"
                        response_text += f"\n\n**💡 Next Attack Step:** {next_step}"
                    elif next_reason:
                        response_text += f"\n\n**💡 Recommended next step:** {next_reason}"
                
                # Store next_tool in context for "do the next step" command
                if next_tool:
                    normalized_tool = next_tool.lower().strip()
                    
                    # List of valid tool names for matching
                    valid_tools = [
                        "subfinder", "amass", "theHarvester", "dnsrecon", "dig", "clatscope", 
                        "shodan", "securitytrails", "recon-ng", "fierce", "spiderfoot", "emailharvester",
                        "nmap", "masscan", "httpx", "whatweb", "wafw00f",
                        "nuclei", "nikto", "wpscan", "testssl", "sqlmap",
                        "hydra", "metasploit", "searchsploit", "crackmapexec",
                        "gobuster", "dirsearch", "feroxbuster", "ffuf"
                    ]
                    
                    # First, check if it's already a valid tool name
                    if normalized_tool not in valid_tools:
                        # Pattern matching to extract tool name
                        tool_match = re.search(r'(?:\(e\.g\.,\s*|tool\s+is\s+|use\s+)?([a-z0-9_-]+)(?:\s+tool|\s+\(|$)', normalized_tool, re.IGNORECASE)
                        if tool_match:
                            candidate = tool_match.group(1).lower()
                            if candidate in valid_tools:
                                normalized_tool = candidate
                            else:
                                alt_match = re.search(r'(?:e\.g\.,\s*|example:\s*)([A-Z][a-z0-9_-]+)', next_tool)
                                if alt_match:
                                    candidate = alt_match.group(1).lower()
                                    if candidate in valid_tools:
                                        normalized_tool = candidate
                                for tool in valid_tools:
                                    if tool in normalized_tool:
                                        normalized_tool = tool
                                        break
                        else:
                            alt_match = re.search(r'(?:e\.g\.,\s*|example:\s*)([A-Z][a-z0-9_-]+)', next_tool)
                            if alt_match:
                                candidate = alt_match.group(1).lower()
                                if candidate in valid_tools:
                                    normalized_tool = candidate
                            for tool in valid_tools:
                                if tool in normalized_tool:
                                    normalized_tool = tool
                                    break
                    
                    # Validate tool exists in registry
                    try:
                        from app.tools.registry import get_registry
                        registry = get_registry()
                        
                        tool_name_mapping = {
                            "selenium": None,
                            "browser": None,
                            "emulation": None,
                        }
                        
                        if normalized_tool in tool_name_mapping:
                            mapped_tool = tool_name_mapping[normalized_tool]
                            if mapped_tool and registry.is_available(mapped_tool):
                                normalized_tool = mapped_tool
                            else:
                                normalized_tool = None
                        
                        if normalized_tool and registry.is_available(normalized_tool):
                            context["analyzer_next_tool"] = normalized_tool
                        elif normalized_tool:
                            normalized_tool = None
                    except Exception:
                        normalized_tool = None
                    
                    if normalized_tool:
                        context["analyzer_next_tool"] = normalized_tool
                        context["analyzer_next_target"] = next_target if next_target else domain
                        context["analyzer_next_reason"] = next_reason
                        
                        try:
                            from app.tools.registry import get_registry
                            registry = get_registry()
                            tool_available = registry.is_available(normalized_tool)
                            context["analyzer_next_tool_available"] = tool_available
                        except Exception:
                            context["analyzer_next_tool_available"] = False
                        
                        # Also store in session memory for persistence across queries
                        try:
                            from app.memory import get_session_memory
                            session_memory = get_session_memory()
                            if not hasattr(session_memory, 'analyzer_recommendations'):
                                session_memory.analyzer_recommendations = {}
                            session_memory.analyzer_recommendations = {
                                "next_tool": normalized_tool,
                                "next_target": next_target if next_target else domain,
                                "next_reason": next_reason,
                                "available": context.get("analyzer_next_tool_available", False),
                                "timestamp": time.time()
                            }
                        except Exception:
                            pass
                
                # PHASE COMPLETION CHECK
                auto_chain = False
                chain_tools = []
                chain_target = None
                
                try:
                    from app.agent.orchestration import get_coordinator
                    coordinator = get_coordinator()
                    advance = coordinator.auto_advance(context)
                    
                    if advance:
                        phase_msg = f"\n\n---\n🔄 **{advance['phase_name']} Phase Complete!**\n"
                        phase_msg += f"✅ {advance['reason']}\n"
                        if advance.get("next_phase_name"):
                            phase_msg += f"\n**Ready for {advance['next_phase_name']} phase.**"
                            if advance.get("next_action"):
                                phase_msg += f"\n💡 Next: {advance['next_action']}"
                        response_text += phase_msg
                        context["phase_complete"] = True
                        context["current_phase"] = advance.get("next_phase", advance["phase"])
                        
                        if context.get("auto_mode") and advance.get("suggested_tools"):
                            auto_chain = True
                            chain_tools = advance.get("suggested_tools", [])[:2]
                            chain_target = next_target if next_target else domain
                            print(f"  🔗 Auto-chain enabled: will run {chain_tools} on {chain_target}")
                except Exception as e:
                    logger.warning(f"Phase check error: {e}")
                
                if not auto_chain and context.get("auto_mode") and next_tool:
                    auto_chain = True
                    chain_tools = [next_tool]
                    chain_target = next_target if next_target else domain
                    print(f"  🔗 Auto-chain from analyzer: {chain_tools} on {chain_target}")
                
                if auto_chain and chain_tools:
                    context["pending_auto_tools"] = chain_tools
                    context["pending_auto_target"] = chain_target
                    
                    return {
                        "response": response_text,
                        "context": context,
                        "suggested_tools": chain_tools,
                        "next_action": "auto_chain"
                    }
                
                # Ensure we have a response text to avoid "No response" error
                # If UI components rendered, use summary as fallback response text
                fallback_response = summary if summary else "Analysis complete."
                final_response = response_text if response_text else fallback_response
                
                # ============================================================
                # CHECKLIST COMPLETION CHECK
                # ============================================================
                checklist = context.get("checklist", [])
                current_task_id = context.get("current_task_id")
                
                if checklist and current_task_id:
                    from app.agent.analyzer import get_checklist_manager
                    checklist_manager = get_checklist_manager()
                    session_id = context.get("session_id", "default")
                    
                    # Mark current task as completed with results
                    checklist_manager.mark_completed(current_task_id, results, session_id)
                    
                    # Check if checklist is complete
                    if checklist_manager.is_complete(session_id):
                        context["checklist_complete"] = True
                        progress = checklist_manager.get_progress(session_id)
                        print(f"  ✅ Checklist complete! ({progress['completed']}/{progress['total']} tasks)")
                        
                        # Route to reasoning for comprehensive analysis
                        result = {
                            "response": final_response,
                            "context": context,
                            "next_action": "reasoning",  # Route to reasoning node
                            "response_streamed": use_ui_components
                        }
                    else:
                        # Get next task
                        next_task = checklist_manager.get_next_task(session_id)
                        if next_task:
                            print(f"  📋 Next task: {next_task.description} (Phase {next_task.phase})")
                            context["current_task_id"] = None  # Will be set by planner
                            # Route back to planner for next task
                            result = {
                                "response": final_response,
                                "context": context,
                                "next_action": "planner",  # Route back to planner
                                "response_streamed": use_ui_components
                            }
                        else:
                            # No next task available (all blocked or done)
                            result = {
                                "response": final_response,
                                "context": context,
                                "next_action": "respond",
                                "response_streamed": use_ui_components
                            }
                    # Update checklist in context
                    context["checklist"] = checklist_manager.to_dict(session_id)
                else:
                    # No checklist, normal flow
                    result = {
                        "response": final_response,  
                        "context": context,
                        "next_action": "respond",
                        "response_streamed": use_ui_components  
                    }
                
                if use_ui_components:
                    result["suggested_tools"] = []  
                    result["suggestion_message"] = ""  
                
                return result
            else:
                # No JSON data extracted - fallback to raw response
                # #region agent log
                try:
                    import json
                    with open("snode_debug.log", "a") as f:
                        f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"H4","location":"analyzer_tool.py:738","message":"No structured data extracted","data":{"clean_response_length":len(clean_response),"clean_response_preview":clean_response[:500],"json_match_found":bool(json_match)},"timestamp":int(__import__("time").time()*1000)})+"\n")
                except: pass
                # #endregion
                logger.warning("Analyzer: No structured data extracted, using raw response")
                return {
                    "response": clean_response[:2000] if len(clean_response) > 2000 else clean_response,
                    "context": context,
                    "next_action": "respond",
                    "response_streamed": True
                }
        except Exception as e:
            logger.error(f"Analyzer execution error: {e}")
            # Fallback - show formatted tool results (LLM failed to parse)
            logger.info(f"Fallback: formatting {len(results)} tool results...")
            formatted = "**Scan Results:**\n\n"
            
            for tool, data in results.items():
                if isinstance(data, dict):
                    if data.get("success"):
                        output = data.get("output", "")
                        if len(output) > 3000:
                            output = output[:3000] + "\n... (truncated)"
                        formatted += f"### {tool.upper()}\n```\n{output}\n```\n\n"
                    else:
                        formatted += f"### {tool.upper()}\n❌ {data.get('error', 'Unknown error')}\n\n"
            
            formatted += "\n---\n**ℹ️ LLM analysis unavailable.** The tool outputs are shown above in raw format. Key findings should be extracted manually.\n"
            
            if formatted.strip() == "**Scan Results:**":
                formatted = "**Note:** No tool results to display. The scan may not have produced output."
            
            logger.success(f"Fallback response: {len(formatted)} chars")
            return {
                "response": formatted,
                "context": context,
                "next_action": "respond",
                "response_streamed": False
            }
    
    def execute_small_analyze(self, execution_results: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Small analyze for a single iteration in AutoChain mode.
        
        Args:
            execution_results: Results from one iteration
            context: Current context
            
        Returns:
            Dictionary with summary and key findings
        """
        if context is None:
            context = {}
        
        # Use analyzer model for analyzing tool outputs
        llm = OllamaClient(model="analyzer")
        
        # Build results summary
        results_str = ""
        successful_tools = []
        failed_tools = []
        
        for tool_name, result in execution_results.items():
            if isinstance(result, dict):
                if result.get("success"):
                    successful_tools.append(tool_name)
                    output = result.get("output", "")[:500]  # Limit length
                    results_str += f"\n{tool_name}:\n{output}\n"
                else:
                    failed_tools.append(tool_name)
                    error = result.get("error", "Unknown error")[:200]
                    results_str += f"\n{tool_name} (FAILED): {error}\n"
            else:
                results_str += f"\n{tool_name}: {str(result)[:500]}\n"
        
        # Simple prompt for 1-2 sentence summary
        prompt = f"""Summarize the results of this security testing iteration in 1-2 sentences. Focus on key findings.

Tools executed: {', '.join(successful_tools) if successful_tools else 'None'}
Failed tools: {', '.join(failed_tools) if failed_tools else 'None'}

Results:
{results_str}

Provide a brief summary (1-2 sentences) of what was found in this iteration."""
        
        try:
            summary = llm.generate(prompt, timeout=30, stream=False, show_content=False).strip()
            
            # Extract key findings (simple extraction)
            key_findings = []
            if successful_tools:
                key_findings.append(f"Executed: {', '.join(successful_tools)}")
            if failed_tools:
                key_findings.append(f"Failed: {', '.join(failed_tools)}")
            
            return {
                "summary": summary,
                "key_findings": key_findings,
                "successful_tools": successful_tools,
                "failed_tools": failed_tools
            }
        except Exception as e:
            return {
                "summary": f"Iteration completed. Tools: {', '.join(successful_tools) if successful_tools else 'None'}",
                "key_findings": [],
                "successful_tools": successful_tools,
                "failed_tools": failed_tools
            }
    
    def execute_comprehensive_analyze(self, autochain_results: List[Dict[str, Any]], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Comprehensive analyze after 5 iterations in AutoChain mode.
        
        Args:
            autochain_results: List of results from all 5 iterations
            context: Current context
            
        Returns:
            Comprehensive analysis with all findings, vulnerabilities, attack vectors, next steps
        """
        if context is None:
            context = {}
        
        # Use analyzer model for analyzing tool outputs
        llm = OllamaClient(model="analyzer")
        
        # Aggregate all results from 5 iterations
        all_results_str = ""
        all_tools_run = []
        all_successful_tools = []
        all_failed_tools = []
        
        for i, iteration_result in enumerate(autochain_results, 1):
            iteration_summary = iteration_result.get("summary", "No summary")
            execution_results = iteration_result.get("execution_results", {})
            successful = iteration_result.get("successful_tools", [])
            failed = iteration_result.get("failed_tools", [])
            
            all_tools_run.extend(successful)
            all_successful_tools.extend(successful)
            all_failed_tools.extend(failed)
            
            all_results_str += f"\n--- Iteration {i} ---\n"
            all_results_str += f"Summary: {iteration_summary}\n"
            all_results_str += f"Tools: {', '.join(successful) if successful else 'None'}\n"
            
            # Add execution results
            for tool_name, result in execution_results.items():
                if isinstance(result, dict) and result.get("success"):
                    output = result.get("output", "")[:1000]  # Limit length
                    all_results_str += f"\n{tool_name} output:\n{output[:500]}...\n"
        
        # Get detected technologies from context
        detected_tech = context.get("detected_tech", [])
        tech_context = ""
        if detected_tech:
            tech_context = f"\nDetected Technologies: {', '.join(detected_tech[:10])}\n"
        
        # Get CVE context if available
        cve_context = ""
        last_cves = context.get("last_cves", [])
        if last_cves:
            cve_context = "\n\n⚠️ POTENTIAL CVEs:\n"
            for cve in last_cves[:5]:
                cve_id = cve.get("cve_id", "Unknown")
                severity = cve.get("severity", "Unknown")
                products = cve.get("products", "Unknown")
                cve_context += f"- {cve_id} ({severity}) {products}\n"
        
        # Comprehensive analysis prompt
        prompt = f"""Analyze all 5 iterations of security testing and provide a comprehensive summary.

Target: {context.get('target_domain') or context.get('last_domain', 'Unknown')}

All Iterations Summary:
{all_results_str}

{tech_context}
{cve_context}

Tools executed across all iterations: {', '.join(set(all_successful_tools))}
Failed tools: {', '.join(set(all_failed_tools)) if all_failed_tools else 'None'}

Provide a comprehensive analysis including:
1. All findings discovered
2. Vulnerabilities identified
3. Attack vectors available
4. Next steps recommendations

Format your response as a detailed security assessment."""
        
        try:
            # Use the same format as regular analyzer
            from app.agent.prompt_loader import format_prompt
            
            # Build comprehensive results string for prompt
            comprehensive_results = all_results_str
            
            # Get security tech context
            security_tech_context = _get_security_tech_context(context)
            
            # Use similar prompt structure as execute() method
            analysis_prompt = format_prompt(
                "analyzer",
                results_str=comprehensive_results,
                target=context.get("target_domain") or context.get("last_domain", "unknown"),
                tools_run=", ".join(set(all_tools_run)),
                security_tech_context=security_tech_context,
                cve_context=cve_context
            )
            
            response = llm.generate(analysis_prompt, timeout=90, stream=True, show_thinking=True, show_content=True)
            
            # Parse response similar to execute() method
            try:
                clean_response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL)
                
                # Try to extract JSON
                json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', clean_response, re.DOTALL)
                
                data = None
                if json_match:
                    json_str = json_match.group()
                    try:
                        data = json.loads(json_str)
                    except json.JSONDecodeError:
                        # Try fixing common issues
                        try:
                            fixed = re.sub(r"'([^']*)':", r'"\1":', json_str)
                            fixed = re.sub(r": '([^']*)'", r': "\1"', fixed)
                            data = json.loads(fixed)
                        except json.JSONDecodeError:
                            pass
                
                # Build response text
                response_text = ""
                
                if data:
                    findings = data.get("findings", [])
                    if findings:
                        response_text += "\n## 🎯 Attack Vectors Identified\n\n"
                        for f in findings:
                            severity = f.get("severity", "Unknown")
                            badge = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                            response_text += f"{badge} **{f.get('issue')}** ({severity})\n"
                            attack = f.get("attack") or f.get("risk", "")
                            if attack:
                                response_text += f"   → Exploit: {attack}\n\n"
                    
                    best_attack = data.get("best_attack_vector", "")
                    if best_attack:
                        response_text += f"\n## ⚡ Best Attack Vector\n{best_attack}\n"
                    
                    summary = data.get("summary", "")
                    if summary:
                        response_text += f"\n## 📊 Comprehensive Analysis\n{summary}\n"
                    
                    next_tool = data.get("next_tool")
                    if next_tool:
                        response_text += f"\n💡 Next Recommended Step: Use **{next_tool}**\n"
                else:
                    # Fallback: use raw response
                    response_text = clean_response
                
                return {
                    "response": response_text,
                    "context": context,
                    "next_action": "respond",
                    "response_streamed": True
                }
            except Exception as e:
                # Fallback to raw response
                return {
                    "response": response,
                    "context": context,
                    "next_action": "respond",
                    "response_streamed": True
                }
            except Exception as e:
                logger.warning(f"Comprehensive analysis parse error: {e}")
                return {
                    "response": f"Comprehensive analysis completed. {len(autochain_results)} iterations analyzed. Tools executed: {', '.join(set(all_successful_tools))}",
                    "context": context,
                    "next_action": "respond",
                    "response_streamed": False
                }
        except Exception as e:
            logger.warning(f"Comprehensive analysis error: {e}")
            return {
                "response": f"Comprehensive analysis completed. {len(autochain_results)} iterations analyzed.",
                "context": context,
                "next_action": "respond",
                "response_streamed": False
            }
        
        # Fallback - show formatted tool results (LLM failed to parse)
        logger.info(f"Fallback: formatting {len(results)} tool results...")
        formatted = "**Scan Results:**\n\n"
        
        for tool, data in results.items():
            if isinstance(data, dict):
                if data.get("success"):
                    output = data.get("output", "")
                    if len(output) > 3000:
                        output = output[:3000] + "\n... (truncated)"
                    formatted += f"### {tool.upper()}\n```\n{output}\n```\n\n"
                else:
                    formatted += f"### {tool.upper()}\n❌ {data.get('error', 'Unknown error')}\n\n"
        
        formatted += "\n---\n**ℹ️ LLM analysis unavailable.** The tool outputs are shown above in raw format. Key findings should be extracted manually.\n"
        
        if formatted.strip() == "**Scan Results:**":
            formatted = "**Note:** No tool results to display. The scan may not have produced output."
        
        logger.success(f"Fallback response: {len(formatted)} chars")
        return {
            "response": formatted,
            "next_action": "respond"
        }
