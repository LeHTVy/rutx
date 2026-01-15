"""
Analyzer Tool - Clean Refactored Version

LLM analyzes security tool execution results and provides insights.
Focus: Pure LLM streaming response with clear prompt about security analysis purpose.
"""
import re
import json
from typing import Dict, Any, Optional, List
from app.agent.tools.base import AgentTool
from app.llm.client import OllamaClient
from app.ui import get_logger

logger = get_logger()


def _get_security_tech_context(context: dict) -> str:
    """Generate security tech bypass context for the LLM."""
    detected_security = context.get("detected_security_tech", [])
    if not detected_security:
        return ""
    
    try:
        from app.rag.security_tech import SECURITY_TECH_DB
        
        security_context = "\n- **SECURITY DEFENSES DETECTED:**\n"
        for tech_id in detected_security[:3]:
            tech = SECURITY_TECH_DB.get(tech_id)
            if tech:
                security_context += f"  * {tech.name} ({tech.category}): {tech.description[:80]}...\n"
                security_context += f"    BYPASS METHODS:\n"
                for method in tech.bypass_methods[:2]:
                    security_context += f"      - {method['method']}: {method['description'][:60]}...\n"
                if tech.origin_discovery and tech.category == "cdn_waf":
                    security_context += f"    ORIGIN IP DISCOVERY: {', '.join(tech.origin_discovery[:2])}\n"
        return security_context
    except Exception:
        return ""


def _format_results_for_llm(results: Dict[str, Any]) -> str:
    """Format tool results into string for LLM analysis."""
    results_str = ""
    for tool, data in results.items():
        if data.get("success"):
            output = data.get("output", "")[:4000]
            results_str += f"\n{tool}: SUCCESS\n{output}\n"
        else:
            results_str += f"\n{tool}: FAILED - {data.get('error', 'Unknown error')}\n"
    return results_str


def _get_cve_context(results_str: str, context: Dict[str, Any]) -> str:
    """Extract technologies and search for relevant CVEs."""
    cve_context = ""
    try:
        from app.rag.cve_web_lookup import search_cves_with_fallback
        from app.agent.prompt_loader import format_prompt
        from datetime import datetime
        from app.llm.client import OllamaClient
        
        llm = OllamaClient(model="analyzer")
        
        # Extract technologies using LLM
        tech_prompt = format_prompt("tech_extractor", results_str=results_str)
        try:
            tech_response = llm.generate(tech_prompt, timeout=30, stream=False, show_content=False, verbose=False)
            detected_tech = []
            if tech_response and "None" not in tech_response:
                clean_response = re.sub(r'[\n\r]+', ', ', tech_response)
                items = [t.strip() for t in clean_response.split(',')]
                detected_tech = [t for t in items if t and len(t) > 2]
            
            logger.info(f"Detected Tech (LLM): {detected_tech}")
            
            if detected_tech:
                context["detected_tech"] = list(set(detected_tech))[:10]
                search_query = ", ".join(detected_tech[:5])
                primary_tech = detected_tech[0] if detected_tech else None
                current_year = datetime.now().year
                
                cve_results = search_cves_with_fallback(
                    query=search_query,
                    technology=primary_tech,
                    year=current_year
                )
                
                if cve_results.get("cves"):
                    filtered_cves = []
                    detected_tech_lower = [t.lower() for t in detected_tech]
                    
                    for cve in cve_results["cves"]:
                        products = cve.get("products", "").lower()
                        vendors = cve.get("vendors", "").lower()
                        title = cve.get("title", "").lower()
                        description = cve.get("description", "").lower()
                        
                        matches = False
                        for tech in detected_tech_lower:
                            tech_normalized = re.sub(r'\s*(v?\d+\.?\d*|latest|unspecific)', '', tech).strip()
                            if len(tech_normalized) < 3:
                                continue
                            if (tech_normalized in products or 
                                tech_normalized in vendors or 
                                tech_normalized in title or 
                                tech_normalized in description):
                                matches = True
                                break
                        
                        if matches:
                            filtered_cves.append(cve)
                    
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
                        logger.info(f"CVE RAG: found {len(filtered_cves)} relevant CVEs")
        except Exception as e:
            logger.warning(f"Tech extraction failed: {e}")
    except Exception as e:
        logger.error(f"CVE RAG Error: {e}")
    
    return cve_context


def _handle_all_tools_failed(results: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Handle case when all tools failed."""
    error_msg = "⚠️ **All scans failed or timed out:**\n\n"
    
    for tool, data in results.items():
        error = data.get("error", "") or data.get("output", "")
        error_msg += f"- **{tool}**: {error[:100]}...\n" if len(error) > 100 else f"- **{tool}**: {error}\n"
    
    detected_security = context.get("detected_security_tech", [])
    if detected_security:
        try:
            from app.rag.security_tech import SECURITY_TECH_DB
            for tech_id in detected_security:
                tech = SECURITY_TECH_DB.get(tech_id)
                if tech:
                    error_msg += f"\n🛡️ **{tech.name} Detected!** ({tech.category})\n"
                    error_msg += f"{tech.description}\n\n"
                    error_msg += "**Bypass Methods:**\n"
                    for method in tech.bypass_methods[:3]:
                        error_msg += f"- {method['method']}: {method['description']}\n"
                    break
        except Exception:
            pass
    
    return {
        "response": error_msg,
        "next_action": "respond"
    }


def _extract_json_from_response(response: str) -> Optional[Dict[str, Any]]:
    """
    Extract JSON from LLM response with multiple fallback strategies.
    
    Supports:
    1. JSON block at the end (```json ... ```)
    2. JSON object anywhere in response
    3. Extract key fields from natural language if no JSON found
    """
    clean_response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL)
    
    # Strategy 1: Look for JSON code block at the end (optional JSON block)
    json_block_pattern = r'```json\s*(\{[\s\S]*?\})\s*```'
    json_block_match = re.search(json_block_pattern, clean_response, re.DOTALL)
    if json_block_match:
        try:
            return json.loads(json_block_match.group(1))
        except json.JSONDecodeError:
            pass
    
    # Strategy 2: Look for any JSON object
    json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', clean_response, re.DOTALL)
    if json_match:
        json_str = json_match.group()
        
        # Try direct parse
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Try fixing single quotes
        try:
            fixed = re.sub(r"'([^']*)':", r'"\1":', json_str)
            fixed = re.sub(r": '([^']*)'", r': "\1"', fixed)
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
        
        # Try fixing unescaped characters
        try:
            fixed = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_str)
            fixed = re.sub(r',\s*}', '}', fixed)
            fixed = re.sub(r',\s*]', ']', fixed)
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
    
    # Strategy 3: Extract key fields from natural language (fallback)
    # Look for patterns like "next tool: nmap" or "recommend running nmap"
    data = {}
    
    # Extract next_tool from natural language
    tool_patterns = [
        r'(?:next tool|recommend|suggest|should run|run)\s*:?\s*([a-z0-9_-]+)',
        r'(?:tool|command)\s+([a-z0-9_-]+)\s+(?:on|for|to)',
    ]
    for pattern in tool_patterns:
        match = re.search(pattern, clean_response, re.IGNORECASE)
        if match:
            tool_name = match.group(1).lower()
            # Validate it's a real tool name (basic check)
            if tool_name and len(tool_name) > 2 and not tool_name in ['the', 'and', 'for', 'with']:
                data["next_tool"] = tool_name
                break
    
    # Extract next_target from natural language
    domain_pattern = r'(?:target|domain|host)\s*:?\s*([a-z0-9.-]+\.[a-z]{2,})'
    domain_match = re.search(domain_pattern, clean_response, re.IGNORECASE)
    if domain_match:
        data["next_target"] = domain_match.group(1)
    
    return data if data else None


def _validate_and_fix_summary(summary: str, successful_tools: List[str]) -> str:
    """Validate summary doesn't mention tools not in results, fix if needed."""
    if not summary:
        return summary
    
    actual_tools = [t.lower() for t in successful_tools]
    tool_names = {
        "securitytrails", "securitytrail", "shodan", "amass", "subfinder",
        "nmap", "masscan", "httpx", "whatweb", "whois", "dig", "nuclei",
        "nikto", "sqlmap", "gobuster", "dirsearch", "feroxbuster", "ffuf"
    }
    
    summary_lower = summary.lower()
    mentioned_tools = [tool for tool in tool_names if tool in summary_lower]
    hallucinated_tools = [tool for tool in mentioned_tools if tool not in actual_tools]
    
    if hallucinated_tools:
        logger.warning(f"⚠️ LLM hallucination detected: Summary mentions tools not in results: {hallucinated_tools}")
        for hallucinated in hallucinated_tools:
            if hallucinated == "securitytrails" and "amass" in actual_tools:
                summary = summary.replace("SecurityTrails", "Amass").replace("securitytrails", "amass")
            elif hallucinated == "securitytrails" and "subfinder" in actual_tools:
                summary = summary.replace("SecurityTrails", "Subfinder").replace("securitytrails", "subfinder")
            else:
                summary = re.sub(rf'\b{re.escape(hallucinated)}\b[^.]*\.?', '', summary, flags=re.IGNORECASE)
        summary = re.sub(r'\s+', ' ', summary).strip()
    
    return summary


class AnalyzerTool(AgentTool):
    """Tool for analyzing execution results and suggesting next steps."""
    
    def execute(self, results: Dict[str, Any] = None, context: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """
        LLM analyzes execution results and provides pure streaming response.
        
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
        
        # Extension hook
        try:
            from app.extensions import call_extensions_sync
            call_extensions_sync("analyzer_start", agent=None, state=self.state)
        except Exception:
            pass
        
        llm = OllamaClient(model="analyzer")
        
        # Check if any tools succeeded
        successful_tools = [t for t, d in results.items() if d.get("success")]
        failed_tools = [t for t, d in results.items() if not d.get("success")]
        
        if not successful_tools:
            return _handle_all_tools_failed(results, context)
        
        # Format results for LLM
        results_str = _format_results_for_llm(results)
        logger.info(f"Analyzing results from: {', '.join(successful_tools)}")
        
        # Add agent analysis if available
        try:
            from app.agent.orchestration import get_coordinator
            agent_name = context.get("current_agent", "base")
            agent = get_coordinator().get_agent(agent_name)
            if agent:
                agent_analysis = agent.analyze_results(results, context)
                if agent_analysis:
                    results_str += f"\n\nAGENCY ANALYSIS ({agent.AGENT_NAME}):\n{agent_analysis}\n"
                    print(f"  🧠 Included insights from {agent.AGENT_NAME} agent")
        except Exception as e:
            logger.error(f"Agent analysis failed: {e}")
        
        # Get CVE context
        cve_context = _get_cve_context(results_str, context)
        
        # Update tools_run in context
        tools_run = context.get("tools_run", [])
        tools_run.extend(successful_tools)
        context["tools_run"] = list(set(tools_run))
        
        # Build prompt
        from app.agent.prompt_loader import format_prompt
        
        tools_run_str = ", ".join(context.get('tools_run', [])) if context.get('tools_run') else "none"
        actual_tools_list = ", ".join(successful_tools) if successful_tools else "none"
        
        prompt = format_prompt("analyzer",
            results_str=results_str,
            cve_context=cve_context,
            domain=context.get('last_domain', 'unknown'),
            subdomain_count=context.get('subdomain_count', 0),
            has_ports=context.get('has_ports', False),
            detected_tech=context.get('detected_tech', []),
            tools_run=tools_run_str,
            actual_tools_executed=actual_tools_list,
            security_tech_context=_get_security_tech_context(context)
        )
        
        # Generate LLM response with streaming
        # Pure LLM streaming - let the model speak naturally
        response = llm.generate(prompt, timeout=90, stream=True, show_thinking=True, show_content=True)
        
        # Try to extract structured data for context updates
        data = _extract_json_from_response(response)
        
        if data:
            # Validate and fix summary
            summary = data.get("summary", "")
            summary = _validate_and_fix_summary(summary, successful_tools)
            
            # Extract key fields
            next_tool = data.get("next_tool") or (data.get("next_tools", [None])[0] if data.get("next_tools") else None)
            next_target_raw = data.get("next_target", "")
            next_reason = data.get("next_reason", "")
            
            # Validate next_tool not already run
            if next_tool and next_tool in context.get("tools_run", []):
                logger.warning(f"LLM suggested '{next_tool}' but it's already in tools_run. Rejecting.")
                next_tool = None
                next_reason = None
            
            # Normalize next_target
            domain = context.get("last_domain") or context.get("domain", "")
            if not next_target_raw or next_target_raw.lower() in ["none", "null", "n/a", ""]:
                next_target = domain if domain else ""
            else:
                next_target = next_target_raw if "." in next_target_raw and len(next_target_raw) > 3 else domain
            
            # Store in context for future use
            if next_tool:
                context["analyzer_next_tool"] = next_tool
                context["analyzer_next_target"] = next_target if next_target else domain
                context["analyzer_next_reason"] = next_reason
        
        # Return pure LLM response - already streamed to user
        # Store minimal structured data in context for system use
        return {
            "response": response,  # Pure LLM response already displayed via streaming
            "context": context,
            "next_action": "respond",
            "response_streamed": True
        }
    
    def execute_small_analyze(self, execution_results: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Small analyze for a single iteration in AutoChain mode."""
        if context is None:
            context = {}
        
        llm = OllamaClient(model="analyzer")
        
        results_str = ""
        successful_tools = []
        failed_tools = []
        
        for tool_name, result in execution_results.items():
            if isinstance(result, dict):
                if result.get("success"):
                    successful_tools.append(tool_name)
                    output = result.get("output", "")[:500]
                    results_str += f"\n{tool_name}:\n{output}\n"
                else:
                    failed_tools.append(tool_name)
                    error = result.get("error", "Unknown error")[:200]
                    results_str += f"\n{tool_name} (FAILED): {error}\n"
            else:
                results_str += f"\n{tool_name}: {str(result)[:500]}\n"
        
        prompt = f"""Summarize the results of this security testing iteration in 1-2 sentences. Focus on key findings.

Tools executed: {', '.join(successful_tools) if successful_tools else 'None'}
Failed tools: {', '.join(failed_tools) if failed_tools else 'None'}

Results:
{results_str}

Provide a brief summary (1-2 sentences) of what was found in this iteration."""
        
        try:
            summary = llm.generate(prompt, timeout=30, stream=False, show_content=False).strip()
            return {
                "summary": summary,
                "key_findings": [],
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
        """Comprehensive analyze after 5 iterations in AutoChain mode."""
        if context is None:
            context = {}
        
        llm = OllamaClient(model="analyzer")
        
        all_results_str = ""
        all_successful_tools = []
        
        for i, iteration_result in enumerate(autochain_results, 1):
            iteration_summary = iteration_result.get("summary", "No summary")
            execution_results = iteration_result.get("execution_results", {})
            successful = iteration_result.get("successful_tools", [])
            
            all_successful_tools.extend(successful)
            all_results_str += f"\n--- Iteration {i} ---\n"
            all_results_str += f"Summary: {iteration_summary}\n"
            all_results_str += f"Tools: {', '.join(successful) if successful else 'None'}\n"
            
            for tool_name, result in execution_results.items():
                if isinstance(result, dict) and result.get("success"):
                    output = result.get("output", "")[:1000]
                    all_results_str += f"\n{tool_name} output:\n{output[:500]}...\n"
        
        # Use analyzer prompt for comprehensive analysis
        from app.agent.prompt_loader import format_prompt
        
        security_tech_context = _get_security_tech_context(context)
        cve_context = ""
        last_cves = context.get("last_cves", [])
        if last_cves:
            cve_context = "\n\n⚠️ POTENTIAL CVEs:\n"
            for cve in last_cves[:5]:
                cve_id = cve.get("cve_id", "Unknown")
                severity = cve.get("severity", "Unknown")
                products = cve.get("products", "Unknown")
                cve_context += f"- {cve_id} ({severity}) {products}\n"
        
        analysis_prompt = format_prompt(
            "analyzer",
            results_str=all_results_str,
            domain=context.get("target_domain") or context.get("last_domain", "unknown"),
            subdomain_count=context.get('subdomain_count', 0),
            has_ports=context.get('has_ports', False),
            detected_tech=context.get("detected_tech", []),
            tools_run=", ".join(set(all_successful_tools)),
            actual_tools_executed=", ".join(set(all_successful_tools)),
            security_tech_context=security_tech_context,
            cve_context=cve_context
        )
        
        response = llm.generate(analysis_prompt, timeout=90, stream=True, show_thinking=True, show_content=True)
        
        return {
            "response": response,
            "context": context,
            "next_action": "respond",
            "response_streamed": True
        }
