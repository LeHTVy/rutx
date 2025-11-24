"""
SNODE AI - Security Node Agent
3-Phase Iteration System for Penetration Testing

Phase 1: Tool Selection (BlackBox) - LLM chooses appropriate tools
Phase 2: Execution & Storage - Run tools and save results to database
Phase 3: Analysis & Report - Analyze vulnerabilities and generate report
"""

import json
import requests
import sys
import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    OLLAMA_ENDPOINT,
    MODEL_NAME,
    TIMEOUT_OLLAMA,
    ENABLE_DATABASE
)
from tools import ALL_TOOLS, execute_tool, get_all_tool_names
from database import save_scan_result, get_llm_context, query_database
from prompts import get_phase1_prompt, get_phase3_prompt, get_phase4_prompt


class IterationPhase:
    """Enumeration for iteration phases"""
    TOOL_SELECTION = 1
    EXECUTION = 2
    ANALYSIS = 3
    COMBINE_ANALYSIS = 4  # For subdomain scans with multiple tools


class SNODEAgent:
    """
    SNODE AI Agent - 3-Phase Security Scanning System
    """

    def __init__(self, model: str = None):
        self.model = model or MODEL_NAME
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.conversation_history = []
        self.scan_results = []
        self.current_phase = IterationPhase.TOOL_SELECTION
        self.is_subdomain_scan = False  # Track if this is a subdomain enumeration scan

    def _call_ollama(
        self,
        messages: List[Dict],
        tools: List[Dict] = None,
        timeout: int = None,
        retry_without_tools: bool = True
    ) -> Dict[str, Any]:
        """Call Ollama API with retry logic"""
        if timeout is None:
            timeout = TIMEOUT_OLLAMA

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False
        }

        if tools:
            payload["tools"] = tools

        try:
            response = requests.post(
                OLLAMA_ENDPOINT,
                json=payload,
                timeout=timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            # If 500 error with tools, retry without tools (model may not support function calling)
            if response.status_code == 500 and tools and retry_without_tools:
                print(f"  ⚠️  Function calling failed, retrying with text-based selection...")
                return self._call_ollama_text_fallback(messages, tools, timeout)
            return {"error": str(e)}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def _call_ollama_text_fallback(
        self,
        messages: List[Dict],
        tools: List[Dict],
        timeout: int
    ) -> Dict[str, Any]:
        """Fallback: Ask LLM to select tools via text instead of function calling"""
        # Build tool list as text
        tool_list = "\n".join([
            f"- {t['function']['name']}: {t['function'].get('description', '')[:100]}"
            for t in tools
        ])

        # Modify system prompt to request JSON tool selection
        fallback_prompt = f"""You are a security scanning assistant. Based on the user's request, select the appropriate tool(s).

AVAILABLE TOOLS:
{tool_list}

RESPOND WITH JSON ONLY in this exact format:
{{"tool_calls": [{{"function": {{"name": "tool_name", "arguments": {{"param": "value"}}}}}}]}}

For port scanning, use: nmap_quick_scan, nmap_service_detection, or nmap_aggressive_scan
For vulnerability scanning, use: nmap_vuln_scan
For IP lookup, use: shodan_lookup or shodan_host
For subdomain enumeration, use: amass_enum or bbot_subdomain_enum

Select the most appropriate tool for the user's request."""

        fallback_messages = [
            {"role": "system", "content": fallback_prompt},
            messages[-1]  # User message
        ]

        payload = {
            "model": self.model,
            "messages": fallback_messages,
            "stream": False
        }

        try:
            response = requests.post(
                OLLAMA_ENDPOINT,
                json=payload,
                timeout=timeout
            )
            response.raise_for_status()
            result = response.json()

            # Parse the text response as JSON
            content = result.get("message", {}).get("content", "")

            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{.*"tool_calls".*\}', content, re.DOTALL)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                    # Convert to standard format
                    result["message"]["tool_calls"] = parsed.get("tool_calls", [])
                except json.JSONDecodeError:
                    pass

            return result
        except Exception as e:
            return {"error": f"Fallback failed: {str(e)}"}

    def _get_tool_list_string(self) -> str:
        """Get formatted list of available tools"""
        lines = []
        for tool in ALL_TOOLS:
            name = tool['function']['name']
            desc = tool['function'].get('description', '')[:80]
            lines.append(f"  - {name}: {desc}")
        return "\n".join(lines)

    def _detect_subdomain_scan(self, user_prompt: str) -> bool:
        """Detect if user is requesting subdomain enumeration"""
        subdomain_keywords = [
            'subdomain', 'subdomains', 'sub-domain', 'sub-domains',
            'enumerate domain', 'domain enumeration', 'find subdomains',
            'discover subdomains', 'subdomain discovery', 'recon domain'
        ]
        prompt_lower = user_prompt.lower()
        return any(keyword in prompt_lower for keyword in subdomain_keywords)

    def _detect_port_scan(self, user_prompt: str) -> bool:
        """Detect if user is requesting port scanning"""
        port_keywords = [
            'scan port', 'port scan', 'scan ports', 'open ports',
            'check ports', 'port scanning', 'nmap', 'service detection'
        ]
        prompt_lower = user_prompt.lower()
        return any(keyword in prompt_lower for keyword in port_keywords)

    def _detect_vuln_scan(self, user_prompt: str) -> bool:
        """Detect if user is requesting vulnerability scanning"""
        vuln_keywords = [
            'vuln', 'vulnerability', 'vulnerabilities', 'cve',
            'exploit', 'security scan', 'check vuln', 'find vuln'
        ]
        prompt_lower = user_prompt.lower()
        return any(keyword in prompt_lower for keyword in vuln_keywords)

    def _detect_shodan_lookup(self, user_prompt: str) -> bool:
        """Detect if user is requesting Shodan lookup"""
        shodan_keywords = [
            'shodan', 'threat intel', 'ip lookup', 'ip info',
            'ip intelligence', 'host info', 'what is running on',
            'osint', 'intelligence', 'enrich'
        ]
        prompt_lower = user_prompt.lower()
        return any(keyword in prompt_lower for keyword in shodan_keywords)

    def _detect_osint_enrichment(self, user_prompt: str) -> bool:
        """Detect if user wants OSINT enrichment with their scan"""
        osint_keywords = [
            'osint', 'enrich', 'threat intel', 'intelligence',
            'detailed', 'comprehensive', 'full recon', 'full scan'
        ]
        prompt_lower = user_prompt.lower()
        return any(keyword in prompt_lower for keyword in osint_keywords)

    def _extract_ip_from_prompt(self, user_prompt: str) -> Optional[str]:
        """Extract IP address from user prompt"""
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, user_prompt)
        return matches[0] if matches else None

    def _extract_domain_from_prompt(self, user_prompt: str) -> Optional[str]:
        """Extract domain from user prompt"""
        import re
        # Match common domain patterns
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        matches = re.findall(domain_pattern, user_prompt)
        return matches[0] if matches else None

    def _extract_target_from_prompt(self, user_prompt: str) -> Optional[str]:
        """Extract any target (IP or domain) from user prompt"""
        ip = self._extract_ip_from_prompt(user_prompt)
        if ip:
            return ip
        return self._extract_domain_from_prompt(user_prompt)

    def _get_subdomain_tools(self, domain: str) -> List[Dict]:
        """Get both amass and bbot tools for subdomain enumeration"""
        return [
            {
                "name": "amass_enum",
                "arguments": {"domain": domain, "passive": True, "timeout": 1800}
            },
            {
                "name": "bbot_subdomain_enum",
                "arguments": {"target": domain, "timeout": 1800}
            }
        ]

    def _get_port_scan_tools(self, target: str, with_osint: bool = False) -> List[Dict]:
        """Get nmap tools for port scanning, optionally with OSINT enrichment"""
        tools = [
            {
                "name": "nmap_quick_scan",
                "arguments": {"target": target}
            }
        ]
        # Add Shodan lookup for OSINT enrichment (only for IP addresses)
        if with_osint and self._is_ip_address(target):
            tools.append({
                "name": "shodan_lookup",
                "arguments": {"ip": target}
            })
        return tools

    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        import re
        ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, target))

    def _parse_nmap_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse raw nmap output into structured data for LLM analysis"""
        import re

        result = {
            "success": True,
            "output": raw_output,
            "hosts": [],
            "open_ports": [],
            "services": [],
            "os_detection": None,
            "vulnerabilities": []
        }

        lines = raw_output.splitlines()
        current_host = None

        for line in lines:
            # Host detection
            host_match = re.search(r'Nmap scan report for ([\w\.\-]+)(?: \((\d+\.\d+\.\d+\.\d+)\))?', line)
            if host_match:
                hostname = host_match.group(1)
                ip = host_match.group(2) or hostname
                current_host = {"hostname": hostname, "ip": ip}
                result["hosts"].append(current_host)

            # Open port detection
            port_match = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$', line)
            if port_match:
                port_info = {
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4).strip()
                }
                result["open_ports"].append(port_info)
                if port_info["state"] == "open":
                    result["services"].append(f"{port_info['port']}/{port_info['protocol']} - {port_info['service']}")

            # OS detection
            if 'OS details:' in line or 'Running:' in line:
                result["os_detection"] = line.strip()

            # Vulnerability detection (from --script vuln)
            if 'VULNERABLE' in line or 'CVE-' in line:
                result["vulnerabilities"].append(line.strip())

        # Build summary
        open_count = len([p for p in result["open_ports"] if p["state"] == "open"])
        result["open_ports_count"] = open_count
        result["hosts_discovered"] = len(result["hosts"])
        result["summary"] = f"Scan completed: {len(result['hosts'])} host(s), {open_count} open port(s)"

        if result["vulnerabilities"]:
            result["summary"] += f", {len(result['vulnerabilities'])} vulnerability indicator(s)"

        return result

    def _get_vuln_scan_tools(self, target: str, with_osint: bool = False) -> List[Dict]:
        """Get tools for vulnerability scanning, optionally with OSINT enrichment"""
        tools = [
            {
                "name": "nmap_vuln_scan",
                "arguments": {"target": target}
            }
        ]
        # Add Shodan for CVE enrichment if target is an IP
        if with_osint and self._is_ip_address(target):
            tools.append({
                "name": "shodan_lookup",
                "arguments": {"ip": target}
            })
        return tools

    def _get_shodan_tools(self, target: str) -> List[Dict]:
        """Get Shodan tools for IP lookup"""
        return [
            {
                "name": "shodan_lookup",
                "arguments": {"ip": target}
            }
        ]

    def phase_1_tool_selection(self, user_prompt: str) -> Tuple[List[Dict], str]:
        """
        Phase 1: BlackBox Tool Selection
        Uses keyword detection first, then falls back to LLM

        Returns:
            Tuple of (selected_tools, reasoning)
        """
        print("\n" + "="*60)
        print("📦 PHASE 1: TOOL SELECTION")
        print("="*60)

        # 1. Check for subdomain enumeration request
        if self._detect_subdomain_scan(user_prompt):
            domain = self._extract_domain_from_prompt(user_prompt)
            if domain:
                self.is_subdomain_scan = True
                selected_tools = self._get_subdomain_tools(domain)
                reasoning = f"Subdomain enumeration detected. Using both Amass and BBOT for comprehensive coverage on {domain}."
                print(f"  🔍 Subdomain scan detected for: {domain}")
                print(f"  ✓ Selected: amass_enum (passive mode)")
                print(f"  ✓ Selected: bbot_subdomain_enum")
                return selected_tools, reasoning

        # 2. Check for vulnerability scan request (with optional OSINT enrichment)
        if self._detect_vuln_scan(user_prompt):
            target = self._extract_target_from_prompt(user_prompt)
            if target:
                with_osint = self._detect_osint_enrichment(user_prompt)
                selected_tools = self._get_vuln_scan_tools(target, with_osint=with_osint)
                reasoning = f"Vulnerability scan detected for {target}."
                print(f"  🔍 Vulnerability scan detected for: {target}")
                print(f"  ✓ Selected: nmap_vuln_scan")
                if with_osint and self._is_ip_address(target):
                    print(f"  ✓ Selected: shodan_lookup (CVE enrichment)")
                    reasoning += " With Shodan CVE enrichment."
                return selected_tools, reasoning

        # 3. Check for port scan request (with optional OSINT enrichment)
        if self._detect_port_scan(user_prompt):
            target = self._extract_target_from_prompt(user_prompt)
            if target:
                with_osint = self._detect_osint_enrichment(user_prompt)
                selected_tools = self._get_port_scan_tools(target, with_osint=with_osint)
                reasoning = f"Port scan detected for {target}."
                print(f"  🔍 Port scan detected for: {target}")
                print(f"  ✓ Selected: nmap_quick_scan")
                if with_osint and self._is_ip_address(target):
                    print(f"  ✓ Selected: shodan_lookup (OSINT enrichment)")
                    reasoning += " With Shodan OSINT enrichment."
                return selected_tools, reasoning

        # 4. Check for Shodan lookup request
        if self._detect_shodan_lookup(user_prompt):
            target = self._extract_ip_from_prompt(user_prompt)
            if target:
                selected_tools = self._get_shodan_tools(target)
                reasoning = f"Shodan lookup detected for {target}."
                print(f"  🔍 Shodan lookup detected for: {target}")
                print(f"  ✓ Selected: shodan_lookup")
                return selected_tools, reasoning

        # 5. Fallback to LLM-based tool selection
        print("  📡 Using LLM for tool selection...")
        system_prompt = get_phase1_prompt(self._get_tool_list_string())

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        response = self._call_ollama(messages, tools=ALL_TOOLS)

        if "error" in response:
            return [], f"Error: {response['error']}"

        message = response.get("message", {})
        tool_calls = message.get("tool_calls", [])
        reasoning = message.get("content", "")

        selected_tools = []
        for call in tool_calls:
            tool_info = {
                "name": call.get("function", {}).get("name"),
                "arguments": call.get("function", {}).get("arguments", {})
            }
            selected_tools.append(tool_info)
            print(f"  ✓ Selected: {tool_info['name']}")

        if not selected_tools and reasoning:
            print(f"  ℹ️  {reasoning[:100]}...")

        return selected_tools, reasoning

    def phase_2_execution(self, selected_tools: List[Dict]) -> List[Dict]:
        """
        Phase 2: Execute Tools & Store Results
        Run each selected tool and save to database

        Returns:
            List of execution results
        """
        print("\n" + "="*60)
        print("⚙️  PHASE 2: EXECUTION & STORAGE")
        print("="*60)

        results = []

        for i, tool in enumerate(selected_tools, 1):
            tool_name = tool["name"]
            tool_args = tool["arguments"]

            print(f"\n[{i}/{len(selected_tools)}] Running: {tool_name}")
            print(f"    Args: {json.dumps(tool_args, indent=2)[:100]}...")

            # Execute the tool
            try:
                result = execute_tool(tool_name, tool_args)

                if isinstance(result, str):
                    try:
                        result = json.loads(result)
                    except:
                        # Handle raw string output from nmap tools
                        if result.startswith("Error:"):
                            result = {"success": False, "error": result, "output": result}
                        else:
                            # Parse nmap output for structured data
                            result = self._parse_nmap_output(result)

                # Save to database if enabled
                if ENABLE_DATABASE and result.get("success"):
                    output_file = (
                        result.get("output_xml") or
                        result.get("output_json") or
                        result.get("json_output_file")
                    )

                    if output_file:
                        target = tool_args.get("target") or tool_args.get("domain") or tool_args.get("ip", "unknown")
                        db_result = save_scan_result(
                            tool=tool_name.split("_")[0],  # Extract tool name
                            target=target,
                            output_file=output_file,
                            scan_profile=tool_name,
                            elapsed_seconds=result.get("elapsed_seconds", 0),
                            session_id=self.session_id
                        )
                        result["database"] = db_result
                        print(f"    💾 Saved to database: {db_result.get('scan_id', 'N/A')}")

                results.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": result
                })

                if result.get("success"):
                    print(f"    ✅ Success")
                else:
                    print(f"    ⚠️  {result.get('error', 'Unknown error')}")

            except Exception as e:
                print(f"    ❌ Error: {e}")
                results.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": {"error": str(e)}
                })

        self.scan_results = results
        return results

    def phase_3_analysis(self, scan_results: List[Dict]) -> str:
        """
        Phase 3: Analyze & Generate Report
        LLM analyzes results and generates vulnerability report

        Returns:
            Analysis report string
        """
        print("\n" + "="*60)
        print("📊 PHASE 3: ANALYSIS & REPORT")
        print("="*60)

        # Prepare scan results for LLM
        results_summary = []
        for r in scan_results:
            summary = {
                "tool": r["tool"],
                "success": r["result"].get("success", False),
                "summary": r["result"].get("summary", ""),
                "findings": r["result"].get("findings_count", 0),
                "hosts": r["result"].get("hosts_discovered", 0),
                "ports": r["result"].get("open_ports_count", 0),
                "subdomains": r["result"].get("subdomains_found", 0)
            }

            # Include port details if available (from nmap parsing)
            if r["result"].get("open_ports"):
                summary["ports_detail"] = r["result"]["open_ports"][:15]

            # Include services detected
            if r["result"].get("services"):
                summary["services"] = r["result"]["services"][:15]

            # Include vulnerabilities if found
            if r["result"].get("vulnerabilities"):
                summary["vulnerabilities"] = r["result"]["vulnerabilities"][:10]

            # Include subdomains if available
            if r["result"].get("subdomains"):
                summary["subdomains_list"] = r["result"]["subdomains"][:20]

            # Include Shodan data if available (OSINT enrichment)
            if "shodan" in r["tool"].lower() and r["result"].get("data"):
                shodan_data = r["result"]["data"]
                summary["shodan_intel"] = {
                    "organization": shodan_data.get("organization"),
                    "isp": shodan_data.get("isp"),
                    "country": shodan_data.get("country"),
                    "ports": shodan_data.get("ports", [])[:20],
                    "vulns": shodan_data.get("vulns", [])[:10],
                    "threat_level": shodan_data.get("threat_level"),
                    "threat_indicators": shodan_data.get("threat_indicators", [])
                }

            results_summary.append(summary)

        # Get database context if available
        db_context = {}
        if ENABLE_DATABASE:
            try:
                db_context = query_database("stats")
            except:
                db_context = {"note": "Database query unavailable"}

        system_prompt = get_phase3_prompt(
            json.dumps(results_summary, indent=2),
            json.dumps(db_context, indent=2)
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Analyze the scan results and provide a comprehensive security report."}
        ]

        print("\n🔍 Analyzing results...")

        # Use config timeout (TIMEOUT_OLLAMA) for LLM analysis
        response = self._call_ollama(messages, timeout=TIMEOUT_OLLAMA)

        if "error" in response:
            return f"Analysis Error: {response['error']}"

        analysis = response.get("message", {}).get("content", "No analysis generated")

        return analysis

    def phase_4_combine_analysis(self, scan_results: List[Dict]) -> str:
        """
        Phase 4: Combine & Analyze Multi-Tool Results
        Used for subdomain scans with Amass + BBOT

        Returns:
            Combined analysis report string
        """
        print("\n" + "="*60)
        print("🔄 PHASE 4: COMBINING RESULTS & ANALYSIS")
        print("="*60)

        # Collect all subdomains from both tools
        combined_data = {
            "tools_used": [],
            "amass_subdomains": [],
            "bbot_subdomains": [],
            "all_subdomains": set()
        }

        for r in scan_results:
            tool_name = r["tool"]
            result = r["result"]

            if result.get("success"):
                combined_data["tools_used"].append(tool_name)
                subdomains = result.get("subdomains", [])

                if "amass" in tool_name.lower():
                    combined_data["amass_subdomains"] = subdomains
                    combined_data["all_subdomains"].update(subdomains)
                    print(f"  📥 Amass found: {len(subdomains)} subdomains")
                elif "bbot" in tool_name.lower():
                    combined_data["bbot_subdomains"] = subdomains
                    combined_data["all_subdomains"].update(subdomains)
                    print(f"  📥 BBOT found: {len(subdomains)} subdomains")

        # Calculate overlap
        amass_set = set(combined_data["amass_subdomains"])
        bbot_set = set(combined_data["bbot_subdomains"])
        overlap = amass_set.intersection(bbot_set)

        # Prepare summary for LLM (limit data to avoid 500 errors)
        all_sorted = sorted(list(combined_data["all_subdomains"]))
        combined_summary = {
            "total_unique": len(combined_data["all_subdomains"]),
            "amass_count": len(amass_set),
            "bbot_count": len(bbot_set),
            "overlap_count": len(overlap),
            "unique_to_amass": len(amass_set - bbot_set),
            "unique_to_bbot": len(bbot_set - amass_set),
            "sample_subdomains": all_sorted[:50],  # Reduced limit for LLM
            "high_value_keywords": ["api", "admin", "dev", "staging", "test", "internal", "vpn", "mail"]
        }

        # Find high-value targets
        high_value = [s for s in all_sorted if any(kw in s.lower() for kw in combined_summary["high_value_keywords"])]
        combined_summary["high_value_targets"] = high_value[:20]

        print(f"\n  📊 Total unique subdomains: {combined_summary['total_unique']}")
        print(f"  📊 Overlap (found by both): {combined_summary['overlap_count']}")
        print(f"  📊 High-value targets found: {len(high_value)}")

        system_prompt = get_phase4_prompt(
            json.dumps(combined_summary, indent=2),
            len(combined_data["tools_used"])
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Analyze the subdomain discovery results."}
        ]

        print("\n🔍 Analyzing combined results...")

        response = self._call_ollama(messages, timeout=TIMEOUT_OLLAMA, retry_without_tools=False)

        if "error" in response:
            # Fallback: Generate a basic report without LLM
            print("  ⚠️  LLM analysis failed, generating basic report...")
            return self._generate_basic_subdomain_report(combined_summary, all_sorted, high_value)

        analysis = response.get("message", {}).get("content", "No analysis generated")

        return analysis

    def _generate_basic_subdomain_report(
        self,
        summary: Dict,
        all_subdomains: List[str],
        high_value: List[str]
    ) -> str:
        """Generate a basic subdomain report when LLM fails"""
        # Categorize subdomains
        categories = {
            "api": [], "admin": [], "dev": [], "staging": [],
            "mail": [], "vpn": [], "www": [], "other": []
        }

        for sub in all_subdomains:
            sub_lower = sub.lower()
            categorized = False
            for cat in ["api", "admin", "dev", "staging", "mail", "vpn", "www"]:
                if cat in sub_lower:
                    categories[cat].append(sub)
                    categorized = True
                    break
            if not categorized:
                categories["other"].append(sub)

        report = f"""## SUBDOMAIN DISCOVERY SUMMARY

- **Total unique subdomains:** {summary['total_unique']}
- **Found by Amass:** {summary['amass_count']}
- **Found by BBOT:** {summary['bbot_count']}
- **Overlap (found by both):** {summary['overlap_count']}
- **Unique to Amass:** {summary['unique_to_amass']}
- **Unique to BBOT:** {summary['unique_to_bbot']}

## HIGH-VALUE TARGETS ({len(high_value)} found)

{chr(10).join(['- ' + s for s in high_value[:15]]) if high_value else 'None identified'}

## CATEGORIZED SUBDOMAINS

### API Endpoints ({len(categories['api'])})
{chr(10).join(['- ' + s for s in categories['api'][:10]]) if categories['api'] else 'None found'}

### Admin Panels ({len(categories['admin'])})
{chr(10).join(['- ' + s for s in categories['admin'][:10]]) if categories['admin'] else 'None found'}

### Development/Staging ({len(categories['dev']) + len(categories['staging'])})
{chr(10).join(['- ' + s for s in (categories['dev'] + categories['staging'])[:10]]) if (categories['dev'] or categories['staging']) else 'None found'}

### Mail Services ({len(categories['mail'])})
{chr(10).join(['- ' + s for s in categories['mail'][:10]]) if categories['mail'] else 'None found'}

### VPN/Internal ({len(categories['vpn'])})
{chr(10).join(['- ' + s for s in categories['vpn'][:10]]) if categories['vpn'] else 'None found'}

## RECOMMENDATIONS

1. **Priority targets for port scanning:** {', '.join(high_value[:5]) if high_value else 'Review all subdomains manually'}
2. **Suggested next steps:** Run nmap_service_detection on high-value targets
3. **Security concern:** Check for exposed admin panels and development environments

---
*Note: This is a basic report. LLM analysis was unavailable.*
"""
        return report

    def run(self, user_prompt: str) -> Dict[str, Any]:
        """
        Execute full scan cycle (3-phase or 4-phase for subdomain scans)

        Args:
            user_prompt: User's natural language request

        Returns:
            Complete results including tools, execution, and analysis
        """
        start_time = datetime.now()

        # Phase 1: Tool Selection
        self.current_phase = IterationPhase.TOOL_SELECTION
        selected_tools, reasoning = self.phase_1_tool_selection(user_prompt)

        if not selected_tools:
            return {
                "success": False,
                "phase": 1,
                "error": "No tools selected",
                "reasoning": reasoning
            }

        # Phase 2: Execution
        self.current_phase = IterationPhase.EXECUTION
        execution_results = self.phase_2_execution(selected_tools)

        # Phase 3 or Phase 4 based on scan type
        if self.is_subdomain_scan:
            # Phase 4: Combined analysis for subdomain scans (Amass + BBOT)
            self.current_phase = IterationPhase.COMBINE_ANALYSIS
            analysis_report = self.phase_4_combine_analysis(execution_results)
            phase_key = "phase_4_combined_analysis"
        else:
            # Phase 3: Standard analysis
            self.current_phase = IterationPhase.ANALYSIS
            analysis_report = self.phase_3_analysis(execution_results)
            phase_key = "phase_3_analysis"

        elapsed = (datetime.now() - start_time).total_seconds()

        result = {
            "success": True,
            "session_id": self.session_id,
            "user_prompt": user_prompt,
            "elapsed_seconds": round(elapsed, 2),
            "is_subdomain_scan": self.is_subdomain_scan,
            "phases": {
                "phase_1_tools": selected_tools,
                "phase_2_results": [
                    {
                        "tool": r["tool"],
                        "success": r["result"].get("success", False),
                        "summary": r["result"].get("summary", "")
                    }
                    for r in execution_results
                ],
                phase_key: analysis_report
            }
        }

        return result


def _get_analysis_from_result(result: Dict) -> str:
    """Extract analysis report from result (handles both phase 3 and 4)"""
    phases = result.get("phases", {})
    return phases.get("phase_4_combined_analysis") or phases.get("phase_3_analysis", "No analysis available")


def main():
    """Simple command-line interface for testing"""
    agent = SNODEAgent()

    print("\n" + "="*60)
    print("  SNODE AI - Security Node Agent")
    print("  3/4-Phase Penetration Testing System")
    print("="*60)

    if len(sys.argv) > 1:
        # Command line mode
        prompt = " ".join(sys.argv[1:])
        result = agent.run(prompt)
        print("\n" + _get_analysis_from_result(result))
    else:
        # Interactive mode
        print("\nEnter your security objective (or 'quit' to exit):\n")

        while True:
            try:
                prompt = input("SNODE> ").strip()

                if prompt.lower() in ['quit', 'exit', 'q']:
                    print("\nGoodbye!")
                    break

                if not prompt:
                    continue

                result = agent.run(prompt)

                print("\n" + "="*60)
                print("📋 FINAL REPORT")
                print("="*60)
                print(_get_analysis_from_result(result))
                print("\n" + "="*60)
                scan_type = "Subdomain Scan (4-Phase)" if result.get("is_subdomain_scan") else "Standard Scan (3-Phase)"
                print(f"Session: {result['session_id']} | Type: {scan_type} | Time: {result['elapsed_seconds']}s")
                print("="*60 + "\n")

            except KeyboardInterrupt:
                print("\n\nInterrupted. Goodbye!")
                break
            except Exception as e:
                print(f"\nError: {e}")


if __name__ == "__main__":
    main()
