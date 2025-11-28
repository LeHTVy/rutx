"""
SNODE AI - Security Node Agent
4-Phase Iteration System for Penetration Testing

Phase 1: Tool Selection (LLM) - Intelligent tool selection based on user request
Phase 2: Execution & Persistence - Atomic: Tools -> Parse -> Save -> Enrich
Phase 3: Intelligence Analysis - LLM with enriched DB context
Phase 4: Report Generation - LLM formats for target audience
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
from database import (
    save_scan_result, get_llm_context, query_database,
    # Enhanced persistence imports
    ScanSessionManager, ToolResultPersister, LLMContextBuilder,
    persist_tool_results, build_and_cache_context, get_cached_context
)
from prompts import get_phase1_prompt, get_phase3_prompt, get_phase4_prompt

# SNODE Integration (Tracing + Guardrails)
try:
    from utils.tracing import trace_ollama_call
    TRACING_AVAILABLE = True
except ImportError:
    TRACING_AVAILABLE = False


class IterationPhase:
    """Enumeration for iteration phases"""
    TOOL_SELECTION = 1      # Phase 1: LLM selects tools
    EXECUTION = 2           # Phase 2: Execute & Persist (Atomic)
    ANALYSIS = 3            # Phase 3: LLM Intelligence Analysis
    REPORT_GENERATION = 4   # Phase 4: LLM Report Generation


class SNODEAgent:
    """
    SNODE AI Agent - 4-Phase Security Scanning System

    Flow:
        Phase 1: Tool Selection (LLM) -> selected_tools
        Phase 2: Execution & Persistence (Atomic: Tools -> Parse -> Save -> Enrich)
        Phase 3: Intelligence Analysis (LLM with enriched DB context)
        Phase 4: Report Generation (LLM formats for audience)
    """

    def __init__(self, model: str = None):
        self.model = model or MODEL_NAME
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.conversation_history = []
        self.max_history_size = 3  # Store last 3 scan results for context
        self.scan_results = []
        self.current_phase = IterationPhase.TOOL_SELECTION
        self.is_subdomain_scan = False  # Track if this is a subdomain enumeration scan
        self.high_value_targets = set()  # Track high-value subdomains for smart scan prioritization
        self.critical_targets = set()  # Track CRITICAL targets (api, admin, dev) for comprehensive scans
        
        # OSINT Intelligence (for crown jewel identification)
        self.osint_intelligence = None  # Stores OSINT analysis results
        self.crown_jewels = set()  # CROWN JEWEL targets identified from business intelligence
        self.business_context = ""  # Business context scraped from target website

        # Enhanced persistence (4-phase flow)
        self.db_session_id = None  # Database ScanSession ID
        self.session_manager = None
        self.persister = None
        self.context_builder = None

        if ENABLE_DATABASE:
            try:
                self.session_manager = ScanSessionManager()
            except Exception as e:
                print(f"  Warning: Could not initialize session manager: {e}")

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

        # === SNODE TRACING: Wrap Ollama call ===
        try:
            if TRACING_AVAILABLE:
                # Get prompt for tracing
                user_msg = next((m["content"] for m in messages if m["role"] == "user"), "")
                with trace_ollama_call(self.model, user_msg):
                    response = requests.post(
                        OLLAMA_ENDPOINT,
                        json=payload,
                        timeout=timeout
                    )
                    response.raise_for_status()
                    return response.json()
            else:
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

    def _detect_session_type(self, user_prompt: str) -> str:
        """Detect the type of scan session for categorization."""
        if self._detect_subdomain_scan(user_prompt):
            return "subdomain_enum"
        elif self._detect_vuln_scan(user_prompt):
            return "vuln_scan"
        elif self._detect_port_scan(user_prompt):
            return "port_scan"
        elif self._detect_shodan_lookup(user_prompt):
            return "osint"
        return "general"

    def _detect_subdomain_scan(self, user_prompt: str) -> bool:
        """Detect if user is requesting subdomain enumeration"""
        subdomain_keywords = [
            'subdomain', 'subdomains', 'sub-domain', 'sub-domains',
            'enumerate domain', 'domain enumeration', 'find subdomains',
            'discover subdomains', 'subdomain discovery', 'recon domain'
        ]
        prompt_lower = user_prompt.lower()
        
        # Avoid false positives if user is asking for port scan on subdomains
        if "port" in prompt_lower or "nmap" in prompt_lower:
            return False
            
        return any(keyword in prompt_lower for keyword in subdomain_keywords)

    def _detect_port_scan(self, user_prompt: str) -> bool:
        """Detect if user is requesting port scanning"""
        port_keywords = [
            'scan port', 'port scan', 'scan ports', 'open ports',
            'check ports', 'port scanning', 'nmap', 'service detection',
            # Natural language security assessment terms
            'security assessment', 'security scan', 'thorough', 'comprehensive',
            'check everything', 'full scan', 'complete scan', 'assess',
            'penetration test', 'pentest', 'security audit', 'scan target'
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

    def _detect_masscan_scan(self, user_prompt: str) -> bool:
        """Detect if user is requesting masscan scanning"""
        masscan_keywords = [
            'masscan', 'mass scan', 'fast scan', 'batch scan'
        ]
        prompt_lower = user_prompt.lower()
        return any(keyword in prompt_lower for keyword in masscan_keywords)

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

    def _extract_target_from_prompt(self, user_prompt: str) -> Optional[str]:
        """Extract target (IP or domain) from user prompt"""
        # Try IP first
        ip = self._extract_ip_from_prompt(user_prompt)
        if ip:
            return ip

        # Try domain
        domain = self._extract_domain_from_prompt(user_prompt)
        if domain:
            return domain

        return None

    def _extract_domain_from_prompt(self, user_prompt: str) -> Optional[str]:
        """Extract domain from user prompt"""
        import re
        # Match domain patterns (e.g., example.com, sub.example.com)
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        matches = re.findall(domain_pattern, user_prompt)
        return matches[0] if matches else None

    def _get_subdomain_tools(self, domain: str, user_prompt: str = "") -> List[Dict]:
        """Get subdomain enumeration tools with keyword detection"""
        prompt_lower = user_prompt.lower()

        # Detect Amass mode based on keywords
        amass_passive = True  # Default to passive
        amass_brute = False
        use_amass_intel = False
        
        if "intel" in prompt_lower or "intelligence" in prompt_lower or "whois" in prompt_lower:
            use_amass_intel = True
        elif "brute" in prompt_lower or "brute force" in prompt_lower or "bruteforce" in prompt_lower:
            amass_brute = True
            amass_passive = False
        elif "active" in prompt_lower and "subdomain" in prompt_lower:
            amass_passive = False
        # If "passive" is explicitly mentioned, keep passive=True (already default)
        
        # Detect BBOT mode based on keywords
        bbot_passive = False  # Default to active
        use_bbot_web = False
        use_bbot_quick = False
        
        if "web scan" in prompt_lower or "web recon" in prompt_lower:
            use_bbot_web = True
        elif "quick" in prompt_lower and "bbot" in prompt_lower:
            use_bbot_quick = True
        elif "passive" in prompt_lower and "bbot" in prompt_lower:
            bbot_passive = True
        
        tools = []
        
        # Add Amass tool
        if use_amass_intel:
            tools.append({
                "name": "amass_intel",
                "arguments": {"domain": domain, "whois": True, "timeout": 1800}
            })
        else:
            tools.append({
                "name": "amass_enum",
                "arguments": {
                    "domain": domain,
                    "passive": amass_passive,
                    "brute": amass_brute,
                    "timeout": 1800
                }
            })
        
        # Add BBOT tool
        if use_bbot_web:
            tools.append({
                "name": "bbot_web_scan",
                "arguments": {"target": domain, "timeout": 1800}
            })
        elif use_bbot_quick:
            tools.append({
                "name": "bbot_quick_scan",
                "arguments": {"target": domain, "timeout": 1800}
            })
        else:
            tools.append({
                "name": "bbot_subdomain_enum",
                "arguments": {"target": domain, "passive": bbot_passive, "timeout": 1800}
            })
        
        return tools

    def _get_port_scan_tools(self, target: str, user_prompt: str = "", with_osint: bool = False) -> List[Dict]:
        """Get nmap tools with automatic comprehensive scan for critical/high-value targets"""
        prompt_lower = user_prompt.lower()

        # Check if target is critical (api, admin, dev) - these get COMPREHENSIVE scans always
        is_critical = target.lower() in {t.lower() for t in self.critical_targets}

        # Check if target is high-value (staging, test, mail, vpn, internal)
        is_high_value = target.lower() in {t.lower() for t in self.high_value_targets}

        # CRITICAL TARGETS: Auto-upgrade to comprehensive scan + Shodan (always)
        # Unless user explicitly requests quick/fast scan
        if is_critical and "quick" not in prompt_lower and "fast" not in prompt_lower:
            nmap_tool = "nmap_comprehensive_scan"
            auto_shodan = True
            print(f"  🚨 CRITICAL target detected: {target} → Comprehensive scan + Shodan")
        # HIGH-VALUE TARGETS: Auto-upgrade to comprehensive scan
        elif is_high_value and "quick" not in prompt_lower and "fast" not in prompt_lower:
            nmap_tool = "nmap_comprehensive_scan"
            auto_shodan = True
            print(f"  🎯 High-value target detected: {target} → Comprehensive scan")
        else:
            # Detect nmap scan type based on keywords
            if self._is_ip_address(target):
                 # Single IP target - default to better scan (Top 1000 + Version)
                 nmap_tool = "nmap_service_detection"
            else:
                 nmap_tool = "nmap_quick_scan"  # Default for domains/unknowns
            
            auto_shodan = False  # Auto-enable Shodan for certain scan types
            
            if "comprehensive" in prompt_lower or "complete" in prompt_lower:
                nmap_tool = "nmap_comprehensive_scan"
                auto_shodan = True  # Comprehensive scans get Shodan automatically
            elif "aggressive" in prompt_lower:
                nmap_tool = "nmap_aggressive_scan"
                auto_shodan = True  # Aggressive scans get Shodan automatically
            elif "stealth" in prompt_lower or "stealthy" in prompt_lower or "syn" in prompt_lower:
                nmap_tool = "nmap_stealth_scan"
            elif "service" in prompt_lower or "version" in prompt_lower:
                nmap_tool = "nmap_service_detection"
            elif "full" in prompt_lower or "all ports" in prompt_lower or "all port" in prompt_lower:
                nmap_tool = "nmap_all_ports"
            elif "fast" in prompt_lower and "scan" in prompt_lower:
                nmap_tool = "nmap_fast_scan"
            elif "quick" in prompt_lower or "rapid" in prompt_lower:
                nmap_tool = "nmap_quick_scan"
        
        tools = [
            {
                "name": nmap_tool,
                "arguments": {"target": target}
            }
        ]
        
        # Auto-add Shodan for public IPs, critical targets, or if explicitly requested
        # Skip Shodan for internal/private IPs to save API quota
        should_add_shodan = (
            with_osint or  # Explicitly requested
            auto_shodan or  # Comprehensive/aggressive scans, critical/high-value targets
            (self._is_ip_address(target) and self._is_public_ip(target))  # Public IP auto-enrichment
        )

        # Add Shodan if target is a public IP (for direct lookups)
        if should_add_shodan and self._is_ip_address(target) and self._is_public_ip(target):
            tools.append({
                "name": "shodan_lookup",
                "arguments": {"ip": target}
            })
            if not with_osint and auto_shodan:
                print(f"  🔍 Auto-enabling Shodan for threat intelligence")

        # For critical domain targets (not IPs), add Shodan search by hostname
        # This provides threat intel even for domains that need to be resolved
        elif should_add_shodan and is_critical and not self._is_ip_address(target):
            tools.append({
                "name": "shodan_search",
                "arguments": {"query": f"hostname:{target}"}
            })
            print(f"  🔍 Auto-enabling Shodan search for critical domain: {target}")
        
        return tools

    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        import re
        ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, target))

    def _is_public_ip(self, ip: str) -> bool:
        """Check if an IP address is public (external) vs private (internal)"""
        if not self._is_ip_address(ip):
            return False
        
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Check if it's a private, loopback, link-local, or reserved IP
            return not (
                ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_link_local or 
                ip_obj.is_reserved or
                ip_obj.is_multicast
            )
        except:
            return False

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
        """Get tools for vulnerability scanning with automatic Shodan enrichment for public IPs"""
        tools = [
            {
                "name": "nmap_vuln_scan",
                "arguments": {"target": target}
            }
        ]
        
        # ALWAYS add Shodan for vulnerability scans on public IPs (CVE enrichment)
        # Vulnerability scans benefit most from threat intelligence data
        if self._is_ip_address(target) and self._is_public_ip(target):
            tools.append({
                "name": "shodan_lookup",
                "arguments": {"ip": target}
            })
            if not with_osint:
                print(f"  🔍 Auto-enabling Shodan for CVE enrichment")
        
        return tools

    def _get_masscan_tools(self, targets: str, ports: str = None, user_prompt: str = "") -> List[Dict]:
        """Get masscan tools for fast batch scanning"""
        prompt_lower = user_prompt.lower()
        
        # Determine tool based on keywords
        if 'web' in prompt_lower:
            tool_name = "masscan_web_scan"
        elif ports:
            tool_name = "masscan_port_scan"
        elif 'batch' in prompt_lower or 'quick' in prompt_lower:
            tool_name = "masscan_quick_scan"
        else:
            tool_name = "masscan_quick_scan"  # Default
        
        tools = [{
            "name": tool_name,
            "arguments": {"targets": targets}
        }]
        
        # Add ports if specified
        if ports and tool_name == "masscan_port_scan":
            tools[0]["arguments"]["ports"] = ports
        
        return tools

    def _get_shodan_tools(self, target: str) -> List[Dict]:
        """Get Shodan tools for IP lookup"""
        return [
            {
                "name": "shodan_lookup",
                "arguments": {"ip": target}
            }
        ]

    def _detect_context_reference(self, user_prompt: str) -> bool:
        """Detect if user is referencing previous scan results"""
        reference_keywords = [
            'these', 'those', 'them', 'the list', 'above', 'previous',
            'from the scan', 'from that scan', 'the subdomains', 'the targets',
            'high-value', 'high value', 'that list'
        ]
        prompt_lower = user_prompt.lower()
        return any(keyword in prompt_lower for keyword in reference_keywords)

    def _get_intelligent_port_scan_strategy(self, subdomains: List[str]) -> List[Dict]:
        """
        Professional port scanning workflow with DNS pre-resolution and deduplication
        
        Uses OSINT intelligence to prioritize scanning:
        - Crown jewels: Full port scan (1-65535) with naabu
        - High-value: Top 1000 ports
        - Others: Batch scan common ports
        
        Args:
            subdomains: List of subdomains to scan
        
        Returns:
            List of tool selections with intelligent prioritization
        """
        print("\n  🧠 INTELLIGENT PORT SCAN STRATEGY")
        print("  " + "="*58)
        
        try:
            from tools.dns_tools import get_unique_ips, print_deduplication_stats
            
            # Stage 0: DNS Resolution + Deduplication
            print("  📊 STAGE 0: DNS Pre-Resolution & Deduplication")
            unique_ips, ip_to_subdomains, subdomain_to_ip = get_unique_ips(subdomains)
            
            # Print stats
            print_deduplication_stats(subdomains, unique_ips, ip_to_subdomains)
            
        except ImportError:
            print("  ⚠️  DNS tools not available, using subdomains directly")
            subdomain_to_ip = {sub: sub for sub in subdomains}
            ip_to_subdomains = {sub: [sub] for sub in subdomains}
            unique_ips = subdomains
        
        # Use OSINT intelligence if available
        selected_tools = []
        
        if self.osint_intelligence:
            print("\n  🎯 STAGE 1: OSINT-Guided Prioritization")
            
            intelligence = self.osint_intelligence
            
            # CROWN JEWELS: Comprehensive scans (ALL 65535 ports!)
            crown_jewels = intelligence.get("crown_jewels", [])
            if crown_jewels:
                crown_targets = [t["subdomain"] for t in crown_jewels]
                print(f"\n  👑 CROWN JEWELS ({len(crown_targets)}) → FULL PORT SCAN (1-65535):")
                
                for target_info in crown_jewels:
                    subdomain = target_info["subdomain"]
                    score = target_info["score"]
                    print(f"     • {subdomain} (Score: {score}/10)")
                    
                    # Use naabu for full port scan
                    selected_tools.append({
                        "name": "naabu_full_scan",
                        "arguments": {"targets": subdomain, "rate": 10000}
                    })
            
            # HIGH-VALUE: Top 1000 ports
            high_value = intelligence.get("high_value", [])
            if high_value:
                high_targets = [t["subdomain"] for t in high_value]
                print(f"\n  🎯 HIGH-VALUE ({len(high_targets)}) → TOP 1000 PORTS:")
                
                for target_info in high_value[:5]:  # Show first 5
                    print(f"     • {target_info['subdomain']} (Score: {target_info['score']}/10)")
                
                if len(high_value) > 5:
                    print(f"     ... and {len(high_value) - 5} more")
                
                # Batch scan with naabu top-1000
                selected_tools.append({
                    "name": "naabu_top_ports",
                    "arguments": {
                        "targets": ",".join(high_targets),
                        "top": 1000
                    }
                })
            
            # MEDIUM/LOW: Quick batch scan (common ports)
            medium_low = intelligence.get("medium_value", []) + intelligence.get("low_value", [])
            if medium_low:
                medium_low_targets = [t["subdomain"] for t in medium_low]
                print(f"\n  ⚡ MEDIUM/LOW ({len(medium_low_targets)}) → COMMON PORTS (FAST):")
                print(f"     → Masscan batch scan")
                
                selected_tools.append({
                    "name": "masscan_batch_scan",
                    "arguments": {"targets": ",".join(medium_low_targets)}
                })
            
            total = len(crown_jewels) + len(high_value) + len(medium_low)
            print(f"\n  ✅ Strategy: {len(crown_jewels)} comprehensive + {len(high_value)} detailed + {len(medium_low)} quick = {total} targets")
            
        else:
            # Fallback: No OSINT, use IP deduplication only
            print("\n  ⚡ STAGE 1: Fast Discovery (No OSINT)")
            print(f"     → Scanning {len(unique_ips)} unique IPs with top-1000 ports")
            
            # Use naabu top-1000 on all unique IPs
            selected_tools.append({
                "name": "naabu_top_ports",
                "arguments": {
                    "targets": ",".join(unique_ips),
                    "top": 1000
                }
            })
        
        return selected_tools

    def _gather_osint_intelligence(self, domain: str, subdomains: List[str]) -> Dict[str, Any]:
        """
        Gather OSINT intelligence to identify crown jewels
        
        Scrapes company website, analyzes business context,
        identifies which subdomains are most critical
        
        Args:
            domain: Main domain (e.g., "snode.com")
            subdomains: List of discovered subdomains
        
        Returns:
            Intelligence dictionary with crown jewels identified
        """
        print("\n" + "="*60)
        print("🔍 INTELLIGENCE ENRICHMENT (OSINT)")
        print("="*60)
        
        try:
            from osint_intelligence import OSINTIntelligenceAnalyzer
            
            # Try to scrape homepage for business context
            web_content = {}
            try:
                import requests
                try:
                    from bs4 import BeautifulSoup
                    has_bs4 = True
                except ImportError:
                    has_bs4 = False
                    import re
                
                print(f"  📄 Scraping homepage of {domain}...")
                response = requests.get(f"https://{domain}", timeout=10, verify=False)
                
                if has_bs4:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    homepage_text = soup.get_text(separator=' ', strip=True)[:2000]
                else:
                    # Regex fallback if bs4 missing
                    print("  ⚠️  bs4 not found, using regex scraping")
                    text = re.sub(r'<[^>]+>', ' ', response.text)
                    homepage_text = re.sub(r'\s+', ' ', text).strip()[:2000]
                
                web_content = {"homepage": homepage_text}
                
                # Store business context
                self.business_context = homepage_text
                
                print(f"  ✓ Scraped {len(homepage_text)} characters of business context")
            except Exception as e:
                print(f"  ⚠️  Could not scrape {domain}: {e}")
                web_content = {}
            
            # Analyze intelligence
            analyzer = OSINTIntelligenceAnalyzer()
            intelligence = analyzer.analyze_target_intelligence(
                domain=domain,
                subdomains=subdomains,
                web_content=web_content
            )
            
            # Store intelligence
            self.osint_intelligence = intelligence
            
            # Extract crown jewels
            for target in intelligence.get("crown_jewels", []):
                self.crown_jewels.add(target["subdomain"])
            
            # Display results
            crown_count = len(intelligence.get("crown_jewels", []))
            high_count = len(intelligence.get("high_value", []))
            
            if crown_count > 0:
                print(f"\n  👑 CROWN JEWELS IDENTIFIED ({crown_count}):")
                for target in intelligence.get("crown_jewels", [])[:5]:
                    print(f"     • {target['subdomain']} (Score: {target['score']}/10)")
                    for reason in target['reasons'][:2]:
                        print(f"       - {reason}")
            
            if high_count > 0:
                print(f"\n  🎯 HIGH-VALUE TARGETS ({high_count}):")
                for target in intelligence.get("high_value", [])[:3]:
                    print(f"     • {target['subdomain']} (Score: {target['score']}/10)")
            
            print(f"\n  ✓ Intelligence gathered on {len(subdomains)} targets")
            
            return intelligence
            
        except ImportError:
            print("  ⚠️  OSINT intelligence module not available")
            return None
        except Exception as e:
            print(f"  ⚠️  OSINT intelligence failed: {e}")
            return None

    def phase_1_tool_selection(self, user_prompt: str) -> Tuple[List[Dict], str]:
        """
        Phase 1: Tool Selection (LLM/Keyword)
        Creates scan session, uses keyword detection first, then falls back to LLM

        Returns:
            Tuple of (selected_tools, reasoning)
        """
        print("\n" + "="*60)
        print("📦 PHASE 1: TOOL SELECTION")
        print("="*60)

        # Check if user is referencing previous scan results
        if self._detect_context_reference(user_prompt):
            # NEW: Use intelligent port scan workflow with DNS deduplication!
            if self.osint_intelligence and self._detect_port_scan(user_prompt):
                # Collect all subdomains from OSINT intelligence
                intelligence = self.osint_intelligence
                all_subdomains = []
                
                for category in ["crown_jewels", "high_value", "medium_value", "low_value"]:
                    targets = intelligence.get(category, [])
                    all_subdomains.extend([t["subdomain"] for t in targets])
                
                if all_subdomains:
                    # Use intelligent workflow (DNS + dedup + naabu!)
                    selected_tools = self._get_intelligent_port_scan_strategy(all_subdomains)
                    
                    total_targets = len(all_subdomains)
                    crown_count = len(intelligence.get("crown_jewels", []))
                    high_count = len(intelligence.get("high_value", []))
                    other_count = total_targets - crown_count - high_count
                    
                    reasoning = f"Intelligent port scan: {crown_count} crown jewels (full 65535 ports), {high_count} high-value (top 1000), {other_count} others (batch) = {total_targets} total with DNS deduplication"
                    
                    return selected_tools, reasoning
            
            # FALLBACK: Original keyword-based prioritization (if no OSINT)
            # Combine critical and high-value targets
            all_priority_targets = list(self.critical_targets.union(self.high_value_targets))

            # Check if we have targets from previous subdomain scan
            if all_priority_targets and self._detect_port_scan(user_prompt):
                # Separate critical and high-value targets
                critical_list = sorted(list(self.critical_targets))
                high_value_list = sorted(list(self.high_value_targets))
                
                print(f"  🔗 Context reference detected - using {len(all_priority_targets)} priority targets + ALL others from previous scan")
                selected_tools = []
                
                # Process priority targets with service detection (Top 1000 + Version)
                # Use nmap for detailed analysis of critical/high-value targets
                for target in critical_list + high_value_list:
                    selected_tools.append({
                        "name": "nmap_service_detection",  # Top 1000 ports + Version info
                        "arguments": {"target": target}
                    })
                
                # Also scan all other (non-priority) subdomains
                all_subdomains = set()
                for scan_result in self.scan_results:
                    if scan_result.get("result", {}).get("subdomains"):
                        all_subdomains.update(scan_result["result"]["subdomains"])
                
                # Get non-priority targets
                other_targets = sorted(all_subdomains - self.critical_targets - self.high_value_targets)
                
                # Use masscan for batch scanning if many targets (10+)
                if len(other_targets) >= 10:
                    # Masscan batch scan - much faster for many targets
                    selected_tools.append({
                        "name": "masscan_batch_scan",
                        "arguments": {"targets": ",".join(other_targets)}
                    })
                else:
                    # Use nmap quick scan for few targets
                    for target in other_targets:
                        selected_tools.append({
                            "name": "nmap_quick_scan",  # Top 100 ports - very fast
                            "arguments": {"target": target}
                        })
                
                total_targets = len(all_subdomains)
                priority_count = len(critical_list) + len(high_value_list)
                other_count = len(other_targets)
                
                if len(other_targets) >= 10:
                    scan_strategy = f"{priority_count} priority (nmap service) + {other_count} others (masscan batch)"
                    reasoning = f"Smart batch scan: {scan_strategy} = {total_targets} total"
                else:
                    reasoning = f"Smart batch scan: {priority_count} priority targets (service scan) + {other_count} others (quick scan) = {total_targets} total"
                
                print(f"  🚨 {len(critical_list)} CRITICAL targets → Nmap service scan (top 1000 + version)")
                print(f"  🎯 {len(high_value_list)} High-value targets → Nmap service scan (top 1000 + version)")
                if len(other_targets) >= 10:
                    print(f"  ⚡ {len(other_targets)} Other targets → Masscan batch scan (FAST)")
                else:
                    print(f"  ⚡ {len(other_targets)} Other targets → Nmap quick scan (top 100 ports)")
                
                if selected_tools:
                    print(f"  ✓ Selected: Port scan for {len(selected_tools)} total targets")
                    for i, tool in enumerate(selected_tools[:3], 1):
                        tool_target = tool['arguments'].get('target') or f"{len(tool['arguments'].get('targets', '').split(','))} targets"
                        print(f"    {i}. {tool_target} ({tool['name']})")
                    if len(selected_tools) > 3:
                        print(f"    ... and {len(selected_tools) - 3} more")
                    return selected_tools, reasoning

            # If no priority targets but we have scan_results, try to extract subdomains from previous scan
            elif len(self.scan_results) > 0 and self._detect_port_scan(user_prompt):
                # Try to recover subdomains from previous scan results
                recovered_subdomains = []
                for scan_result in self.scan_results:
                    if scan_result.get("result", {}).get("subdomains"):
                        recovered_subdomains.extend(scan_result["result"]["subdomains"])

                if recovered_subdomains:
                    targets_to_scan = sorted(set(recovered_subdomains))
                    
                    # Use masscan for batch scanning if many targets (10+)
                    if len(targets_to_scan) >= 10:
                        print(f"  🔗 Context reference detected - recovered {len(targets_to_scan)} subdomains from interrupted scan")
                        selected_tools = [{
                            "name": "masscan_batch_scan",
                            "arguments": {"targets": ",".join(targets_to_scan)}
                        }]
                        reasoning = f"Port scanning {len(targets_to_scan)} subdomains recovered from previous scan (masscan batch)."
                        print(f"  ✓ Selected: Masscan batch scan for {len(targets_to_scan)} targets (FAST)")
                    else:
                        # Use nmap quick scan for few targets
                        print(f"  🔗 Context reference detected - recovered {len(targets_to_scan)} subdomains from interrupted scan")
                        selected_tools = []
                        reasoning = f"Port scanning {len(targets_to_scan)} subdomains recovered from previous scan (quick scan)."
                        
                        for target in targets_to_scan:
                            selected_tools.append({
                                "name": "nmap_quick_scan",
                                "arguments": {"target": target}
                            })

                    if selected_tools:
                        if len(targets_to_scan) < 10:
                            print(f"  ✓ Selected: Quick scan for {len(selected_tools)} targets")
                            for i, tool in enumerate(selected_tools[:3], 1):
                                print(f"    {i}. {tool['arguments']['target']} ({tool['name']})")
                            if len(selected_tools) > 3:
                                print(f"    ... and {len(selected_tools) - 3} more")
                        return selected_tools, reasoning
                else:
                    print("  ⚠️  Context reference detected but no usable targets from previous scan")
                    print("  💡 Tip: The previous scan was interrupted. Try running a complete subdomain scan first")
            else:
                print("  ⚠️  Context reference detected but no previous scan results available")
                print("  💡 Tip: Try running a subdomain scan first, then reference 'those subdomains'")

        # Create scan session in database
        target = self._extract_target_from_prompt(user_prompt)
        if ENABLE_DATABASE and self.session_manager:
            try:
                session = self.session_manager.create_session(
                    user_prompt=user_prompt,
                    target=target or "unknown",
                    session_type=self._detect_session_type(user_prompt)
                )
                self.db_session_id = session.id
                self.persister = ToolResultPersister(session_id=session.id)
                self.context_builder = LLMContextBuilder(session_id=session.id)
                print(f"  📝 Created session: {session.id[:8]}...")
            except Exception as e:
                print(f"  ⚠️  Session creation failed: {e}")

        # 1. Check for subdomain enumeration request
        if self._detect_subdomain_scan(user_prompt):
            # Clear previous high-value targets for fresh subdomain scan
            self.high_value_targets.clear()
            
            domain = self._extract_domain_from_prompt(user_prompt)
            if domain:
                self.is_subdomain_scan = True
                selected_tools = self._get_subdomain_tools(domain, user_prompt)
                reasoning = f"Subdomain enumeration detected. Using Amass and BBOT for comprehensive coverage on {domain}."
                print(f"  🔍 Subdomain scan detected for: {domain}")
                for tool in selected_tools:
                    tool_name = tool['name']
                    mode_info = ""
                    if 'passive' in tool.get('arguments', {}):
                        mode_info = f" ({'passive' if tool['arguments']['passive'] else 'active'} mode)"
                    elif 'brute' in tool.get('arguments', {}) and tool['arguments']['brute']:
                        mode_info = " (brute force mode)"
                    print(f"  ✓ Selected: {tool_name}{mode_info}")
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

        # 3. Check for masscan request (BEFORE port scan to avoid conflict)
        if self._detect_masscan_scan(user_prompt):
            target = self._extract_target_from_prompt(user_prompt)
            if target:
                # Extract port specification from prompt
                import re
                port_match = re.search(r'ports?\s+([\d,\-]+)', user_prompt, re.IGNORECASE)
                ports = port_match.group(1) if port_match else None
                
                selected_tools = self._get_masscan_tools(target, ports, user_prompt)
                reasoning = f"Masscan scan detected for {target}."
                print(f"  🔍 Masscan scan detected for: {target}")
                print(f"  ✓ Selected: {selected_tools[0]['name']}")
                
                # Show actual command that will be executed
                if ports:
                    print(f"     → Command: masscan {target} -p {ports} --rate 1000")
                else:
                    default_ports = "80,443,8080,8443,22,3389"
                    print(f"     → Command: masscan {target} -p {default_ports} --rate 1000")
                
                return selected_tools, reasoning

        # 4. Check for port scan request (with optional OSINT enrichment)
        if self._detect_port_scan(user_prompt):
            target = self._extract_target_from_prompt(user_prompt)
            if target:
                with_osint = self._detect_osint_enrichment(user_prompt)
                selected_tools = self._get_port_scan_tools(target, user_prompt, with_osint=with_osint)
                reasoning = f"Port scan detected for {target}."
                print(f"  🔍 Port scan detected for: {target}")
                for tool in selected_tools:
                    if 'nmap' in tool['name']:
                        print(f"  ✓ Selected: {tool['name']}")

        #  5. LLM fallback for unrecognized requests
        # Build system prompt with effectiveness guidance
        from prompts import get_phase1_prompt
        from tools import get_all_tool_names
        
        # Format tool list for LLM
        tool_names = get_all_tool_names()
        tool_list_str = "\\n".join([f"- {tool}" for tool in tool_names])
        
        # Get enhanced Phase 1 prompt with effectiveness + patterns
        system_prompt = get_phase1_prompt(tool_list_str, user_request=user_prompt)
        
        # Call LLM with enhanced guidance
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
        Phase 2: Execute Tools & Atomic Persistence
        Run each selected tool, parse output, save to tool-specific models, enrich

        Returns:
            List of execution results
        """
        print("\n" + "="*60)
        print("⚙️  PHASE 2: EXECUTION & PERSISTENCE")
        print("="*60)

        # Update session phase
        if self.session_manager and self.db_session_id:
            try:
                self.session_manager.update_phase(self.db_session_id, 2, selected_tools)
            except Exception:
                pass

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

                # Add tool name to result for persistence
                if "tool" not in result:
                    result["tool"] = tool_name

                # Display the actual command that was executed
                if result.get("command"):
                    print(f"    Running: {result['command']}")

                # ATOMIC PERSISTENCE: Save to tool-specific models
                if ENABLE_DATABASE and result.get("success"):
                    # Save to enhanced tool-specific tables
                    if self.persister:
                        try:
                            model = self.persister.save_tool_result(tool_name, result)
                            if model:
                                result["db_model_id"] = model.id
                                print(f"    💾 Persisted to {type(model).__name__}: {model.id[:8]}...")
                        except Exception as e:
                            print(f"    ⚠️  Enhanced persistence failed: {e}")

                    # Also save to legacy tables (backward compatibility)
                    output_file = (
                        result.get("output_xml") or
                        result.get("output_json") or
                        result.get("json_output_file")
                    )

                    if output_file:
                        target = tool_args.get("target") or tool_args.get("domain") or tool_args.get("ip", "unknown")
                        try:
                            db_result = save_scan_result(
                                tool=tool_name.split("_")[0],
                                target=target,
                                output_file=output_file,
                                scan_profile=tool_name,
                                elapsed_seconds=result.get("elapsed_seconds", 0),
                                session_id=self.session_id
                            )
                            result["legacy_db"] = db_result
                        except Exception:
                            pass  # Legacy save is optional

                results.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": result
                })

                if result.get("success"):
                    print(f"    ✅ Success")
                else:
                    print(f"    ⚠️  {result.get('error', 'Unknown error')}")

            except requests.exceptions.ConnectionError as e:
                print(f"    ⚠️  Network Error: Could not connect to external service (DNS/Internet issue).")
                print(f"    ℹ️  Continuing without this tool's results.")
                results.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": {"success": False, "error": "Network Connection Error (DNS/Internet)"}
                })
            except Exception as e:
                print(f"    ❌ Error: {e}")
                results.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": {"success": False, "error": str(e)}
                })

        self.scan_results = results

        # Build and cache context for Phase 3 - only if there's successful data
        if ENABLE_DATABASE and self.context_builder and self.db_session_id:
            # Check if at least one scan was successful
            has_success = any(r["result"].get("success", False) for r in results)
            
            if has_success:
                try:
                    print("\n  🔄 Building enriched context...")
                    self.enriched_context = build_and_cache_context(self.db_session_id)
                    risk_score = self.enriched_context.get('summary', {}).get('risk_score', 0)
                    risk_level = self.enriched_context.get('summary', {}).get('risk_level', 'UNKNOWN')
                    print(f"    ✅ Context cached | Risk: {risk_level} ({risk_score}/100)")
                except Exception as e:
                    print(f"    ⚠️  Context build failed: {e}")
                    self.enriched_context = None
            else:
                print("\n  ⚠️  All scans failed - no context to build")
                self.enriched_context = None

        return results


    def _detect_scan_type(self, scan_results: List[Dict]) -> str:
        """Detect scan type based on tools used in scan results"""
        tools_used = [r["tool"] for r in scan_results]
        
        # Check for subdomain tools
        subdomain_tools = ["amass_enum", "amass_intel", "bbot_subdomain_enum", "bbot_web_scan"]
        if any(tool in tools_used for tool in subdomain_tools):
            return "subdomain"
        
        # Check for vulnerability scan
        if "nmap_vuln_scan" in tools_used:
            return "vuln_scan"
        
        # Check for Shodan/OSINT
        shodan_tools = ["shodan_lookup", "shodan_host", "shodan_search"]
        if any(tool in tools_used for tool in shodan_tools):
            # If ONLY shodan, it's osint, otherwise it's enrichment
            nmap_tools = [t for t in tools_used if "nmap" in t]
            if not nmap_tools:
                return "osint"
        
        # Check for masscan tools
        masscan_tools = ["masscan_scan", "masscan_quick_scan", "masscan_batch_scan",
                        "masscan_port_scan", "masscan_web_scan"]
        if any(tool in tools_used for tool in masscan_tools):
            return "masscan"
        
        # Check for port scan tools
        port_scan_tools = ["nmap_quick_scan", "nmap_fast_scan", "nmap_port_scan", 
                          "nmap_all_ports", "nmap_service_detection", "nmap_aggressive_scan",
                          "nmap_stealth_scan", "nmap_comprehensive_scan"]
        if any(tool in tools_used for tool in port_scan_tools):
            return "port_scan"
        
        # Default to generic
        return "generic"

    def phase_3_analysis(self, scan_results: List[Dict]) -> str:
        """
        Phase 3: Intelligence Analysis
        LLM analyzes results with enriched DB context and generates vulnerability report

        Returns:
            Analysis report string
        """
        print("\n" + "="*60)
        print("📊 PHASE 3: INTELLIGENCE ANALYSIS")
        print("="*60)

        # Update session phase
        if self.session_manager and self.db_session_id:
            try:
                self.session_manager.update_phase(self.db_session_id, 3)
            except Exception:
                pass

        # Prepare COMPLETE scan results for LLM (no truncation!)
        results_for_llm = []
        for r in scan_results:
            tool_result = {
                "tool": r["tool"],
                "success": r["result"].get("success", False),
                "target": r["result"].get("target") or r["args"].get("target") or r["args"].get("domain") or r["args"].get("ip"),
                "command": r["result"].get("command", ""),
            }

            # Include ALL scan data (no truncation!)
            result = r["result"]
            
            # For Nmap scans - include everything
            if "nmap" in r["tool"].lower():
                tool_result["scan_summary"] = result.get("summary", "")
                tool_result["hosts_discovered"] = result.get("hosts_discovered", 0)
                tool_result["open_ports"] = result.get("open_ports", [])  # All ports!
                tool_result["open_ports_count"] = result.get("open_ports_count", 0)
                tool_result["services"] = result.get("services", [])  # All services!
                tool_result["vulnerabilities"] = result.get("vulnerabilities", [])
                tool_result["os_detection"] = result.get("os_detection")
                tool_result["raw_summary"] = result.get("output", "")[:2000]  # First 2000 chars of raw output

            # For Masscan - include complete results
            elif "masscan" in r["tool"].lower():
                masscan_result = result
                tool_result["masscan_data"] = {
                    "targets": masscan_result.get("targets", []),
                    "resolved_targets": masscan_result.get("resolved_targets", []),
                    "hostname_to_ip": masscan_result.get("hostname_to_ip", {}),
                    "results": masscan_result.get("results", {}),  # All results!
                    "ports_scanned": masscan_result.get("ports_scanned"),
                    "command": masscan_result.get("command"),
                    "scan_rate": masscan_result.get("scan_rate"),
                    "targets_with_open_ports": masscan_result.get("targets_with_open_ports", 0),
                    "total_open_ports": masscan_result.get("total_open_ports", 0),
                    "scan_duration": masscan_result.get("scan_duration", 0)
                }

            # For Shodan - include complete data
            elif "shodan" in r["tool"].lower() and result.get("data"):
                shodan_data = result["data"]
                tool_result["shodan_intel"] = {
                    "ip": shodan_data.get("ip_str"),
                    "organization": shodan_data.get("organization"),
                    "isp": shodan_data.get("isp"),
                    "country": shodan_data.get("country_name"),
                    "city": shodan_data.get("city"),
                    "ports": shodan_data.get("ports", []),  # All ports!
                    "hostnames": shodan_data.get("hostnames", []),
                    "vulns": list(shodan_data.get("vulns", [])),  # All CVEs!
                    "os": shodan_data.get("os"),
                    "threat_level": shodan_data.get("threat_level"),
                    "threat_indicators": shodan_data.get("threat_indicators", [])
                }

            # For subdomain scans - include all subdomains
            elif result.get("subdomains"):
                tool_result["subdomains"] = result["subdomains"]  # All subdomains!
                tool_result["subdomains_count"] = len(result["subdomains"])

            results_for_llm.append(tool_result)

        # Get enriched context from Phase 2 caching OR build fresh
        enriched_context = getattr(self, 'enriched_context', None)
        if not enriched_context and ENABLE_DATABASE and self.db_session_id:
            try:
                enriched_context = get_cached_context(self.db_session_id)
            except Exception:
                enriched_context = None

        # Build combined context for LLM
        db_context = {}
        if enriched_context:
            db_context = {
                "enriched_summary": enriched_context.get("summary", {}),
                "threat_intel": enriched_context.get("threat_intel", {}),
                "subdomain_data": enriched_context.get("subdomain_data", {}),
                "risk_score": enriched_context.get("summary", {}).get("risk_score", 0),
                "risk_level": enriched_context.get("summary", {}).get("risk_level", "UNKNOWN")
            }
            print(f"  📊 Using enriched context (Risk: {db_context.get('risk_level', 'N/A')})")
        elif ENABLE_DATABASE:
            try:
                db_context = query_database("stats")
            except:
                db_context = {"note": "Database query unavailable"}

        # Detect scan type for appropriate report format
        scan_type = self._detect_scan_type(scan_results)
        print(f"  📋 Report format: {scan_type}")

        # SPECIAL HANDLING: Check if masscan found zero results
        # Generate report programmatically instead of relying on LLM
        if scan_type == "masscan":
            # Extract masscan data from results
            masscan_data = None
            for r in results_for_llm:
                if r.get("tool", "").startswith("masscan") and "masscan_data" in r:
                    masscan_data = r["masscan_data"]
                    break

            # If masscan found zero open ports, generate report directly
            if masscan_data and masscan_data.get("total_open_ports", 0) == 0:
                print("  ⚠️  Masscan found no open ports - generating report directly")
                total_targets = len(masscan_data.get("targets", []))
                ports_scanned = masscan_data.get("ports_scanned", "unknown")

                analysis = f"""## SCAN RESULTS

Masscan batch scan completed on {total_targets} targets.
Scanned ports: {ports_scanned}
**Result: No open ports detected on any target.**

This indicates:
- All scanned ports are closed or filtered by firewalls
- Targets may not be responding to scans
- Network filtering may be blocking scan traffic

### Targets Scanned:
"""
                # List all targets
                for i, target in enumerate(masscan_data.get("targets", [])[:50], 1):
                    analysis += f"\n{i}. {target}"

                if len(masscan_data.get("targets", [])) > 50:
                    analysis += f"\n... and {len(masscan_data.get('targets', [])) - 50} more targets"

                analysis += """

## RECOMMENDATIONS

1. **Verify Connectivity**: Test basic network connectivity to targets (ping, traceroute)
2. **Check Firewall Rules**: Network firewalls may be blocking scan traffic
3. **Retry with Different Approach**:
   - Try slower scan rate to avoid triggering IDS/IPS
   - Use Nmap service detection on high-priority targets for more detailed results
   - Scan from different source IP/network if possible
4. **Alternative Tools**: Consider using Nmap for more detailed scanning with service detection
5. **Targeted Scanning**: Focus on known critical targets with comprehensive scans

### Next Steps:
- Review if targets are actually reachable from your scan position
- Consider using 'nmap service detection' on high-priority targets
- Check if scan is being blocked by network security devices
"""
                # Skip LLM call and return the programmatic report
                if self.session_manager and self.db_session_id and enriched_context:
                    try:
                        self.session_manager.set_analysis_results(
                            self.db_session_id,
                            {"analysis": analysis[:5000]},
                            enriched_context.get("summary", {}).get("risk_score", 0),
                            enriched_context.get("summary", {}).get("risk_level", "UNKNOWN")
                        )
                    except Exception:
                        pass

                return analysis

        # Send COMPLETE scan data to LLM
        system_prompt = get_phase3_prompt(
            json.dumps(results_for_llm, indent=2),
            json.dumps(db_context, indent=2),
            scan_type=scan_type
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Analyze the scan results and provide a comprehensive security report."}
        ]

        print("\n🔍 Analyzing results with enriched context...")

        # Use config timeout (TIMEOUT_OLLAMA) for LLM analysis
        response = self._call_ollama(messages, timeout=TIMEOUT_OLLAMA)

        if "error" in response:
            return f"Analysis Error: {response['error']}"

        analysis = response.get("message", {}).get("content", "No analysis generated")

        # DEBUG: Log LLM response for troubleshooting
        if analysis:
            print(f"  🔍 DEBUG: LLM response length: {len(analysis)} chars")
            # Show first 300 chars to diagnose issues without overwhelming output
            preview = analysis[:300].replace("\n", "\\n")
            print(f"  🔍 DEBUG: Preview: {preview}...")

        # Handle invalid LLM responses or generic templates
        invalid_responses = ["", "None", "No analysis generated", "null", "N/A"]
        
        # More specific placeholder detection - only flag if response has MULTIPLE generic placeholders
        # Removed overly broad patterns like [X], [list, [count that match legitimate outputs
        placeholder_patterns = [
            "[Insert Date]",      # Very specific generic placeholder
            "[Total Number]",     # Very specific generic placeholder  
            "ServerA",            # Clearly a placeholder name from examples
            "[brief summary]",    # Instruction placeholder
            "[WHY IT'S",         # From prompt examples, shouldn't appear in good output
            "[Insert",           # Catch other [Insert X] variants
        ]

        # Count how many different placeholders appear
        placeholder_count = sum(1 for p in placeholder_patterns if p in analysis)

        # Flag as invalid if:
        # 1. Response is empty or in invalid_responses list, OR
        # 2. Has 2+ generic placeholders (stronger evidence of template), OR
        # 3. Analysis is suspiciously short (<100 chars) suggesting incomplete generation
        is_template = (
            not analysis or
            analysis.strip() in invalid_responses or
            placeholder_count >= 2 or
            (len(analysis.strip()) < 100 and any(p in analysis for p in ["[", "ServerA"]))
        )

        if is_template:
            print(f"  ⚠️  LLM returned invalid/generic template - using fallback report (placeholders: {placeholder_count})")
            analysis = self._generate_basic_analysis_report(scan_results)

        # Store analysis results in session
        if self.session_manager and self.db_session_id and enriched_context:
            try:
                self.session_manager.set_analysis_results(
                    self.db_session_id,
                    {"analysis": analysis[:5000]},  # Truncate for storage
                    enriched_context.get("summary", {}).get("risk_score", 0),
                    enriched_context.get("summary", {}).get("risk_level", "UNKNOWN")
                )
            except Exception:
                pass

        return analysis

    def phase_4_report_generation(self, scan_results: List[Dict]) -> str:
        """
        Phase 4: Report Generation
        LLM formats analysis for target audience (combines multi-tool results)

        Returns:
            Combined analysis report string
        """
        print("\n" + "="*60)
        print("📝 PHASE 4: REPORT GENERATION")
        print("="*60)

        # Update session phase
        if self.session_manager and self.db_session_id:
            try:
                self.session_manager.update_phase(self.db_session_id, 4)
            except Exception:
                pass

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
        
        # Pre-categorize subdomains for better LLM output
        categories = {
            "www": [],
            "api": [],
            "mail": [],
            "dev": [],
            "staging": [],
            "admin": [],
            "vpn": [],
            "internal": [],
            "test": [],
            "other": []
        }
        
        # Helper function for keyword matching with word boundaries
        def matches_keyword(subdomain: str, keywords: list) -> bool:
            """Check if subdomain matches keywords with word boundaries"""
            import re
            sub_lower = subdomain.lower()
            # Extract the subdomain part before the domain (e.g., "dev" from "dev.example.com")
            subdomain_part = sub_lower.split('.')[0]

            for keyword in keywords:
                # Check if keyword appears as a word boundary (start, end, or separated by hyphens/underscores)
                pattern = r'(^|[-_])' + re.escape(keyword) + r'([-_]|$)'
                if re.search(pattern, subdomain_part):
                    return True
                # Also check if subdomain starts with keyword
                if subdomain_part.startswith(keyword):
                    return True
            return False

        for subdomain in all_sorted:
            sub_lower = subdomain.lower()
            categorized = False

            # Categorize based on keywords with word boundaries
            if matches_keyword(subdomain, ["www", "web", "portal"]):
                categories["www"].append(subdomain)
                categorized = True
            elif matches_keyword(subdomain, ["api", "rest", "graphql"]):
                categories["api"].append(subdomain)
                categorized = True
            elif matches_keyword(subdomain, ["mail", "smtp", "mx", "imap", "pop", "pop3"]):
                categories["mail"].append(subdomain)
                categorized = True
            elif matches_keyword(subdomain, ["dev", "develop", "development"]) and "staging" not in sub_lower:
                categories["dev"].append(subdomain)
                categorized = True
            elif matches_keyword(subdomain, ["staging", "stage", "uat", "preprod"]):
                categories["staging"].append(subdomain)
                categorized = True
            elif matches_keyword(subdomain, ["admin", "administrator", "management"]):
                categories["admin"].append(subdomain)
                categorized = True
            elif matches_keyword(subdomain, ["vpn", "remote"]):
                categories["vpn"].append(subdomain)
                categorized = True
            elif matches_keyword(subdomain, ["internal", "intranet", "corp", "backend"]):
                categories["internal"].append(subdomain)
                categorized = True
            elif matches_keyword(subdomain, ["test", "testing", "qa"]):
                categories["test"].append(subdomain)
                categorized = True

            if not categorized:
                categories["other"].append(subdomain)
        
        combined_summary = {
            "total_unique": len(combined_data["all_subdomains"]),
            "amass_count": len(amass_set),
            "bbot_count": len(bbot_set),
            "overlap_count": len(overlap),
            "unique_to_amass": len(amass_set - bbot_set),
            "unique_to_bbot": len(bbot_set - amass_set),
            "sample_subdomains": all_sorted[:200],  # Keep larger sample for reference
            "high_value_keywords": ["api", "admin", "dev", "staging", "test", "internal", "vpn", "mail"],
            # Add categorized lists (full lists for complete reporting)
            "categorized": {
                "www": categories["www"],
                "api": categories["api"],
                "mail": categories["mail"],
                "dev": categories["dev"],
                "staging": categories["staging"],
                "admin": categories["admin"],
                "vpn": categories["vpn"],
                "internal": categories["internal"],
                "test": categories["test"],
                "other": categories["other"]  # Full list - no truncation
            },
            "category_counts": {
                "www": len(categories["www"]),
                "api": len(categories["api"]),
                "mail": len(categories["mail"]),
                "dev": len(categories["dev"]),
                "staging": len(categories["staging"]),
                "admin": len(categories["admin"]),
                "vpn": len(categories["vpn"]),
                "internal": len(categories["internal"]),
                "test": len(categories["test"]),
                "other": len(categories["other"])
            }
        }

        # Find high-value targets and separate CRITICAL from high-value
        # Use the pre-categorized data to ensure accuracy
        critical_targets = (
            categories["api"] +      # api.*, rest.*, graphql.*
            categories["admin"] +    # admin.*, administrator.*
            categories["dev"]        # dev.* (but not staging)
        )

        high_value_targets = (
            categories["staging"] +  # staging.*, stage.*, uat.*
            categories["test"] +     # test.*
            categories["mail"] +     # mail.*, smtp.*, mx.*, imap.*
            categories["vpn"] +      # vpn.*
            categories["internal"]   # internal.*, intranet.*
        )

        combined_summary["critical_targets"] = critical_targets
        combined_summary["high_value_targets"] = high_value_targets

        # Store targets for smart scan prioritization
        self.critical_targets = set(critical_targets)
        self.high_value_targets = set(high_value_targets)

        if critical_targets:
            print(f"  🚨 Identified {len(critical_targets)} CRITICAL targets (comprehensive scan + Shodan)")
            print(f"     {', '.join(sorted(critical_targets)[:5])}{' ...' if len(critical_targets) > 5 else ''}")
        if high_value_targets:
            print(f"  🎯 Identified {len(high_value_targets)} high-value targets (comprehensive scan)")
            print(f"     {', '.join(sorted(high_value_targets)[:5])}{' ...' if len(high_value_targets) > 5 else ''}")

        print(f"\n  📊 Total unique subdomains: {combined_summary['total_unique']}")
        print(f"  📊 Overlap (found by both): {combined_summary['overlap_count']}")

        system_prompt = get_phase4_prompt(
            json.dumps(combined_summary, indent=2),
            len(combined_data["tools_used"])
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Analyze the subdomain discovery results."}
        ]

        print("\n🔍 Generating comprehensive report...")

        # HYBRID APPROACH:
        # 1. Generate programmatic categorized lists (accurate, complete, no truncation)
        # 2. Use LLM for security analysis and intelligent recommendations

        # Get LLM analysis for security insights
        print("  🤖 LLM analyzing security implications...")
        response = self._call_ollama(messages, timeout=TIMEOUT_OLLAMA, retry_without_tools=False)

        llm_analysis = ""
        llm_recommendations = ""

        if "error" not in response:
            full_analysis = response.get("message", {}).get("content", "")
            if full_analysis and full_analysis.strip() not in ["", "None", "null", "N/A"]:
                # Extract security analysis and recommendations sections from LLM output
                import re

                # Try to extract SECURITY ANALYSIS section
                security_match = re.search(r'## SECURITY ANALYSIS\s*(.*?)(?=##|\Z)', full_analysis, re.DOTALL | re.IGNORECASE)
                if security_match:
                    llm_analysis = security_match.group(1).strip()

                # Try to extract RECOMMENDATIONS section
                rec_match = re.search(r'## RECOMMENDATIONS\s*(.*?)(?=##|\Z)', full_analysis, re.DOTALL | re.IGNORECASE)
                if rec_match:
                    llm_recommendations = rec_match.group(1).strip()

        # Generate complete report with programmatic lists + LLM insights
        print(f"  ✅ Report generated ({combined_summary['total_unique']} subdomains)")
        return self._generate_subdomain_report_text(combined_summary, llm_analysis, llm_recommendations)

    def _generate_subdomain_report_text(self, combined_summary: Dict, llm_analysis: str = "", llm_recommendations: str = "") -> str:
        """Generate formatted subdomain report from categorized data with optional LLM insights"""
        lines = []

        # Header
        lines.append("## SUBDOMAIN DISCOVERY SUMMARY")
        lines.append(f"- Total unique subdomains: {combined_summary['total_unique']}")
        lines.append(f"- Found by Amass: {combined_summary['amass_count']}")
        lines.append(f"- Found by BBOT: {combined_summary['bbot_count']}")
        lines.append(f"- Overlap (found by both): {combined_summary['overlap_count']}")
        lines.append("")

        # Critical Targets
        critical = combined_summary.get('critical_targets', [])
        lines.append("## CRITICAL TARGETS (api, admin, dev)")
        if critical:
            lines.append("*These will receive COMPREHENSIVE scans + Shodan automatically*")
            for target in sorted(critical):
                lines.append(f"- {target}")
        else:
            lines.append("- None found")
        lines.append("")

        # High-Value Targets
        high_value = combined_summary.get('high_value_targets', [])
        lines.append("## HIGH-VALUE TARGETS (staging, test, mail, vpn, internal)")
        if high_value:
            lines.append("*These will receive COMPREHENSIVE scans*")
            for target in sorted(high_value):
                lines.append(f"- {target}")
        else:
            lines.append("- None found")
        lines.append("")

        # Categorized Subdomains
        lines.append("## CATEGORIZED SUBDOMAINS")
        lines.append("")

        categorized = combined_summary.get('categorized', {})
        category_counts = combined_summary.get('category_counts', {})

        # Web Services
        lines.append(f"### Web Services (www, web, portal) - {category_counts.get('www', 0)}")
        if categorized.get('www'):
            for sub in sorted(categorized['www']):
                lines.append(f"- {sub}")
        else:
            lines.append("- None found")
        lines.append("")

        # API Endpoints
        lines.append(f"### API Endpoints (api, rest, graphql) - {category_counts.get('api', 0)}")
        if categorized.get('api'):
            for sub in sorted(categorized['api']):
                lines.append(f"- {sub}")
        else:
            lines.append("- None found")
        lines.append("")

        # Mail/Communication
        lines.append(f"### Mail/Communication (mail, smtp, mx) - {category_counts.get('mail', 0)}")
        if categorized.get('mail'):
            for sub in sorted(categorized['mail']):
                lines.append(f"- {sub}")
        else:
            lines.append("- None found")
        lines.append("")

        # Development/Staging/Test combined
        dev_staging_test = (categorized.get('dev', []) +
                           categorized.get('staging', []) +
                           categorized.get('test', []))
        total_dst = (category_counts.get('dev', 0) +
                    category_counts.get('staging', 0) +
                    category_counts.get('test', 0))
        lines.append(f"### Development/Staging/Test (dev, staging, test, uat) - {total_dst}")
        if dev_staging_test:
            for sub in sorted(set(dev_staging_test)):
                lines.append(f"- {sub}")
        else:
            lines.append("- None found")
        lines.append("")

        # Admin/Management
        lines.append(f"### Admin/Management (admin) - {category_counts.get('admin', 0)}")
        if categorized.get('admin'):
            for sub in sorted(categorized['admin']):
                lines.append(f"- {sub}")
        else:
            lines.append("- None found")
        lines.append("")

        # VPN/Internal combined
        vpn_internal = categorized.get('vpn', []) + categorized.get('internal', [])
        total_vi = category_counts.get('vpn', 0) + category_counts.get('internal', 0)
        lines.append(f"### VPN/Internal (vpn, internal) - {total_vi}")
        if vpn_internal:
            for sub in sorted(set(vpn_internal)):
                lines.append(f"- {sub}")
        else:
            lines.append("- None found")
        lines.append("")

        # Other - ALL items
        lines.append(f"### Other - {category_counts.get('other', 0)}")
        if categorized.get('other'):
            for sub in sorted(categorized['other']):
                lines.append(f"- {sub}")
        else:
            lines.append("- None found")
        lines.append("")

        # Security Analysis - use LLM insights if available, otherwise use basic analysis
        lines.append("## SECURITY ANALYSIS")

        if llm_analysis:
            # Use LLM-generated security analysis
            lines.append(llm_analysis)
        else:
            # Fallback to basic programmatic analysis
            if critical:
                lines.append(f"- **CRITICAL**: {len(critical)} critical targets identified requiring immediate attention")
            if high_value:
                lines.append(f"- **HIGH-VALUE**: {len(high_value)} high-value targets identified for comprehensive scanning")
            if dev_staging_test:
                lines.append("- **WARNING**: Exposed development/staging/test environments detected")
            if categorized.get('admin'):
                lines.append("- **WARNING**: Admin panels discovered - ensure proper authentication")

        lines.append("")

        # Recommendations - use LLM insights if available, otherwise use basic recommendations
        lines.append("## RECOMMENDATIONS")

        if llm_recommendations:
            # Use LLM-generated recommendations
            lines.append(llm_recommendations)
        else:
            # Fallback to basic programmatic recommendations
            lines.append("1. **CRITICAL targets** will automatically receive:")
            lines.append("   - Comprehensive port scans (all 65535 ports + service detection + OS detection)")
            lines.append("   - Shodan threat intelligence enrichment")
            lines.append("2. **HIGH-VALUE targets** will automatically receive:")
            lines.append("   - Comprehensive port scans")
            lines.append("3. Next Steps:")
            lines.append("   - Use 'Port scan those subdomains' to begin automated scanning")
            lines.append("   - Review and secure exposed development/staging environments")
            lines.append("   - Implement strong authentication on admin panels")

        return "\n".join(lines)

    def _generate_basic_subdomain_report(
        self,
        summary: Dict,
        all_subdomains: List[str],
        high_value: List[str]
    ) -> str:
        """Generate a basic subdomain report when LLM fails (legacy fallback)"""
        # Use the new comprehensive report generator
        return self._generate_subdomain_report_text(summary)

    def _generate_basic_analysis_report(self, scan_results: List[Dict]) -> str:
        """Generate a basic analysis report when LLM fails (for non-subdomain scans)"""
        report_parts = ["## SCAN ANALYSIS SUMMARY\n"]

        for r in scan_results:
            tool_name = r["tool"]
            result = r["result"]
            success = result.get("success", False)

            report_parts.append(f"\n### {tool_name}")
            report_parts.append(f"- **Status:** {'✅ Success' if success else '❌ Failed'}")

            if success:
                # Summary
                if result.get("summary"):
                    report_parts.append(f"- **Summary:** {result['summary']}")

                # MASSCAN-SPECIFIC HANDLING
                if "masscan" in tool_name.lower():
                    total_targets = result.get("targets_count", len(result.get("targets", [])))
                    total_ports = result.get("total_open_ports", 0)
                    targets_with_ports = result.get("targets_with_open_ports", 0)
                    ports_scanned = result.get("ports_scanned", "unknown")

                    report_parts.append(f"- **Targets Scanned:** {total_targets}")
                    report_parts.append(f"- **Ports Scanned:** {ports_scanned}")
                    report_parts.append(f"- **Targets with Open Ports:** {targets_with_ports}/{total_targets}")
                    report_parts.append(f"- **Total Open Ports Found:** {total_ports}")

                    if total_ports == 0:
                        report_parts.append("\n**⚠️  No open ports detected on any target**")
                        report_parts.append("This may indicate:")
                        report_parts.append("  - Targets are protected by firewalls")
                        report_parts.append("  - Targets are offline or unreachable")
                        report_parts.append("  - Scan traffic is being filtered")
                    else:
                        # Show results per target
                        masscan_results = result.get("results", {})
                        hostname_to_ip = result.get("hostname_to_ip", {})

                        # Reverse mapping (IP to hostname)
                        ip_to_hostname = {v: k for k, v in hostname_to_ip.items()}

                        if masscan_results:
                            report_parts.append("\n**Open Ports by Target:**")
                            for ip, ports in list(masscan_results.items())[:10]:  # Show first 10
                                hostname = ip_to_hostname.get(ip, ip)
                                port_str = ", ".join([f"{p['port']}/{p['protocol']}" for p in ports])
                                report_parts.append(f"  - **{hostname}** ({ip}): {port_str}")

                            if len(masscan_results) > 10:
                                report_parts.append(f"  ... and {len(masscan_results) - 10} more targets with open ports")

                    continue  # Skip generic port handling below

                # Target info
                target = result.get("target") or result.get("domain") or result.get("ip")
                if target:
                    report_parts.append(f"- **Target:** {target}")

                # Open ports (for Nmap, etc.)
                if result.get("open_ports"):
                    ports = result["open_ports"][:10]
                    port_list = [f"{p['port']}/{p['protocol']} ({p.get('service', 'unknown')})" for p in ports]
                    report_parts.append(f"- **Open Ports:** {', '.join(port_list)}")

                # Hosts discovered
                if result.get("hosts_discovered"):
                    report_parts.append(f"- **Hosts Discovered:** {result['hosts_discovered']}")

                # Subdomains found
                if result.get("subdomains_found"):
                    report_parts.append(f"- **Subdomains Found:** {result['subdomains_found']}")

                # Vulnerabilities
                if result.get("vulnerabilities"):
                    vulns = result["vulnerabilities"][:5]
                    report_parts.append(f"- **Vulnerabilities:** {len(vulns)} detected")
                    for v in vulns:
                        if isinstance(v, dict):
                            report_parts.append(f"  - {v.get('name', v)}")
                        else:
                            report_parts.append(f"  - {v}")
            else:
                error = result.get("error", "Unknown error")
                report_parts.append(f"- **Error:** {error}")

        report_parts.append("\n---")
        report_parts.append("*Note: This is a basic report. LLM analysis was unavailable.*")

        return "\n".join(report_parts)

    def run(self, user_prompt: str) -> Dict[str, Any]:
        """
        Execute full scan cycle (3-phase or 4-phase for subdomain scans)

        Args:
            user_prompt: User's natural language request

        Returns:
            Complete results including tools, execution, and analysis
        """
        start_time = datetime.now()

        # Reset scan type flags for new scan to prevent state leakage
        self.is_subdomain_scan = False

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
        
        # NEW: Gather OSINT Intelligence after subdomain enumeration
        # This identifies crown jewels BEFORE user says "port scan those"
        if self.is_subdomain_scan:
            # Extract discovered subdomains from execution results
            all_subdomains = []
            domain = None
            
            for result in execution_results:
                if result["result"].get("subdomains"):
                    all_subdomains.extend(result["result"]["subdomains"])
                    # Get domain from first result
                    if not domain:
                        domain = result.get("args", {}).get("domain") or result["result"].get("target")
            
            # Gather OSINT intelligence if we have subdomains
            if all_subdomains and domain:
                self._gather_osint_intelligence(domain, all_subdomains)

        # Phase 3: Intelligence Analysis
        self.current_phase = IterationPhase.ANALYSIS
        analysis_report = self.phase_3_analysis(execution_results)

        # Phase 4: Report Generation (ONLY for actual subdomain enumeration scans)
        # Detect scan type based on tools used, not the flag (which may be stale)
        scan_type = self._detect_scan_type(execution_results)
        if scan_type == "subdomain":
            self.current_phase = IterationPhase.REPORT_GENERATION
            analysis_report = self.phase_4_report_generation(execution_results)

        elapsed = (datetime.now() - start_time).total_seconds()

        # Get enriched context summary if available
        enriched_summary = {}
        if hasattr(self, 'enriched_context') and self.enriched_context:
            enriched_summary = self.enriched_context.get("summary", {})

        # Build phases dict explicitly to avoid any variable key issues
        phases = {
            "phase_1_tools": selected_tools,
            "phase_2_results": [
                {
                    "tool": r["tool"],
                    "success": r["result"].get("success", False),
                    "summary": r["result"].get("summary", ""),
                    "db_model_id": r["result"].get("db_model_id")
                }
                for r in execution_results
            ],
            "phase_3_analysis": None,
            "phase_4_report": None
        }

        # Set the appropriate phase result
        if self.is_subdomain_scan:
            phases["phase_4_report"] = analysis_report
        else:
            phases["phase_3_analysis"] = analysis_report

        result = {
            "success": True,
            "session_id": self.session_id,
            "db_session_id": self.db_session_id,
            "user_prompt": user_prompt,
            "elapsed_seconds": round(elapsed, 2),
            "is_subdomain_scan": self.is_subdomain_scan,
            "risk_score": enriched_summary.get("risk_score", 0),
            "risk_level": enriched_summary.get("risk_level", "N/A"),
            "phases": phases,
            "enriched_summary": enriched_summary
        }

        return result


def _get_analysis_from_result(result: Dict) -> str:
    """Extract analysis report from result (handles both phase 3 and 4)"""
    phases = result.get("phases", {})

    # Try phase 4 first, then phase 3
    report = phases.get("phase_4_report") or phases.get("phase_3_analysis")

    # Handle edge cases where report might be invalid
    invalid_values = [None, "", "None", "null", "N/A", "No analysis generated"]
    if report is None or (isinstance(report, str) and report.strip() in invalid_values):
        # Try to build a minimal report from execution results
        phase2_results = phases.get("phase_2_results", [])
        if phase2_results:
            lines = ["## Scan Execution Summary\n"]
            for r in phase2_results:
                tool = r.get("tool", "Unknown")
                success = "✓" if r.get("success") else "✗"
                summary = r.get("summary", "No summary")
                lines.append(f"- **{tool}**: {success} {summary}")
            return "\n".join(lines)
        return "No analysis available. Please check scan execution results."

    return str(report)


def main():
    """Simple command-line interface for testing"""
    agent = SNODEAgent()

    print("\n" + "="*60)
    print("  SNODE AI - Security Node Agent")
    print("  4-Phase Penetration Testing System")
    print("  Phase 1: Tool Selection | Phase 2: Execution & Persistence")
    print("  Phase 3: Intelligence Analysis | Phase 4: Report Generation")
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
                final_report = _get_analysis_from_result(result)
                print(final_report)
                print("\n" + "="*60)
                scan_type = "Subdomain Scan (4-Phase)" if result.get("is_subdomain_scan") else "Standard Scan"
                risk_info = f"Risk: {result.get('risk_level', 'N/A')} ({result.get('risk_score', 0)}/100)"
                print(f"Session: {result['session_id']} | Type: {scan_type} | {risk_info} | Time: {result['elapsed_seconds']}s")
                if result.get('db_session_id'):
                    print(f"DB Session: {result['db_session_id'][:8]}...")
                print("="*60 + "\n")

            except KeyboardInterrupt:
                print("\n\nInterrupted. Goodbye!")
                break
            except Exception as e:
                print(f"\nError: {e}")


if __name__ == "__main__":
    main()
