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
import urllib3
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
    persist_tool_results, build_and_cache_context, get_cached_context,
    # Programmatic report imports
    ProgrammaticReportService
)
from database.programmatic_report_generator import ProgrammaticReportGenerator
from prompts import get_phase1_prompt, get_phase3_prompt, get_phase4_prompt

# Audit logging for crash recovery
from audit.logger import AuditLogger, SessionMetrics, create_audit_logger

# Multi-phase orchestration for queue-based exploitation
from orchestration.queue_manager import ExploitQueue, QueueItem, create_exploit_queue
from orchestration.validators import PhaseValidator, validate_phase_output, AgentValidator
from orchestration.session_mutex import SessionMutex, ParallelScanner, get_session_mutex

# Configuration management
try:
    from scan_configs.scan_config import ScanConfig, load_scan_config
    SCAN_CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

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

    def __init__(self, model: str = None, target: str = None):
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

        # Initialize unified LLM client (supports multiple providers)
        try:
            from llm_client import get_llm_client
            self.llm_client = get_llm_client()
            self.llm_provider = self.llm_client.provider
        except Exception as e:
            print(f"⚠️  Failed to initialize LLM client: {e}")
            self.llm_client = None
            self.llm_provider = "ollama"

        # Audit logging for crash recovery
        self.audit_logger = None
        self.metrics = None
        self.target = target or "unknown_target"

        # Multi-phase orchestration (queue-based exploitation)
        self.exploit_queue = None  # Initialized when audit logger is created

        # Parallel scanning (Week 3)
        self.session_mutex = get_session_mutex()
        self.parallel_scanner = None  # Initialized when needed

        # Configuration-driven scanning (Week 4)
        self.scan_config = None  # Can be loaded from YAML file

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
        """Call LLM API with retry logic (supports multiple providers via unified client)"""
        if timeout is None:
            timeout = TIMEOUT_OLLAMA

        # Use unified LLM client if available
        if self.llm_client:
            try:
                # Note: Tool calling support varies by provider
                # For now, only Ollama fully supports native tool calling
                if tools and self.llm_provider != "ollama":
                    # Fallback to text-based tool selection for non-Ollama providers
                    return self._call_ollama_text_fallback(messages, tools, timeout)

                # === SNODE TRACING: Wrap LLM call ===
                if TRACING_AVAILABLE:
                    user_msg = next((m["content"] for m in messages if m["role"] == "user"), "")
                    with trace_ollama_call(self.model, user_msg):
                        return self.llm_client.chat(messages, timeout)
                else:
                    return self.llm_client.chat(messages, timeout)

            except Exception as e:
                print(f"⚠️  LLM client error: {e}")
                return {"error": str(e)}

        # Fallback to direct Ollama call if client not available
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
            
            # IMPORTANT: Check "full assessment" BEFORE checking just "full"
            # "Full assessment" means comprehensive analysis (OSINT + service scan), NOT all ports
            if "full assessment" in prompt_lower or "complete assessment" in prompt_lower:
                nmap_tool = "nmap_service_detection"  # Top 1000 ports + versions (5-10 min)
                auto_shodan = True  # Add Shodan for complete picture
                print(f"  🎯 Full assessment detected → Smart scan (service detection + OSINT)")
            elif "comprehensive" in prompt_lower or "complete" in prompt_lower:
                nmap_tool = "nmap_comprehensive_scan"
                auto_shodan = True  # Comprehensive scans get Shodan automatically
            elif "aggressive" in prompt_lower:
                nmap_tool = "nmap_aggressive_scan"
                auto_shodan = True  # Aggressive scans get Shodan automatically
            elif "stealth" in prompt_lower or "stealthy" in prompt_lower or "syn" in prompt_lower:
                nmap_tool = "nmap_stealth_scan"
            elif "service" in prompt_lower or "version" in prompt_lower:
                nmap_tool = "nmap_service_detection"
            # Only select nmap_all_ports if user EXPLICITLY says "all ports" (not just "full")
            elif "all ports" in prompt_lower or "all port" in prompt_lower or "full port scan" in prompt_lower:
                nmap_tool = "nmap_all_ports"
                print(f"  ⚠️  WARNING: All-ports scan (65,535 ports) - this will take 60+ minutes")
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
        Enhanced 4-Stage Port Scanning Workflow with OSINT enrichment

        Stage 1: DNS Resolution - Convert subdomains to unique public IPs
        Stage 2: OSINT Enrichment - Query Shodan for intelligence on IPs
        Stage 3: Naabu Scanning - Fast port discovery
        Stage 4: Masscan Scanning - Comprehensive port verification

        Each stage builds enriched context for LLM analysis.

        Args:
            subdomains: List of subdomains to scan

        Returns:
            List of tool selections for 4-stage workflow
        """
        print("\n  🧠 ENHANCED 4-STAGE PORT SCAN STRATEGY")
        print("  " + "="*58)

        selected_tools = []

        # =====================================================================
        # STAGE 1: DNS RESOLUTION - Convert subdomains to unique public IPs
        # =====================================================================
        print("\n  📡 STAGE 1: DNS RESOLUTION")
        print("  " + "-"*58)

        selected_tools.append({
            "name": "dns_bulk_resolve",
            "arguments": {
                "subdomains": subdomains,
                "save_results": True
            },
            "justification": f"Stage 1: Resolve {len(subdomains)} subdomains to unique IPs for deduplication and efficient scanning"
        })

        # =====================================================================
        # STAGE 2: OSINT ENRICHMENT - Shodan lookup on resolved IPs
        # =====================================================================
        print("\n  🔍 STAGE 2: OSINT ENRICHMENT (Shodan)")
        print("  " + "-"*58)
        print("     → Will query Shodan for each unique IP")
        print("     → Gather: Open ports, services, CVEs, threat intel")

        selected_tools.append({
            "name": "shodan_batch_lookup",
            "arguments": {
                "source": "stage1_dns_results",  # Will use Stage 1 output
                "save_results": True
            },
            "justification": "Stage 2: OSINT enrichment - query Shodan for intelligence on resolved IPs"
        })

        # =====================================================================
        # STAGE 3: NAABU SCANNING - Fast port discovery
        # =====================================================================
        print("\n  ⚡ STAGE 3: NAABU PORT SCANNING")
        print("  " + "-"*58)
        print("     → Fast port discovery with Naabu")
        print("     → Scan top 1000 ports on unique IPs")

        selected_tools.append({
            "name": "naabu_batch_scan",
            "arguments": {
                "source": "stage1_dns_results",  # Will use Stage 1 IPs
                "ports": "top-1000",
                "rate": 5000,
                "save_results": True
            },
            "justification": "Stage 3: Fast port discovery with Naabu on unique IPs from Stage 1"
        })

        # =====================================================================
        # STAGE 4: NMAP SERVICE DETECTION - Source of Truth
        # =====================================================================
        print("\n  🎯 STAGE 4: NMAP SERVICE DETECTION (Source of Truth)")
        print("  " + "-"*58)
        print("     → Detailed service/version detection with Nmap")
        print("     → OS fingerprinting when possible")
        print("     → Will scan ONLY IPs with open ports from Stage 3")
        print("     → This is the authoritative data for final report")

        selected_tools.append({
            "name": "nmap_service_detection_batch",
            "arguments": {
                "source": "stage3_naabu_results",  # Only scan IPs with open ports
                "scan_discovered_ports": True,  # Target specific ports found by Naabu
                "save_results": True
            },
            "justification": "Stage 4: Nmap service detection on discovered open ports - SOURCE OF TRUTH for final report"
        })

        print("\n  ✅ 4-STAGE WORKFLOW CONFIGURED")
        print("     → Stage 1: DNS Resolution (subdomain → IP)")
        print("     → Stage 2: OSINT Enrichment (Shodan intel)")
        print("     → Stage 3: Naabu Scanning (fast port discovery)")
        print("     → Stage 4: Nmap Detection (🎯 SOURCE OF TRUTH)")
        print("     → Final report will use Nmap data with enriched context")

        return selected_tools

    def _execute_phase2_if_needed(self, results: List[Dict], selected_tools: List[Dict]):
        """
        TWO-PHASE SCANNING: After Naabu quick scan, run detailed Nmap on hosts with open ports

        Args:
            results: Results from Phase 1 execution
            selected_tools: Original tool selection (to check if this was a batch scan)
        """
        # Check if we just ran a naabu_batch_scan or masscan_batch_scan
        batch_scan_tools = ["naabu_batch_scan", "naabu_top_ports", "masscan_batch_scan"]

        naabu_results = []
        for r in results:
            tool_name = r.get("tool", "")
            if any(batch_tool in tool_name for batch_tool in batch_scan_tools):
                if r["result"].get("success"):
                    naabu_results.append(r)

        if not naabu_results:
            return  # No batch scan results to process

        # Extract hosts with open ports from Naabu/Masscan
        hosts_with_ports = set()
        total_open_ports = 0

        for r in naabu_results:
            scan_data = r["result"]

            # Handle both naabu and masscan result formats
            if "results" in scan_data:  # Batch scan format: {ip: [ports]}
                for ip, ports in scan_data["results"].items():
                    if ports:  # Has open ports
                        hosts_with_ports.add(ip)
                        total_open_ports += len(ports)

        if not hosts_with_ports:
            print("\n  ℹ️  Phase 2 skipped: No hosts with open ports found")
            return

        # Run Phase 2: Detailed Nmap scan on hosts with open ports
        print(f"\n{'='*60}")
        print(f"🔬 PHASE 2: DETAILED ANALYSIS")
        print(f"{'='*60}")
        print(f"  Found {len(hosts_with_ports)} hosts with {total_open_ports} open ports")
        print(f"  Running detailed Nmap scans for service detection...")
        print()

        # Group hosts for efficient scanning (max 10 at a time)
        hosts_list = list(hosts_with_ports)
        batch_size = 10

        for i in range(0, len(hosts_list), batch_size):
            batch = hosts_list[i:i+batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(hosts_list) + batch_size - 1) // batch_size

            print(f"[Batch {batch_num}/{total_batches}] Scanning {len(batch)} hosts: {', '.join(batch[:3])}{'...' if len(batch) > 3 else ''}")

            # Run Nmap service detection
            tool_name = "nmap_service_detection"
            tool_args = {
                "target": ",".join(batch),
                "ports": ""  # Scan default ports, or you could pass discovered ports
            }

            try:
                result = execute_tool(tool_name, tool_args)

                if isinstance(result, str):
                    try:
                        result = json.loads(result)
                    except:
                        result = {"success": False, "error": result, "output": result}

                if "tool" not in result:
                    result["tool"] = tool_name

                # Add to results
                results.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": result
                })

                # Update self.scan_results for Phase 3
                self.scan_results = results

                if result.get("success"):
                    print(f"    ✅ Detected services on {len(batch)} hosts")
                else:
                    print(f"    ⚠️  {result.get('error', 'Unknown error')}")

            except Exception as e:
                print(f"    ❌ Error: {e}")
                results.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": {"success": False, "error": str(e)}
                })

        print(f"\n  ✅ Phase 2 complete: Detailed analysis on {len(hosts_with_ports)} hosts")

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
                # Suppress SSL verification warnings for scraping
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                response = requests.get(f"https://{domain}", timeout=10, verify=False)
                
                if has_bs4:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    homepage_text = soup.get_text(separator=' ', strip=True)[:2000]
                else:
                    # Regex fallback (works fine without bs4)
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
        
        # Log phase start for audit trail
        if self.audit_logger:
            self.audit_logger.log_event('phase_start', {'phase': 'phase1_tool_selection', 'user_prompt': user_prompt})

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
                
                # Initialize audit logging for crash recovery
                from audit.logger import create_audit_logger, SessionMetrics
                from orchestration.queue_manager import create_exploit_queue
                
                try:
                    self.audit_logger = create_audit_logger(
                        session_id=session.id,
                        target=target or "unknown"
                    )
                    self.metrics = SessionMetrics(self.audit_logger)
                    
                    # Initialize exploit queue (multi-phase orchestration)
                    if self.audit_logger:
                        # Fix: Pass session_id (str) not audit_logger object
                        self.exploit_queue = create_exploit_queue(
                            session_id=session.id,
                            audit_log_dir=str(self.audit_logger.output_dir)
                        )
                    
                    print(f"  📋 Audit logging enabled: {self.audit_logger.session_dir}")
                except Exception as audit_err:
                    print(f"  ⚠️  Audit logger failed (non-critical): {audit_err}")
                    
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
                
                # Add justification for Phase 1 validation
                for tool in selected_tools:
                    tool_name = tool['name']
                    if 'justification' not in tool:
                        if 'amass' in tool_name:
                            tool['justification'] = "Comprehensive subdomain enumeration using OWASP Amass"
                        elif 'bbot' in tool_name:
                            tool['justification'] = "Advanced subdomain discovery using BBOT framework"
                        else:
                            tool['justification'] = f"Subdomain enumeration for {domain}"
                    
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
                
                # Add justification for Phase 1 validation
                for tool in selected_tools:
                    if 'justification' not in tool:
                        if 'vuln_scan' in tool['name']:
                            tool['justification'] = "Nmap vulnerability scan with NSE scripts for CVE detection"
                        elif 'shodan' in tool['name']:
                            tool['justification'] = "OSINT enrichment with Shodan for CVE intelligence"
                        else:
                            tool['justification'] = f"Vulnerability assessment for {target}"
                
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
                
                # Add justification for Phase 1 validation
                for tool in selected_tools:
                    if 'justification' not in tool:
                        tool['justification'] = "Ultra-fast port scanner for high-speed network discovery"
                
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
                
                # Add justification to each tool for Phase 1 validation
                for tool in selected_tools:
                    if 'justification' not in tool:
                        # Generate justification based on tool name
                        tool_name = tool['name']
                        if 'service_detection' in tool_name:
                            tool['justification'] = "Scans top 1000 ports with service/version detection for comprehensive analysis"
                        elif 'quick_scan' in tool_name:
                            tool['justification'] = "Quick scan of top 100 most common ports"
                        elif 'fast_scan' in tool_name:
                            tool['justification'] = "Fast scan optimized for speed"
                        elif 'all_ports' in tool_name:
                            tool['justification'] = "Full port scan of all 65,535 ports (user explicitly requested)"
                        elif 'shodan' in tool_name:
                            tool['justification'] = "OSINT enrichment with Shodan threat intelligence"
                        else:
                            tool['justification'] = f"Selected based on keyword detection for {user_prompt[:50]}"
                    
                    print(f"  ✓ Selected: {tool['name']}")
                    
                # Log phase 1 completion
                if self.audit_logger:
                    self.audit_logger.log_event('phase_end', {
                        'phase': 'phase1_tool_selection',
                        'success': True,
                        'tools_selected': [t['name'] for t in selected_tools]
                    })
                    
                return selected_tools, reasoning

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
        
        # Parse reasoning to extract per-tool justifications
        # Expected format: "1. tool_name - justification text"
        tool_justifications = {}
        if reasoning:
            import re
            # Try to extract numbered justifications (e.g., "1. nmap_service_detection - ...")
            pattern = r'(\d+)\.\s*([a-z_]+)\s*[-:]\s*([^\n]+)'
            matches = re.findall(pattern, reasoning, re.IGNORECASE)
            for num, tool_name, justification in matches:
                tool_justifications[tool_name.lower()] = justification.strip()
        
        for call in tool_calls:
            tool_name = call.get("function", {}).get("name")
            tool_info = {
                "name": tool_name,
                "arguments": call.get("function", {}).get("arguments", {})
            }
            
            # Add justification from parsed reasoning
            if tool_name and tool_name.lower() in tool_justifications:
                tool_info["justification"] = tool_justifications[tool_name.lower()]
            else:
                # Fallback: use generic reasoning or extract from full reasoning
                tool_info["justification"] = reasoning[:200] if reasoning else f"Selected for {user_prompt[:50]}"
            
            selected_tools.append(tool_info)
            print(f"  ✓ Selected: {tool_info['name']}")

        # FALLBACK VALIDATION: Check if LLM selection is valid or needs override
        from intent_mapper import IntentMapper

        # Check if we should use fallback instead of LLM selection
        should_use_fallback = IntentMapper.should_use_fallback(selected_tools, user_prompt)

        if should_use_fallback:
            print("  ⚠️  LLM tool selection needs override - using intent-based fallback")

            # Extract target from prompt
            target = self._extract_target_from_prompt(user_prompt)
            if not target:
                target = IntentMapper.extract_target(user_prompt)

            if target:
                # Get fallback tools from intent mapper
                fallback_tools, fallback_reasoning = IntentMapper.get_fallback_tools(
                    user_prompt, target
                )

                if fallback_tools:
                    # Check for 4-stage workflow special case
                    if fallback_tools[0].get("name") == "_4stage_workflow":
                        # Use the existing 4-stage workflow logic
                        subdomains = fallback_tools[0]["arguments"].get("subdomains", [])
                        selected_tools = self._get_intelligent_port_scan_strategy(subdomains)
                        reasoning = fallback_reasoning
                        print(f"  ✓ Fallback: Using 4-stage workflow for {len(subdomains)} subdomains")
                    else:
                        selected_tools = fallback_tools
                        reasoning = fallback_reasoning
                        print(f"  ✓ Fallback: {fallback_reasoning}")

                        for tool in selected_tools:
                            print(f"  ✓ Selected: {tool['name']}")

        # SAFETY FILTER: Block forbidden tools for "full assessment" requests
        full_assessment_keywords = ['full assessment', 'comprehensive scan', 'complete scan', 'full scan']
        is_full_assessment = any(keyword in user_prompt.lower() for keyword in full_assessment_keywords)
        
        if is_full_assessment:
            forbidden_tools = ['nmap_all_ports', 'nmap_comprehensive_scan']
            filtered_tools = []
            replaced_tools = []
            
            for tool in selected_tools:
                if tool['name'] in forbidden_tools:
                    # Replace with smart alternative
                    print(f"  ⚠️  BLOCKED: {tool['name']} (forbidden for 'full assessment' - would timeout)")
                    print(f"  ✅ AUTO-REPLACING with nmap_service_detection (top 1000 ports, 5-10 min)")
                    
                    smart_tool = {
                        "name": "nmap_service_detection",
                        "arguments": tool['arguments'],
                        "justification": f"Replaced {tool['name']} with smart alternative - service detection scans top 1000 ports with version info, perfect for full assessment without timeout"
                    }
                    filtered_tools.append(smart_tool)
                    replaced_tools.append(tool['name'])
                else:
                    filtered_tools.append(tool)
            
            if replaced_tools:
                selected_tools = filtered_tools
                reasoning = f"[AUTO-CORRECTED] Original selection included forbidden tools ({', '.join(replaced_tools)}) which would timeout. Replaced with nmap_service_detection. " + reasoning

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
        
        # Log phase start
        if self.audit_logger:
            self.audit_logger.log_event('phase_start', {
                'phase': 'phase2_execution',
                'tools_count': len(selected_tools)
            })

        # Update session phase
        if self.session_manager and self.db_session_id:
            try:
                self.session_manager.update_phase(self.db_session_id, 2, selected_tools)
            except Exception:
                pass

        results = []


        for i, tool_info in enumerate(selected_tools, 1):
            tool_name = tool_info['name']
            tool_args = tool_info.get('arguments', {})
            
            # Log tool start
            if self.audit_logger:
                self.audit_logger.log_event('tool_start', {
                    'tool': tool_name,
                    'args': tool_args
                })
                self.metrics.start_timer(f'tool_{tool_name}')

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

                # Log tool completion
                if self.audit_logger:
                    tool_elapsed = self.metrics.end_timer(f'tool_{tool_name}')
                    self.audit_logger.log_event('tool_end', {
                        'tool': tool_name,
                        'success': result.get('success', False),
                        'elapsed_seconds': tool_elapsed
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

        # TWO-PHASE SCANNING: Check if we need Phase 2 (detailed nmap scan)
        self._execute_phase2_if_needed(results, selected_tools)

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

        # AUTO NMAP FOLLOW-UP: Check for Naabu results and trigger service detection
        naabu_scan_executed = False
        naabu_results_found = False

        for scan_result in results:
            if "naabu" in scan_result["tool"].lower():
                naabu_scan_executed = True
                naabu_data = scan_result["result"]

                if naabu_data.get("success"):
                    # Extract targets with open ports
                    naabu_results = naabu_data.get("results", {})
                    targets_with_ports = []

                    for ip, port_list in naabu_results.items():
                        if port_list and len(port_list) > 0:
                            targets_with_ports.append(ip)

                    if targets_with_ports:
                        naabu_results_found = True
                        print(f"\n  📊 Naabu discovered {len(targets_with_ports)} hosts with open ports")
                        print(f"  🔍 Triggering automatic Nmap service detection...")

                        # Limit to 50 hosts to avoid timeout
                        targets_to_scan = targets_with_ports[:50]

                        if len(targets_with_ports) > 50:
                            print(f"  ⚠️  Limiting Nmap to top 50 hosts (found {len(targets_with_ports)} total)")

                        # Run Nmap service detection
                        try:
                            nmap_result = execute_tool("nmap_service_detection", {
                                "target": ",".join(targets_to_scan),
                                "timeout": 900  # 15 minutes for service detection
                            })

                            # Append to results for Phase 3 analysis
                            results.append({
                                "tool": "nmap_service_detection_followup",
                                "args": {"target": ",".join(targets_to_scan)},
                                "result": nmap_result
                            })

                            if nmap_result.get("success"):
                                print(f"  ✅ Nmap service detection completed")
                            else:
                                print(f"  ⚠️  Nmap service detection failed: {nmap_result.get('error', 'unknown')}")

                        except Exception as e:
                            print(f"  ⚠️  Nmap follow-up error: {e}")

        # Only show message if Naabu was actually executed
        if naabu_scan_executed and not naabu_results_found:
            print("  ℹ️  No Naabu results to follow up on")

        # AUTO PORT SCAN SUGGESTION: After subdomain enumeration, offer to scan discovered subdomains
        subdomain_scan_executed = False
        discovered_subdomains = []

        for scan_result in results:
            tool = scan_result.get("tool", "")
            if "subdomain" in tool.lower() or "amass" in tool.lower() or "bbot" in tool.lower():
                subdomain_scan_executed = True
                subdomain_data = scan_result.get("result", {})
                
                if subdomain_data.get("success"):
                    subdomains = subdomain_data.get("subdomains", [])
                    discovered_subdomains.extend(subdomains)
        
        # Remove duplicates
        discovered_subdomains = sorted(set(discovered_subdomains))
        
        if subdomain_scan_executed and discovered_subdomains:
            print(f"\n  🎯 Subdomain enumeration completed: {len(discovered_subdomains)} subdomains discovered")
            print(f"  💡 SUGGESTION: Check which subdomains have open ports")
            print(f"\n  📝 Try these commands:")
            
            if len(discovered_subdomains) >= 10:
                print(f"     • \"Use masscan to scan those {len(discovered_subdomains)} subdomains for open ports\"")
                print(f"     • \"Scan web ports on those subdomains\"")
                print(f"     • \"Check which subdomains have active web services\"")
            else:
                print(f"     • \"Scan those subdomains for open ports\"")
                print(f"     • \"Check which subdomains are alive\"")
            
            print(f"\n  ℹ️  You can scan these subdomains by referencing 'those subdomains' or 'these subdomains'")

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

        # Check for naabu tools
        naabu_tools = ["naabu_scan", "naabu_batch_scan", "naabu_port_scan"]
        if any(tool in tools_used for tool in naabu_tools):
            return "naabu"

        # Check for port scan tools
        port_scan_tools = ["nmap_quick_scan", "nmap_fast_scan", "nmap_port_scan",
                          "nmap_all_ports", "nmap_service_detection", "nmap_aggressive_scan",
                          "nmap_stealth_scan", "nmap_comprehensive_scan", "nmap_stealth_batch_scan"]
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

        # EARLY FAILURE DETECTION: Check if all scans failed before calling LLM
        # This prevents generating generic "I'd be happy to help" responses
        def has_actual_results(scan_result: Dict) -> bool:
            """Check if scan result contains actual usable data"""
            result = scan_result.get("result", {})
            
            # Check success flag
            if not result.get("success"):
                return False
            
            # Check for actual data in different scan types
            tool = scan_result.get("tool", "")
            
            # Subdomain scans
            if "subdomain" in tool.lower() or "bbot" in tool.lower() or "amass" in tool.lower():
                subdomains = result.get("subdomains", [])
                return len(subdomains) > 0
            
            # Port scans (nmap, masscan, naabu)
            if "nmap" in tool.lower():
                # Check multiple possible result formats
                open_ports = result.get("open_ports_count", 0)
                hosts = result.get("hosts_discovered", 0)
                total_ports = result.get("total_open_ports", 0)
                return open_ports > 0 or hosts > 0 or total_ports > 0
            
            if "masscan" in tool.lower():
                total_ports = result.get("total_open_ports", 0)
                results_dict = result.get("results", {})
                return total_ports > 0 or len(results_dict) > 0
            
            if "naabu" in tool.lower():
                total_ports = result.get("total_open_ports", 0)
                results_dict = result.get("results", {})
                return total_ports > 0 or len(results_dict) > 0
            
            # Shodan scans
            if "shodan" in tool.lower():
                data = result.get("data", {})
                return data and len(data) > 0
            
            # Default: assume success means we have data
            return True
        
        # Check if we have ANY successful scans with actual results
        successful_scans_with_data = [
            r for r in scan_results 
            if has_actual_results(r)
        ]
        
        if not successful_scans_with_data:
            # ALL SCANS FAILED - Generate failure report instead of calling LLM
            print("  ⚠️  All scans failed or returned no data")
            print("  📋 Generating failure report with diagnostics...")
            
            from prompts import generate_failure_report
            failure_report = generate_failure_report(scan_results)
            
            # Save to database if available
            if self.session_manager and self.db_session_id:
                try:
                    self.session_manager.set_analysis_results(
                        self.db_session_id,
                        {"analysis": failure_report[:5000]},
                        0,  # risk_score = 0 for failed scans
                        "UNKNOWN"  # risk_level unknown
                    )
                except Exception:
                    pass
            
            return failure_report
        
        # Continue with normal analysis if we have data...
        print(f"  ✅ {len(successful_scans_with_data)}/{len(scan_results)} scans have usable data")


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

            # For Nmap stealth batch scan - treat like masscan/naabu (batch format)
            if r["tool"] == "nmap_stealth_batch_scan":
                # Copy all batch scan data directly
                tool_result["targets_count"] = result.get("targets_count", 0)
                tool_result["results"] = result.get("results", {})
                tool_result["hostname_to_ip"] = result.get("hostname_to_ip", {})
                tool_result["targets_with_open_ports"] = result.get("targets_with_open_ports", 0)
                tool_result["total_open_ports"] = result.get("total_open_ports", 0)
                tool_result["scan_duration"] = result.get("scan_duration", 0)
                tool_result["scan_rate"] = result.get("scan_rate", 0)
                tool_result["ports_scanned"] = result.get("ports_scanned", "unknown")
                tool_result["timing"] = result.get("timing", "unknown")

            # For Nmap scans - include everything
            elif "nmap" in r["tool"].lower():
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

            # For Naabu - include complete results (similar to masscan)
            elif "naabu" in r["tool"].lower():
                naabu_result = result
                tool_result["naabu_data"] = {
                    "targets": naabu_result.get("targets", []),
                    "targets_count": len(naabu_result.get("targets", [])),
                    "results": naabu_result.get("results", {}),  # {IP: [ports]}
                    "hostname_to_ip": naabu_result.get("hostname_to_ip", {}),  # {hostname: IP} mapping
                    "total_hosts_scanned": naabu_result.get("total_hosts_scanned", 0),
                    "targets_with_open_ports": naabu_result.get("hosts_with_ports", 0),
                    "total_open_ports": naabu_result.get("total_open_ports", 0),
                    "scan_duration": naabu_result.get("elapsed_seconds", 0),
                    "scan_rate": naabu_result.get("scan_rate", 1000),
                    "ports_scanned": naabu_result.get("ports_scanned", "unknown"),
                    "success": naabu_result.get("success", True),
                    "error": naabu_result.get("error", None)
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

        # CVE ENRICHMENT: Extract and enrich CVEs from scan results
        try:
            from utils.cve_utils import extract_cves_from_scan_results, summarize_cve_severity

            cve_summary = extract_cves_from_scan_results(scan_results)
            cve_stats = summarize_cve_severity(cve_summary["total_unique"])

            # Enrich CVEs with OSV + ExploitDB
            if cve_summary["total_unique"]:
                from services.cve_sync_service import CVESyncService

                syncer = CVESyncService()
                cve_enrichment = syncer.enrich_found_cves(cve_summary["total_unique"])

                # Add enriched data to LLM context
                db_context["cve_details"] = {
                    cve_id: {
                        "cvss_score": data.get("cvss_v3_score"),
                        "severity": data.get("cvss_v3_severity"),
                        "description": data.get("description", "")[:200],
                        "exploit_available": data.get("exploit_available", False),
                        "exploit_count": data.get("exploit_count", 0),
                        "has_metasploit": data.get("has_metasploit", False),
                        "affected_packages": data.get("affected_packages", [])
                    }
                    for cve_id, data in cve_enrichment.items()
                }

                # Calculate risk score based on CVEs
                critical_cves = [cve for cve, data in cve_enrichment.items()
                                if data.get("cvss_v3_score", 0) >= 9.0]
                high_cves = [cve for cve, data in cve_enrichment.items()
                            if 7.0 <= data.get("cvss_v3_score", 0) < 9.0]
                exploitable_cves = [cve for cve, data in cve_enrichment.items()
                                    if data.get("exploit_available", False)]

                print(f"  🚨 {len(critical_cves)} CRITICAL, {len(high_cves)} HIGH severity CVEs")
                print(f"  💣 {len(exploitable_cves)} CVEs have PUBLIC EXPLOITS")

                # Cleanup
                syncer.close()
        except Exception as e:
            print(f"  ⚠️  CVE enrichment error: {e}")

        # Detect scan type for appropriate report format
        scan_type = self._detect_scan_type(scan_results)
        print(f"  📋 Report format: {scan_type}")

        # NEW FLOW: Generate and store programmatic report FIRST
        # This ensures we have structured data before LLM analysis
        programmatic_report_id, programmatic_report_content = self._generate_and_store_programmatic_report(
            scan_results, scan_type
        )

        # SPECIAL HANDLING: Check if masscan found zero results
        # Generate report programmatically instead of relying on LLM
        if scan_type == "masscan":
            # Extract masscan data from results
            masscan_data = None
            for r in results_for_llm:
                if r.get("tool", "").startswith("masscan") and "masscan_data" in r:
                    masscan_data = r["masscan_data"]
                    # Extract the results and hostname mapping for report generation
                    results = masscan_data.get("results", {})
                    hostname_to_ip = masscan_data.get("hostname_to_ip", {})
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

            # ELSE: Masscan found open ports - generate detailed per-domain report
            if masscan_data and masscan_data.get("total_open_ports", 0) > 0:
                print("  📊 Masscan found open ports - generating detailed report")
                # Build per-domain report
                analysis = f"""## SCAN SUMMARY

**Targets Scanned:** {len(masscan_data.get('targets', []))}
**Unique IPs:** {len(results)}
**Total Open Ports Found:** {masscan_data.get('total_open_ports', 0)}
**Targets with Open Ports:** {masscan_data.get('targets_with_open_ports', 0)}
**Ports Scanned:** {masscan_data.get('ports_scanned', 'N/A')}
**Scan Duration:** {masscan_data.get('scan_duration', 0):.1f} seconds

---

## DOMAIN-BY-DOMAIN FINDINGS

"""
                
                # Critical services to flag
                critical_ports = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 3389: "RDP", 445: "SMB"}
                high_risk_ports = {22: "SSH", 21: "FTP", 25: "SMTP", 23: "Telnet"}
                web_ports = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
                
                critical_findings = []
                high_risk_findings = []
                web_services = []
                
                # Process each domain
                for domain, ip in sorted(hostname_to_ip.items()):
                    if ip in results and results[ip]:
                        ports_data = results[ip]
                        port_numbers = sorted([p["port"] for p in ports_data])
                        
                        analysis += f"\n### **{domain}** (`{ip}`)\n\n"
                        
                        # Categorize ports
                        critical_on_host = []
                        high_risk_on_host = []
                        web_on_host = []
                        other_ports = []
                        
                        for port_num in port_numbers:
                            if port_num in critical_ports:
                                critical_on_host.append(f"{port_num}/{critical_ports[port_num]}")
                            elif port_num in high_risk_ports:
                                high_risk_on_host.append(f"{port_num}/{high_risk_ports[port_num]}")
                            elif port_num in web_ports:
                                web_on_host.append(f"{port_num}/{web_ports[port_num]}")
                            else:
                                other_ports.append(str(port_num))
                        
                        # Display ports
                        analysis += f"**Open Ports:** {', '.join(map(str, port_numbers))}\n\n"
                        
                        # Risk assessment
                        if critical_on_host:
                            risk = "🚨 **CRITICAL**"
                            analysis += f"**Risk Level:** {risk}\n\n"
                            analysis += f"**Critical Services Exposed:**\n"
                            for svc in critical_on_host:
                                analysis += f"- {svc}\n"
                            critical_findings.append((domain, ip, critical_on_host))
                        elif high_risk_on_host:
                            risk = "⚠️ **HIGH**"
                            analysis += f"**Risk Level:** {risk}\n\n"
                            analysis += f"**High-Risk Services:**\n"
                            for svc in high_risk_on_host:
                                analysis += f"- {svc}\n"
                            high_risk_findings.append((domain, ip, high_risk_on_host))
                        elif web_on_host:
                            risk = "ℹ️ **MEDIUM**"
                            analysis += f"**Risk Level:** {risk}\n\n"
                            analysis += f"**Web Services:**\n"
                            for svc in web_on_host:
                                analysis += f"- {svc}\n"
                            web_services.append((domain, ip, web_on_host))
                        else:
                            risk = "ℹ️ **LOW**"
                            analysis += f"**Risk Level:** {risk}\n\n"
                        
                        analysis += "\n"
                
                # Summary sections
                if critical_findings:
                    analysis += f"\n---\n\n## 🚨 CRITICAL FINDINGS ({len(critical_findings)})\n\n"
                    analysis += "These services should NEVER be exposed to the internet:\n\n"
                    for domain, ip, services in critical_findings:
                        analysis += f"- **{domain}** (`{ip}`): {', '.join(services)}\n"
                
                if high_risk_findings:
                    analysis += f"\n---\n\n## ⚠️ HIGH-RISK FINDINGS ({len(high_risk_findings)})\n\n"
                    analysis += "These services should be carefully secured:\n\n"
                    for domain, ip, services in high_risk_findings:
                        analysis += f"- **{domain}** (`{ip}`): {', '.join(services)}\n"
                
                if web_services:
                    analysis += f"\n---\n\n## 🌐 WEB SERVICES ({len(web_services)})\n\n"
                    # Check for HTTP without HTTPS
                    http_only = []
                    for domain, ip, services in web_services:
                        has_https = any("443" in s for s in services)
                        has_http = any("80/" in s for s in services)
                        if has_http and not has_https:
                            http_only.append(domain)
                    
                    if http_only:
                        analysis += f"**⚠️ HTTP Only (No HTTPS):** {', '.join(http_only)}\n\n"
                
                # Recommendations
                analysis += "\n---\n\n## RECOMMENDATIONS\n\n"
                
                if critical_findings:
                    analysis += "### IMMEDIATE (Critical - 0-24h)\n\n"
                    analysis += "1. **Block Database Ports**: Firewall rules should block external access to MySQL (3306), PostgreSQL (5432), MSSQL (1433)\n"
                    analysis += "2. **Block RDP/SMB**: Remote Desktop (3389) and SMB (445) should NEVER be internet-facing\n"
                    analysis += "3. **Verify Business Justification**: If these services are intentional, implement VPN access instead\n\n"
                
                if high_risk_findings:
                    analysis += "### HIGH PRIORITY (1-7 days)\n\n"
                    analysis += "1. **Secure SSH Access**: Implement key-based auth, disable password login, use fail2ban\n"
                    analysis += "2. **Review FTP/SMTP**: Consider SFTP instead of FTP, verify SMTP has proper auth\n"
                    analysis += "3. **Monitor Access Logs**: Set up alerts for login attempts on these services\n\n"
                
                if http_only:
                    analysis += "### MEDIUM PRIORITY (7-30 days)\n\n"
                    analysis += "1. **Enable HTTPS**: Deploy SSL certificates for all HTTP-only sites\n"
                    analysis += "2. **Redirect HTTP to HTTPS**: Configure automatic redirection\n\n"
                
                analysis += "### NEXT STEPS\n\n"
                analysis += "1. **Detailed Scanning**: Run `nmap service detection` on critical/high-risk hosts for version info\n"
                analysis += "2. **Vulnerability Assessment**: Check for known CVEs in exposed services\n"
                analysis += "3. **Network Segmentation**: Review firewall rules and network architecture\n"
                analysis += "4. **Compliance Review**: Verify exposure aligns with PCI-DSS, HIPAA, or other compliance requirements\n"
                
                # Save to database
                if self.session_manager and self.db_session_id and enriched_context:
                    try:
                        # Calculate risk score based on findings
                        risk_score = min(100, len(critical_findings) * 40 + len(high_risk_findings) * 20)
                        risk_level = "CRITICAL" if critical_findings else ("HIGH" if high_risk_findings else "MEDIUM")
                        
                        self.session_manager.set_analysis_results(
                            self.db_session_id,
                            {"analysis": analysis[:10000]},  # Increased limit for detailed reports
                            risk_score,
                            risk_level
                        )
                    except Exception:
                        pass
                
                # HYBRID APPROACH: Use LLM as cyber analyst to review the programmatic report
                print(f"  🤖 LLM Cyber Analyst reviewing findings...")
                
                analyst_prompt = f"""You are a senior cybersecurity analyst reviewing a port scan report.

**YOUR TASK**: Provide strategic security insights and actionable recommendations based on the findings below.

# SCAN REPORT TO ANALYZE:

{analysis}

---

As a cyber analyst, provide:

1. **THREAT ASSESSMENT** 
   - What are the most critical security risks?
   - Which findings pose immediate threats?
   - What attack vectors are exposed?

2. **VULNERABILITY ANALYSIS**
   - Which services are most likely to be vulnerable?
   - What known exploits exist for the exposed services?
   - What CVEs should be checked?

3. **STRATEGIC RECOMMENDATIONS**
   - What should be prioritized first?
   - What additional scans or assessments are needed?
   - What security controls should be implemented?

4. **COMPLIANCE & BEST PRACTICES**
   - Any compliance violations (PCI-DSS, HIPAA, SOC2)?
   - Industry best practices being violated?
   - Recommended security frameworks to follow?

Be specific, actionable, and prioritize by risk level. Reference specific findings from the report."""

                llm_messages = [
                    {"role": "system", "content": "You are a senior cybersecurity analyst with expertise in penetration testing, vulnerability assessment, and security architecture."},
                    {"role": "user", "content": analyst_prompt}
                ]
                
                try:
                    llm_response = self._call_ollama(llm_messages, timeout=TIMEOUT_OLLAMA)
                    
                    if "error" not in llm_response:
                        llm_insights = llm_response.get("message", {}).get("content", "")
                        
                        if llm_insights and len(llm_insights.strip()) > 100:
                            # Append LLM insights to programmatic report
                            analysis += "\n\n---\n\n# 🧠 CYBER ANALYST INSIGHTS\n\n"
                            analysis += llm_insights
                            print(f"  ✅ Cyber analyst insights added ({len(llm_insights)} chars)")
                        else:
                            print(f"  ⚠️  Cyber analyst response too short, skipping")
                    else:
                        print(f"  ⚠️  Cyber analyst LLM error: {llm_response.get('error', 'unknown')}")
                except Exception as e:
                    print(f"  ⚠️  Cyber analyst failed: {e}")

                return analysis


        # NAABU PORT SCAN: Generate programmatic report (like Masscan)
        if scan_type == "naabu":
            # Extract naabu data from results
            naabu_data = None
            targets_scanned = 0

            for r in results_for_llm:
                if "naabu" in r.get("tool", "").lower() and "naabu_data" in r:
                    naabu_data = r["naabu_data"]
                    targets_scanned = naabu_data.get("targets_count", 0)
                    break

            # Generate programmatic report
            if naabu_data:
                print(f"  📊 Generating programmatic Naabu report for {targets_scanned} targets")
                analysis = self._generate_naabu_report(naabu_data, targets_scanned, tool_name="naabu")
                return analysis
            else:
                # Fallback for edge cases
                print(f"  ⚠️  No Naabu data available to generate report")
                analysis = "## NAABU SCAN REPORT\n\n"
                analysis += "⚠️  No Naabu scan data found in results.\n\n"
                analysis += "This could indicate:\n"
                analysis += "- Scan did not execute properly\n"
                analysis += "- Data extraction error\n"
                analysis += "- Tool execution failed silently\n\n"
                analysis += "**Recommendation:** Check Phase 2 execution logs for errors.\n"
                return analysis


        # NMAP PORT SCAN: Disabled programmatic report - let LLM analyze for contextual insights
        # User prefers LLM analysis similar to subdomain discovery reports
        if scan_type == "port_scan":
            # Check if it's a batch scan (nmap_stealth_batch_scan)
            # batch_scan_data = None
            # for r in results_for_llm:
            #     if r.get("tool", "") == "nmap_stealth_batch_scan":
            #         batch_scan_data = r
            #         break

            # # If batch scan, use the programmatic batch report (like naabu)
            # if batch_scan_data:
            #     print(f"  📊 Generating programmatic Nmap batch scan report")
            #
            #     # Get target count - try multiple sources for accuracy
            #     targets_scanned = (
            #         len(batch_scan_data.get("targets", [])) or  # Try actual target list first
            #         batch_scan_data.get("targets_count", 0) or  # Then the count field
            #         batch_scan_data.get("total_hosts_scanned", 0) or # Alternative field name
            #         0
            #     )
            #
            #     # DEBUG: Print what we actually have
            #     print(f"  🔍 DEBUG: targets_scanned = {targets_scanned} (from targets list)")
            #     print(f"  🔍 DEBUG: total_open_ports = {batch_scan_data.get('total_open_ports', 0)}")
            #     print(f"  🔍 DEBUG: batch_scan_data keys = {list(batch_scan_data.keys())}")
            #
            #     # Reuse the n aabu report generator (compatible format)
            #     analysis = self._generate_naabu_report(batch_scan_data, targets_scanned, tool_name="nmap_stealth_batch_scan")
            #     return analysis
            pass  # Let LLM handle port scan analysis

            # Extract traditional single-target nmap data
            nmap_data = None
            for r in results_for_llm:
                if "nmap" in r.get("tool", "").lower() and (r.get("open_ports") or r.get("scan_summary")):
                    nmap_data = r
                    break

            if nmap_data:
                print(f"  📊 Generating structured Nmap port scan report")

                target = nmap_data.get("target", "Unknown")
                command = nmap_data.get("command", "N/A")
                open_ports = nmap_data.get("open_ports", [])
                services = nmap_data.get("services", [])
                hosts_discovered = nmap_data.get("hosts_discovered", 0)

                # Initialize findings lists (needed even if no ports found)
                # MUST be defined here to avoid UnboundLocalError
                critical_findings = []
                high_risk_findings = []
                web_findings = []
                other_findings = []

                # Define port categorization dicts upfront (needed for analysis later)
                critical_ports_dict = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 3389: "RDP", 445: "SMB", 139: "NetBIOS"}
                high_risk_ports_dict = {22: "SSH", 21: "FTP", 23: "Telnet", 25: "SMTP", 161: "SNMP"}
                web_ports_dict = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8000: "HTTP-Alt", 8888: "HTTP-Alt"}

                # Build report
                analysis = f"""## SCAN SUMMARY

**Target:** {target}
**Hosts Discovered:** {hosts_discovered}
**Total Open Ports:** {len(open_ports)}
**Scan Command:** `{command}`

---

## OPEN PORTS

"""

                if not open_ports:
                    analysis += "**No open ports detected.**\n\n"
                    analysis += "This could indicate:\n"
                    analysis += "- Host is down or unreachable\n"
                    analysis += "- All ports are filtered by firewall\n"
                    analysis += "- Host is configured to not respond to scans\n"
                else:
                    # Categorize ports
                    for port_info in open_ports:
                        port_num = port_info.get("port", 0)
                        service = port_info.get("service", "unknown")
                        state = port_info.get("state", "unknown")

                        if state == "open":
                            if port_num in critical_ports_dict:
                                critical_findings.append((port_num, service, critical_ports_dict[port_num]))
                            elif port_num in high_risk_ports_dict:
                                high_risk_findings.append((port_num, service, high_risk_ports_dict[port_num]))
                            elif port_num in web_ports_dict:
                                web_findings.append((port_num, service, web_ports_dict[port_num]))
                            else:
                                other_findings.append((port_num, service))
                    
                    # Display ports by category
                    if critical_findings:
                        analysis += f"### 🚨 **CRITICAL** ({len(critical_findings)} ports)\n\n"
                        analysis += "These services should NEVER be exposed to the internet:\n\n"
                        analysis += "| Port | State | Service | Risk |\n"
                        analysis += "|------|-------|---------|------|\n"
                        for port, service, svc_name in critical_findings:
                            analysis += f"| {port}/tcp | open | {service} | {svc_name} - CRITICAL |\n"
                        analysis += "\n"
                    
                    if high_risk_findings:
                        analysis += f"### ⚠️ **HIGH RISK** ({len(high_risk_findings)} ports)\n\n"
                        analysis += "These services require strong security controls:\n\n"
                        analysis += "| Port | State | Service | Risk |\n"
                        analysis += "|------|-------|---------|------|\n"
                        for port, service, svc_name in high_risk_findings:
                            analysis += f"| {port}/tcp | open | {service} | {svc_name} - HIGH |\n"
                        analysis += "\n"
                    
                    if web_findings:
                        analysis += f"### 🌐 **WEB SERVICES** ({len(web_findings)} ports)\n\n"
                        analysis += "| Port | State | Service | Protocol |\n"
                        analysis += "|------|-------|---------|----------|\n"
                        for port, service, svc_name in web_findings:
                            analysis += f"| {port}/tcp | open | {service} | {svc_name} |\n"
                        analysis += "\n"
                        
                        # Check for HTTP without HTTPS
                        has_http = any(p[0] in [80, 8080, 8000, 8888] for p in web_findings)
                        has_https = any(p[0] in [443, 8443] for p in web_findings)
                        if has_http and not has_https:
                            analysis += "⚠️ **WARNING**: HTTP detected without HTTPS - unencrypted traffic\n\n"
                    
                    if other_findings:
                        analysis += f"### ℹ️ **OTHER OPEN PORTS** ({len(other_findings)} ports)\n\n"
                        analysis += "| Port | State | Service |\n"
                        analysis += "|------|-------|--------|\n"
                        for port, service in other_findings:
                            analysis += f"| {port}/tcp | open | {service} |\n"
                        analysis += "\n"
                
                # Recommendations
                analysis += "\n---\n\n## RECOMMENDATIONS\n\n"
                
                if critical_findings:
                    analysis += "### IMMEDIATE (0-24h)\n\n"
                    analysis += "1. **Block Critical Services**: Immediately firewall block "
                    analysis += ", ".join([f"port {p[0]}" for p in critical_findings])
                    analysis += "\n2. **Verify Necessity**: Confirm if these services require internet exposure\n"
                    analysis += "3. **Implement VPN**: Use VPN access instead of direct exposure\n\n"
                
                if high_risk_findings:
                    analysis += "### SHORT-TERM (1-7 days)\n\n"
                    for port, _, svc_name in high_risk_findings:
                        if svc_name == "SSH":
                            analysis += f"1. **SSH (port {port})**: Use key-based auth, disable password login, enable fail2ban\n"
                        elif svc_name == "FTP":
                            analysis += f"2. **FTP (port {port})**: Replace with SFTP or FTPS\n"
                        elif svc_name == "Telnet":
                            analysis += f"3. **Telnet (port {port})**: DISABLE immediately - use SSH instead\n"
                    analysis += "\n"
                
                if web_findings:
                    has_http = any(p[0] in [80, 8080] for p in web_findings)
                    has_https = any(p[0] in [443, 8443] for p in web_findings)
                    if has_http:
                        if not has_https:
                            if not high_risk_findings and not critical_findings:
                                analysis += "### SHORT-TERM (1-7 days)\n\n"
                            analysis += "4. **Enable HTTPS**: Deploy SSL/TLS certificates\n"
                            analysis += "5. **Redirect HTTP to HTTPS**: Configure automatic redirection\n\n"
                
                analysis += "### NEXT STEPS\n\n"
                analysis += "1. **Service Version Detection**: Run `nmap -sV` to identify software versions\n"
                analysis += "2. **Vulnerability Scan**: Run `nmap --script vuln` to check for known vulnerabilities\n"
                analysis += "3. **OS Detection**: Run `nmap -O` for operating system fingerprinting\n"
                analysis += "4. **Threat Intelligence**: Use Shodan to check for known exposures\n"
                
                # Calculate risk score
                if self.session_manager and self.db_session_id and enriched_context:
                    try:
                        risk_score = min(100, len(critical_findings) * 50 + len(high_risk_findings) * 25 + len(web_findings) * 10)
                        risk_level = "CRITICAL" if critical_findings else ("HIGH" if high_risk_findings else "MEDIUM")
                        
                        self.session_manager.set_analysis_results(
                            self.db_session_id,
                            {"analysis": analysis[:10000]},
                            risk_score,
                            risk_level
                        )
                    except Exception:
                        pass
                
                # HYBRID APPROACH: Use LLM as cyber analyst
                print(f"  🤖 LLM Cyber Analyst reviewing Nmap findings...")
                
                analyst_prompt = f"""You are a senior cybersecurity analyst reviewing an Nmap port scan report.

**YOUR TASK**: Provide expert security analysis based on the findings below.

# SCAN REPORT TO ANALYZE:

{analysis}

---

As a cyber analyst, provide:

1. **THREAT ASSESSMENT**: What are the immediate security risks and attack vectors?
2. **VULNERABILITY ANALYSIS**: Which services are likely vulnerable? What CVEs to check?
3. **STRATEGIC RECOMMENDATIONS**: What actions should be prioritized?
4. **NEXT STEPS**: What additional scans or security assessments are needed?

Be specific and reference exact findings from the report."""

                llm_messages = [
                    {"role": "system", "content": "You are a senior cybersecurity analyst specializing in network security and vulnerability assessment."},
                    {"role": "user", "content": analyst_prompt}
                ]
                
                try:
                    llm_response = self._call_ollama(llm_messages, timeout=TIMEOUT_OLLAMA)
                    
                    if "error" not in llm_response:
                        llm_insights = llm_response.get("message", {}).get("content", "")
                        
                        if llm_insights and len(llm_insights.strip()) > 100:
                            analysis += "\n\n---\n\n# 🧠 CYBER ANALYST INSIGHTS\n\n"
                            analysis += llm_insights
                            print(f"  ✅ Cyber analyst insights added")
                except Exception as e:
                    print(f"  ⚠️  Cyber analyst failed: {e}")
                
                return analysis


        # NMAP VULN SCAN: Generate programmatic vulnerability report
        if scan_type == "vuln_scan":
            # Extract nmap vuln data
            nmap_data = None
            for r in results_for_llm:
                if "vuln" in r.get("tool", "").lower() and r.get("vulnerabilities"):
                    nmap_data = r
                    break
            
            if nmap_data:
                print(f"  📊 Generating structured vulnerability report")
                
                target = nmap_data.get("target", "Unknown")
                vulnerabilities = nmap_data.get("vulnerabilities", [])
                open_ports = nmap_data.get("open_ports", [])
                
                analysis = f"""## VULNERABILITY SCAN REPORT

**Target:** {target}
**Scan Type:** Nmap NSE Vulnerability Scripts
**Open Ports:** {len(open_ports)}
**Vulnerability Indicators Found:** {len(vulnerabilities)}

---

"""
                
                if not vulnerabilities:
                    analysis += "## RESULTS\n\n"
                    analysis += "✅ **No vulnerabilities detected by NSE scripts.**\n\n"
                    analysis += "**Note**: This does not guarantee the system is secure. It only means:\n"
                    analysis += "- No known vulnerabilities found in Nmap's script database\n"
                    analysis += "- Services may still have unpatched vulnerabilities\n"
                    analysis += "- Configuration issues may exist\n\n"
                else:
                    analysis += "## 🚨 VULNERABILITIES DETECTED\n\n"
                    
                    # Try to categorize vulnerabilities by severity
                    critical_vulns = []
                    high_vulns = []
                    other_vulns = []
                    
                    for vuln in vulnerabilities:
                        vuln_lower = vuln.lower()
                        if "critical" in vuln_lower or "rce" in vuln_lower or "remote code execution" in vuln_lower:
                            critical_vulns.append(vuln)
                        elif "high" in vuln_lower or "vulnerable" in vuln_lower:
                            high_vulns.append(vuln)
                        else:
                            other_vulns.append(vuln)
                    
                    if critical_vulns:
                        analysis += "### 🔴 CRITICAL SEVERITY\n\n"
                        for vuln in critical_vulns:
                            analysis += f"- {vuln}\n"
                        analysis += "\n"
                    
                    if high_vulns:
                        analysis += "### 🟠 HIGH SEVERITY\n\n"
                        for vuln in high_vulns:
                            analysis += f"- {vuln}\n"
                        analysis += "\n"
                    
                    if other_vulns:
                        analysis += "### ℹ️ OTHER FINDINGS\n\n"
                        for vuln in other_vulns:
                            analysis += f"- {vuln}\n"
                        analysis += "\n"
                
                analysis += "---\n\n## RECOMMENDATIONS\n\n"
                
                if critical_vulns:
                    analysis += "### IMMEDIATE (0-24h) - CRITICAL\n\n"
                    analysis += "1. **Patch Immediately**: Apply security updates for all critical vulnerabilities\n"
                    analysis += "2. **Isolate System**: Consider isolating the system until patches are applied\n"
                    analysis += "3. **Incident Response**: Activate incident response procedures\n\n"
                
                if high_vulns or critical_vulns:
                    analysis += "### SHORT-TERM (1-7 days)\n\n"
                    analysis += "1. **Verify Patches**: Confirm all security updates are applied successfully\n"
                    analysis += "2. **Scan Again**: Re-run vulnerability scan to verify fixes\n"
                    analysis += "3. **Review Logs**: Check for signs of exploitation\n\n"
                
                analysis += "### ONGOING\n\n"
                analysis += "1. **Regular Scanning**: Schedule monthly vulnerability scans\n"
                analysis += "2. **Patch Management**: Implement automated patch management\n"
                analysis += "3. **Security Monitoring**: Enable IDS/IPS and SIEM monitoring\n"
                analysis += "4. **Penetration Testing**: Conduct annual penetration tests\n"
                
                if self.session_manager and self.db_session_id and enriched_context:
                    try:
                        risk_score = min(100, len(critical_vulns) * 60 + len(high_vulns) * 30 + len(other_vulns) * 10)
                        risk_level = "CRITICAL" if critical_vulns else ("HIGH" if high_vulns else "MEDIUM")
                        
                        self.session_manager.set_analysis_results(
                            self.db_session_id,
                            {"analysis": analysis[:10000]},
                            risk_score,
                            risk_level
                        )
                    except Exception:
                        pass
                
                # HYBRID APPROACH: Use LLM as cyber analyst for vulnerability interpretation
                print(f"  🤖 LLM Cyber Analyst reviewing vulnerabilities...")
                
                analyst_prompt = f"""You are a senior cybersecurity analyst reviewing a vulnerability scan report.

**YOUR TASK**: Provide expert vulnerability analysis and remediation guidance.

# VULNERABILITY SCAN REPORT:

{analysis}

---

As a cyber analyst, provide:

1. **EXPLOIT RISK ASSESSMENT**: Which vulnerabilities are actively exploited in the wild?
2. **CVE ANALYSIS**: What are the CVSS scores and exploit complexity?
3. **ATTACK CHAIN**: How could these vulnerabilities be chained together?
4. **REMEDIATION ROADMAP**: Detailed, prioritized patching plan
5. **COMPENSATING CONTROLS**: What temporary mitigations can be implemented?

Be specific about CVEs, provide CVSS scores if known, and reference specific vulnerabilities."""

                llm_messages = [
                    {"role": "system", "content": "You are a senior vulnerability analyst with expertise in exploit development, CVE analysis, and security patching."},
                    {"role": "user", "content": analyst_prompt}
                ]
                
                try:
                    llm_response = self._call_ollama(llm_messages, timeout=TIMEOUT_OLLAMA)
                    
                    if "error" not in llm_response:
                        llm_insights = llm_response.get("message", {}).get("content", "")
                        
                        if llm_insights and len(llm_insights.strip()) > 100:
                            analysis += "\n\n---\n\n# 🧠 CYBER ANALYST INSIGHTS\n\n"
                            analysis += llm_insights
                            print(f"  ✅ Vulnerability analyst insights added")
                except Exception as e:
                    print(f"  ⚠️  Cyber analyst failed: {e}")
                
                return analysis


        # Retrieve programmatic report from database if it was generated
        # Retrieve programmatic report content if available
        if programmatic_report_content:
            print(f"  📄 Retrieved programmatic report ({len(programmatic_report_content)} chars)")
            analysis = programmatic_report_content
        elif programmatic_report_id:
            # Fallback: try to retrieve from DB if content missing but ID exists
            try:
                report = ProgrammaticReportService.get_report(programmatic_report_id)
                if report:
                    analysis = report.get("report_data", "")
                    print(f"  📄 Retrieved programmatic report from DB ({len(analysis)} chars)")
            except Exception:
                pass

        # If no programmatic report and no useful scan data, return failure report instead of calling LLM
        if not programmatic_report_content and scan_type == "generic":
            # Check if there's any actual data in results_for_llm
            has_useful_data = False
            for r in results_for_llm:
                # Check various data indicators
                if r.get("open_ports") or r.get("total_open_ports", 0) > 0 or r.get("hosts_discovered", 0) > 0:
                    has_useful_data = True
                    break
                if r.get("naabu_data", {}).get("total_open_ports", 0) > 0:
                    has_useful_data = True
                    break
                if r.get("masscan_data", {}).get("total_open_ports", 0) > 0:
                    has_useful_data = True
                    break

            if not has_useful_data:
                print(f"  ⚠️  No programmatic report and no scan data - using failure report")
                from prompts import generate_failure_report
                return generate_failure_report(scan_results)

        # Send COMPLETE scan data to LLM with programmatic report
        system_prompt = get_phase3_prompt(
            json.dumps(results_for_llm, indent=2),
            json.dumps(db_context, indent=2),
            scan_type=scan_type,
            programmatic_report=programmatic_report_content
        )

        # DEBUG: Check if programmatic report is in the prompt
        if programmatic_report_content:
            print(f"  🔍 DEBUG: Programmatic report passed to prompt: {len(programmatic_report_content)} chars")
            if "## SUBDOMAIN ENUMERATION REPORT" in programmatic_report_content:
                print(f"  🔍 DEBUG: ✅ Contains subdomain report header")
            if programmatic_report_content in system_prompt:
                print(f"  🔍 DEBUG: ✅ Programmatic report IS in system prompt")
            else:
                print(f"  🔍 DEBUG: ❌ Programmatic report NOT in system prompt!")
                print(f"  🔍 DEBUG: System prompt length: {len(system_prompt)}")

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Analyze the scan results and provide a comprehensive security report."}
        ]

        print("\n🔍 Analyzing results with enriched context (programmatic report + DB data)...")

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

        # VALIDATION: Validate LLM Phase 3 output for quality and accuracy
        print("\n  📋 Validating LLM response quality...")
        from response_validator import ResponseValidator

        try:
            is_valid, issues, quality_score = ResponseValidator.validate_phase3_output(
                analysis,
                programmatic_report_content or ""
            )

            # Print validation report
            validation_report = ResponseValidator.format_validation_report(is_valid, issues, quality_score)
            print(validation_report)

            # If quality is too low (grade D or F), warn user
            if quality_score.get("grade") in ["D", "F"]:
                print(f"  ⚠️  WARNING: Response quality is {quality_score['grade']} - consider reviewing manually")

            # If critical issues found, warn user
            critical_issues = [i for i in issues if "CRITICAL" in i]
            if critical_issues:
                print(f"  🚨 CRITICAL ISSUES DETECTED:")
                for issue in critical_issues:
                    print(f"     {issue}")

        except Exception as val_err:
            print(f"  ⚠️  Validation error (non-critical): {val_err}")

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

    # ========================================================================
    # NAABU REPORT GENERATION (Programmatic)
    # ========================================================================

    # Common port service mappings
    COMMON_PORTS = {
        21: ("FTP", "File Transfer Protocol"),
        22: ("SSH", "Secure Shell"),
        23: ("Telnet", "Unencrypted remote access"),
        25: ("SMTP", "Email server"),
        53: ("DNS", "Domain Name System"),
        80: ("HTTP", "Web server"),
        110: ("POP3", "Email retrieval"),
        143: ("IMAP", "Email retrieval"),
        443: ("HTTPS", "Secure web server"),
        445: ("SMB", "Windows file sharing"),
        1433: ("MSSQL", "Microsoft SQL Server"),
        3306: ("MySQL", "MySQL database server"),
        3389: ("RDP", "Remote Desktop Protocol"),
        5432: ("PostgreSQL", "PostgreSQL database"),
        5900: ("VNC", "Virtual Network Computing"),
        6379: ("Redis", "Redis cache/database"),
        8000: ("HTTP-Alt", "Alternative web server"),
        8080: ("HTTP-Proxy", "HTTP proxy/alternative"),
        8443: ("HTTPS-Alt", "Alternative HTTPS"),
        9200: ("Elasticsearch", "Elasticsearch database"),
        27017: ("MongoDB", "MongoDB NoSQL database"),
    }

    def _format_port_info(self, port: int) -> str:
        """Format port with service name and description"""
        if port in self.COMMON_PORTS:
            service, desc = self.COMMON_PORTS[port]
            return f"{port}/tcp - {service} - {desc}"
        else:
            return f"{port}/tcp - Unknown service"

    def _get_cve_data_for_target(self, target: str) -> Dict:
        """
        Retrieve CVE data for target from enriched context (Shodan scans)

        Args:
            target: Target hostname

        Returns:
            {"cves": [list of CVE IDs], "count": number of CVEs}
        """
        cves = []

        # Check enriched context from Shodan
        if hasattr(self, 'enriched_context') and self.enriched_context:
            threat_intel = self.enriched_context.get('threat_intel', {})
            for intel in threat_intel.values():
                if target in str(intel.get('target', '')):
                    cves.extend(intel.get('vulns', []))

        return {"cves": list(set(cves)), "count": len(set(cves))}

    def _generate_naabu_report(self, scan_data: Dict, targets_scanned: int, tool_name: str = "naabu") -> str:
        """
        Generate programmatic report for batch port scan results
        Compatible with both Naabu and Nmap stealth batch scans

        Args:
            scan_data: Scan result dict (from naabu_batch_scan or nmap_stealth_batch_scan)
            targets_scanned: Number of targets in scan
            tool_name: Name of the tool used ("naabu" or "nmap_stealth_batch_scan")

        Returns:
            Formatted report string
        """
        success = scan_data.get("success", False)
        error = scan_data.get("error")

        # Handle scan failure
        if not success:
            return self._generate_naabu_error_report(error, targets_scanned, tool_name)

        # Extract data
        results = scan_data.get("results", {})
        total_open_ports = scan_data.get("total_open_ports", 0)
        targets_with_ports = scan_data.get("targets_with_open_ports", 0)
        scan_duration = scan_data.get("scan_duration", 0)
        scan_rate = scan_data.get("scan_rate", 0)
        ports_scanned = scan_data.get("ports_scanned", "unknown")
        hostname_to_ip = scan_data.get("hostname_to_ip", {})

        # Handle zero results
        if total_open_ports == 0:
            return self._generate_naabu_zero_ports_report(targets_scanned, scan_duration, scan_rate, ports_scanned, tool_name)

        # Generate full report with results
        return self._generate_naabu_success_report(
            results, targets_scanned, total_open_ports, targets_with_ports,
            scan_duration, scan_rate, ports_scanned, tool_name
        )

    def _generate_naabu_error_report(self, error: str, targets_scanned: int, tool_name: str = "naabu") -> str:
        """Generate report for failed scan"""
        # Determine tool display name
        tool_display = "NMAP STEALTH" if "nmap" in tool_name.lower() else "NAABU"
        # Parse common errors and provide context
        error_explanations = {
            "invalid literal": "Port range parsing error - check port specification format",
            "timed out": "Scan exceeded time limit - consider reducing targets or increasing timeout",
            "not found": "Naabu tool not installed or not in PATH",
            "permission denied": "Insufficient permissions to run port scan",
        }

        explanation = next(
            (exp for pattern, exp in error_explanations.items() if pattern in str(error).lower()),
            "Unexpected error occurred"
        )

        return f"""
════════════════════════════════════════════════════════════
📋 {tool_display} PORT SCAN REPORT
════════════════════════════════════════════════════════════

## SCAN SUMMARY
- Targets: {targets_scanned} subdomains
- Status: ⚠️  FAILED

## ERROR
{error}

## TROUBLESHOOTING
{explanation}

Possible causes:
1. Tool configuration issue
2. Invalid scan parameters
3. Network/permissions problem

## RECOMMENDATIONS
- Check tool version: {'nmap --version' if 'nmap' in tool_name.lower() else 'naabu -version'}
- Verify port range syntax is correct
- Review scan arguments in Phase 1
- Check system permissions for port scanning
- Consult error message above for specific details

════════════════════════════════════════════════════════════
Session: {self.db_session_id or 'N/A'} | Type: Port Scan ({tool_display}) | Status: FAILED
════════════════════════════════════════════════════════════
"""

    def _generate_naabu_zero_ports_report(self, targets_scanned: int, scan_duration: float, scan_rate: int, ports_scanned: str, tool_name: str = "naabu") -> str:
        """Generate report when no open ports found"""
        tool_display = "NMAP STEALTH" if "nmap" in tool_name.lower() else "NAABU"
        duration_str = f"{int(scan_duration//60)}m {int(scan_duration%60)}s" if scan_duration else "N/A"

        return f"""
════════════════════════════════════════════════════════════
📋 {tool_display} PORT SCAN REPORT
════════════════════════════════════════════════════════════

## SCAN SUMMARY
- Targets scanned: {targets_scanned} subdomains
- Targets with open ports: 0 (0%)
- Total open ports found: 0
- Scan duration: {duration_str}
- Scan rate: {scan_rate} pps
- Port range: {ports_scanned}

## RESULT
✓ Scan completed successfully
✗ No open ports found on any target

## ANALYSIS
This could indicate:
1. All targets are properly firewalled
2. No services running on scanned ports ({ports_scanned})
3. Targets may be offline or non-responsive
4. DNS resolution may have failed for some targets
5. Network filtering blocking scan traffic

## RECOMMENDATIONS
- Verify targets are reachable (ping/ICMP check)
- Try comprehensive scan (1-65535) on high-priority targets
- Check if targets require specific source IP/VPN access
- Review DNS resolution for failed targets
- Consider slower scan rate if IDS/IPS may be blocking

════════════════════════════════════════════════════════════
Session: {self.db_session_id or 'N/A'} | Type: Port Scan ({tool_display}) | Time: {duration_str}
════════════════════════════════════════════════════════════
"""

    def _generate_naabu_success_report(self, results: Dict, targets_scanned: int,
                                      total_open_ports: int, targets_with_ports: int,
                                      scan_duration: float, scan_rate: int, ports_scanned: str,
                                      tool_name: str = "naabu") -> str:
        """Generate detailed report when open ports found"""
        tool_display = "NMAP STEALTH" if "nmap" in tool_name.lower() else "NAABU"
        duration_str = f"{int(scan_duration//60)}m {int(scan_duration%60)}s" if scan_duration else "N/A"
        percentage = round((targets_with_ports / targets_scanned * 100), 1) if targets_scanned > 0 else 0

        # Build port statistics
        port_counts = {}
        for target, ports in results.items():
            for port in ports:
                port_counts[port] = port_counts.get(port, 0) + 1

        # Sort by frequency
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # Start report
        report = f"""
════════════════════════════════════════════════════════════
📋 {tool_display} PORT SCAN REPORT
════════════════════════════════════════════════════════════

## SCAN SUMMARY
- Targets scanned: {targets_scanned} subdomains
- Targets with open ports: {targets_with_ports} ({percentage}%)
- Total open ports found: {total_open_ports}
- Scan duration: {duration_str}
- Scan rate: {scan_rate} pps
- Port range: {ports_scanned}

## DETAILED RESULTS

"""

        # Add per-target details (limit to first 50 for readability)
        targets_list = list(results.items())[:50]
        for target, ports in targets_list:
            port_count = len(ports)
            report += f"### {target}\n"
            report += f"**Open Ports ({port_count}):**\n"

            for port in sorted(ports):
                report += f"- {self._format_port_info(port)}\n"

            # Check for CVE data
            cve_data = self._get_cve_data_for_target(target)
            if cve_data["count"] > 0:
                report += f"\n**CVE Intelligence:**\n"
                for cve in cve_data["cves"][:3]:  # Limit to 3 CVEs
                    report += f"- {cve}\n"

            # Add security notes for concerning ports
            if 3306 in ports or 5432 in ports or 27017 in ports or 1433 in ports:
                report += f"\n**Security Alert:**\n"
                report += f"🚨 Database server exposed to internet!\n"
                report += f"   Immediate action required - restrict access or add firewall rules\n"
            elif 3389 in ports:
                report += f"\n**Security Alert:**\n"
                report += f"⚠️  RDP exposed - high risk of brute-force attacks\n"

            report += "\n"

        if len(results) > 50:
            report += f"[... and {len(results) - 50} more targets with open ports ...]\n\n"

        # Port statistics
        report += "## PORT STATISTICS\n"
        report += "Most common open ports:\n"
        for i, (port, count) in enumerate(top_ports, 1):
            service_name = self.COMMON_PORTS.get(port, ("Unknown", ""))[0]
            pct = round((count / targets_with_ports * 100), 0) if targets_with_ports > 0 else 0
            warning = ""
            if port in [3306, 5432, 27017, 1433]:
                warning = "  ⚠️  Database exposure"
            elif port in [3389, 23]:
                warning = "  ⚠️  High-risk protocol"
            elif port > 8000:
                warning = "  ⚠️  Non-standard port"

            report += f"{i}. {port} ({service_name})   - {count} hosts ({int(pct)}%){warning}\n"

        # Recommendations
        report += f"""
## SECURITY RECOMMENDATIONS

### Next Steps
✓ Automatic Nmap service detection triggered for all {targets_with_ports} targets
✓ Detailed service version analysis will be available shortly
✓ CVE enrichment will be performed on identified services

### High Priority Actions
"""

        # Add specific recommendations based on findings
        db_count = sum(1 for ports in results.values() if any(p in ports for p in [3306, 5432, 27017, 1433]))
        rdp_count = sum(1 for ports in results.values() if 3389 in ports)

        if db_count > 0:
            report += f"1. 🚨 Review {db_count} database servers exposed to internet - implement firewall rules\n"
        if rdp_count > 0:
            report += f"2. ⚠️  Secure {rdp_count} RDP instances - enable NLA, use strong passwords, consider VPN\n"

        report += """
3. Monitor service detection results for vulnerable versions
4. Review non-standard ports for unauthorized services

════════════════════════════════════════════════════════════
Session: """ + (self.db_session_id or 'N/A') + f""" | Type: Port Scan ({tool_display}) | Time: {duration_str}
════════════════════════════════════════════════════════════
"""

        return report

    # ========================================================================
    # PROGRAMMATIC REPORT GENERATION (New Flow)
    # ========================================================================

    def _generate_and_store_programmatic_report(
        self,
        scan_results: List[Dict],
        scan_type: str
    ) -> Optional[str]:
        """
        Generate programmatic report from scan results and store in database.

        This is Step 1 of the new 2-step Phase 3 flow:
        Step 1: Generate programmatic report (this function)
        Step 2: LLM analyzes programmatic report + DB context

        Args:
            scan_results: List of tool execution results
            scan_type: Detected scan type (masscan, naabu, nmap, subdomain, etc.)

        Returns:
            Report ID if successful, None if failed
        """
        try:
            print("\n  📝 Generating programmatic report...")

            report_data = None
            target = "unknown"

            # Generate report based on scan type
            if scan_type == "masscan":
                # Find masscan result
                for r in scan_results:
                    if "masscan" in r.get("tool", "").lower():
                        report_data = ProgrammaticReportGenerator.generate_masscan_report(r)
                        target = r.get("args", {}).get("targets", ["unknown"])[0]
                        break

            elif scan_type == "naabu":
                # Find naabu result
                for r in scan_results:
                    if "naabu" in r.get("tool", "").lower():
                        report_data = ProgrammaticReportGenerator.generate_naabu_report(r)
                        target = r.get("args", {}).get("targets", ["unknown"])[0]
                        break

            elif scan_type == "port_scan":
                # Find nmap result
                for r in scan_results:
                    if "nmap" in r.get("tool", "").lower():
                        # Debug: Check what data we're passing to the generator
                        result_data = r.get("result", {})
                        print(f"  [DEBUG] Tool: {r.get('tool')}")
                        print(f"  [DEBUG] Result keys: {list(result_data.keys())}")
                        if "results" in result_data:
                            print(f"  [DEBUG] Batch scan detected with {len(result_data.get('results', {}))} IPs")
                        elif "hosts_discovered" in result_data:
                            print(f"  [DEBUG] Single scan with hosts_discovered type: {type(result_data.get('hosts_discovered'))}")

                        report_data = ProgrammaticReportGenerator.generate_nmap_report(r)
                        target = r.get("args", {}).get("target", "unknown")
                        break

            elif scan_type == "subdomain":
                # Find amass and bbot results
                amass_result = None
                bbot_result = None

                for r in scan_results:
                    tool = r.get("tool", "")
                    if "amass" in tool.lower():
                        amass_result = r
                        target = r.get("args", {}).get("domain", "unknown")
                    elif "bbot" in tool.lower():
                        bbot_result = r
                        if target == "unknown":
                            target = r.get("args", {}).get("target", "unknown")

                report_data = ProgrammaticReportGenerator.generate_subdomain_report(
                    amass_result, bbot_result
                )

            elif scan_type == "shodan" or scan_type == "osint":
                # Find shodan result (osint type uses shodan tools)
                for r in scan_results:
                    if "shodan" in r.get("tool", "").lower():
                        report_data = ProgrammaticReportGenerator.generate_shodan_report(r)
                        target = r.get("args", {}).get("ip", "unknown")
                        break

            elif scan_type == "vuln_scan":
                # Vulnerability scans use nmap vuln scan tool
                for r in scan_results:
                    if "nmap" in r.get("tool", "").lower():
                        report_data = ProgrammaticReportGenerator.generate_nmap_report(r)
                        target = r.get("args", {}).get("target", "unknown")
                        break

            elif scan_type == "generic":
                # Generic: try to find any supported tool
                for r in scan_results:
                    tool = r.get("tool", "").lower()
                    if "nmap" in tool:
                        report_data = ProgrammaticReportGenerator.generate_nmap_report(r)
                        target = r.get("args", {}).get("target", "unknown")
                        break
                    elif "masscan" in tool:
                        report_data = ProgrammaticReportGenerator.generate_masscan_report(r)
                        target = r.get("args", {}).get("targets", ["unknown"])[0]
                        break
                    elif "naabu" in tool:
                        report_data = ProgrammaticReportGenerator.generate_naabu_report(r)
                        target = r.get("args", {}).get("targets", ["unknown"])[0]
                        break
                    elif "shodan" in tool:
                        report_data = ProgrammaticReportGenerator.generate_shodan_report(r)
                        target = r.get("args", {}).get("ip", "unknown")
                        break

            # Save to database if report was generated
            if report_data and self.db_session_id:
                report_id = ProgrammaticReportService.save_programmatic_report(
                    session_id=self.db_session_id,
                    report_data=report_data,
                    target=target
                )
                print(f"  ✅ Programmatic report saved (ID: {report_id[:8]}...)")

                # Extract content from report_data dict
                report_content = report_data.get("content", "")
                return report_id, report_content
            else:
                print(f"  ⚠️  No programmatic report generated for scan type: {scan_type}")
                return None, None

        except Exception as e:
            print(f"  ⚠️  Failed to generate programmatic report: {e}")
            import traceback
            traceback.print_exc()
            return None, None

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

        # Initialize audit logger if not already created
        if not self.audit_logger:
            # Extract target from user prompt (simple heuristic)
            self.target = self._extract_target_from_prompt(user_prompt) or "unknown_target"
            self.audit_logger = create_audit_logger(self.session_id, self.target)
            self.metrics = SessionMetrics(self.audit_logger)

            # Initialize exploit queue for multi-phase orchestration
            self.exploit_queue = create_exploit_queue(self.session_id)

            # Initialize parallel scanner for concurrent operations
            self.parallel_scanner = ParallelScanner(self.session_id, self.session_mutex)

        # Log session start
        self.audit_logger.log_event('session_start', {
            'user_prompt': user_prompt,
            'model': self.model
        })
        self.metrics.start_timer('full_scan')

        # Reset scan type flags for new scan to prevent state leakage
        self.is_subdomain_scan = False

        # Phase 1: Tool Selection
        self.current_phase = IterationPhase.TOOL_SELECTION
        self.audit_logger.log_event('phase_start', {'phase': 'phase1_tool_selection'})
        self.metrics.start_timer('phase1')

        selected_tools, reasoning = self.phase_1_tool_selection(user_prompt)

        phase1_elapsed = self.metrics.end_timer('phase1')

        # Validate Phase 1 output
        phase1_output = {
            'selected_tools': selected_tools if selected_tools else [],
            'reasoning': reasoning
        }
        is_valid, validation_errors = validate_phase_output('phase1_tool_selection', phase1_output)

        self.audit_logger.log_event('phase_end', {
            'phase': 'phase1_tool_selection',
            'success': bool(selected_tools),
            'tools_selected': len(selected_tools) if selected_tools else 0,
            'elapsed_seconds': phase1_elapsed,
            'validation_passed': is_valid,
            'validation_errors': validation_errors if not is_valid else []
        })

        if not selected_tools or not is_valid:
            error_msg = "No tools selected" if not selected_tools else f"Phase 1 validation failed: {', '.join(validation_errors)}"
            print(f"\n  ⚠️  {error_msg}")
            return {
                "success": False,
                "phase": 1,
                "error": error_msg,
                "reasoning": reasoning,
                "validation_errors": validation_errors if not is_valid else []
            }

        # Phase 2: Execution
        self.current_phase = IterationPhase.EXECUTION
        self.audit_logger.log_event('phase_start', {'phase': 'phase2_execution'})
        self.metrics.start_timer('phase2')

        execution_results = self.phase_2_execution(selected_tools)

        phase2_elapsed = self.metrics.end_timer('phase2')

        # Validate Phase 2 output
        phase2_output = {
            'execution_results': execution_results
        }
        is_valid, validation_errors = validate_phase_output('phase2_execution', phase2_output)

        self.audit_logger.log_event('phase_end', {
            'phase': 'phase2_execution',
            'success': True,
            'tools_executed': len(execution_results),
            'elapsed_seconds': phase2_elapsed,
            'validation_passed': is_valid,
            'validation_errors': validation_errors if not is_valid else []
        })

        if not is_valid:
            print(f"\n  ⚠️  Phase 2 validation warnings: {', '.join(validation_errors)}")
            # Continue anyway - Phase 2 validation is informational only

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
        self.audit_logger.log_event('phase_start', {'phase': 'phase3_analysis'})
        self.metrics.start_timer('phase3')

        analysis_report = self.phase_3_analysis(execution_results)

        phase3_elapsed = self.metrics.end_timer('phase3')

        # Basic Phase 3 validation (checks if report exists and is substantial)
        # Note: Full validation would require parsing the markdown report
        phase3_valid = bool(analysis_report) and len(analysis_report.strip()) > 100
        phase3_warnings = []
        if not phase3_valid:
            if not analysis_report:
                phase3_warnings.append("No analysis report generated")
            elif len(analysis_report.strip()) <= 100:
                phase3_warnings.append("Analysis report too short (min 100 chars)")

        # Check for hallucination keywords in report
        hallucination_keywords = ['theoretical', 'may be vulnerable', 'could potentially', 'might have', 'appears to suggest']
        for keyword in hallucination_keywords:
            if keyword in analysis_report.lower():
                phase3_warnings.append(f"Report contains uncertain language: '{keyword}'")

        self.audit_logger.log_event('phase_end', {
            'phase': 'phase3_analysis',
            'success': bool(analysis_report),
            'elapsed_seconds': phase3_elapsed,
            'validation_passed': phase3_valid and len(phase3_warnings) == 0,
            'validation_warnings': phase3_warnings
        })

        if phase3_warnings:
            print(f"\n  ⚠️  Phase 3 validation warnings: {', '.join(phase3_warnings)}")

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

        # Log session completion
        full_scan_elapsed = self.metrics.end_timer('full_scan')
        self.audit_logger.log_event('session_end', {
            'status': 'completed',
            'elapsed_seconds': elapsed
        })

        # Update final session state
        self.audit_logger.update_session_state({
            'status': 'completed',
            'completed_phases': ['phase1_tool_selection', 'phase2_execution', 'phase3_analysis'],
            'completed_tools': [t["name"] for t in selected_tools if any(
                r["tool"] == t["name"] and r["result"].get("success")
                for r in execution_results
            )],
            'failed_tools': [t["name"] for t in selected_tools if any(
                r["tool"] == t["name"] and not r["result"].get("success")
                for r in execution_results
            )],
            'risk_score': enriched_summary.get("risk_score", 0),
            'risk_level': enriched_summary.get("risk_level", "N/A"),
            'total_elapsed_seconds': elapsed
        })

        # Get exploit queue statistics
        exploit_queue_stats = None
        if self.exploit_queue:
            try:
                exploit_queue_stats = self.exploit_queue.get_stats()
            except Exception as e:
                print(f"  ⚠️  Failed to get exploit queue stats: {e}")

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
            "enriched_summary": enriched_summary,
            "audit_log_dir": str(self.audit_logger.session_dir) if self.audit_logger else None,
            "exploit_queue_stats": exploit_queue_stats
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
