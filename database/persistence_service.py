"""
Persistence Service - Atomic Tool Result Persistence with Enrichment

This module implements Phase 2 of the 4-phase flow:
    Phase 2: Execution & Persistence (Atomic: Tools -> Parse -> Save -> Enrich)

It handles:
1. Saving tool results to tool-specific models (NmapResult, ShodanResult, etc.)
2. Enriching data with threat intelligence and CVE data
3. Building LLM context cache for efficient Phase 3 queries
4. Managing scan sessions for grouping related scans
"""

import re
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import xml.etree.ElementTree as ET

from .models_enhanced import (
    ScanSession, NmapResult, ShodanResult, BBOTResult, AmassResult,
    CVEEnrichment, ThreatIntelligence, LLMContextCache, GeneratedReport,
    get_nmap_summary_for_target, get_subdomain_summary_for_domain, get_threat_context_for_ip
)
from .database import get_db_session


# ============================================================================
# SUBDOMAIN CLASSIFICATION
# ============================================================================

HIGH_VALUE_PATTERNS = [
    r'^(admin|administrator|adm)\.',
    r'^(api|api-|apis)\.',
    r'^(dev|develop|development)\.',
    r'^(staging|stage|stg)\.',
    r'^(test|testing|qa)\.',
    r'^(internal|intra|corp)\.',
    r'^(vpn|remote|gateway)\.',
    r'^(mail|smtp|imap|pop3?)\.',
    r'^(db|database|sql|mysql|postgres)\.',
    r'^(jenkins|gitlab|github|ci|cd)\.',
    r'^(aws|azure|gcp|cloud)\.',
    r'^(backup|bak|bkp)\.',
    r'^(ftp|sftp|ssh)\.',
    r'^(portal|dashboard|console)\.',
    r'^(auth|oauth|sso|login)\.',
]


def classify_subdomain(subdomain: str) -> Optional[str]:
    """Classify a subdomain as high-value target with category."""
    subdomain_lower = subdomain.lower()

    categories = {
        'admin': r'^(admin|administrator|adm)\.',
        'api': r'^(api|api-|apis)\.',
        'development': r'^(dev|develop|development|staging|stage|stg|test|testing|qa)\.',
        'internal': r'^(internal|intra|corp|vpn|remote)\.',
        'mail': r'^(mail|smtp|imap|pop3?)\.',
        'database': r'^(db|database|sql|mysql|postgres|mongo|redis)\.',
        'devops': r'^(jenkins|gitlab|github|ci|cd|deploy)\.',
        'cloud': r'^(aws|azure|gcp|cloud|k8s|kubernetes)\.',
        'infrastructure': r'^(backup|bak|ftp|sftp|ssh|gateway)\.',
        'auth': r'^(auth|oauth|sso|login|portal|dashboard|console)\.',
    }

    for category, pattern in categories.items():
        if re.search(pattern, subdomain_lower):
            return category
    return None


def extract_high_value_targets(subdomains: List[str]) -> List[Dict[str, str]]:
    """Extract high-value targets from subdomain list with categories."""
    high_value = []
    for subdomain in subdomains:
        category = classify_subdomain(subdomain)
        if category:
            high_value.append({
                "subdomain": subdomain,
                "category": category,
                "priority": "high" if category in ['admin', 'api', 'auth', 'database'] else "medium"
            })
    return high_value


def categorize_subdomains(subdomains: List[str], domain: str) -> Dict[str, List[str]]:
    """Group subdomains by category for LLM context."""
    categories = {
        'api': [],
        'admin': [],
        'dev': [],
        'mail': [],
        'www': [],
        'other': []
    }

    for subdomain in subdomains:
        sub_lower = subdomain.lower()
        if re.search(r'^(api|apis|api-)', sub_lower):
            categories['api'].append(subdomain)
        elif re.search(r'^(admin|administrator|adm)', sub_lower):
            categories['admin'].append(subdomain)
        elif re.search(r'^(dev|staging|test|qa)', sub_lower):
            categories['dev'].append(subdomain)
        elif re.search(r'^(mail|smtp|imap|pop)', sub_lower):
            categories['mail'].append(subdomain)
        elif sub_lower.startswith('www'):
            categories['www'].append(subdomain)
        else:
            categories['other'].append(subdomain)

    # Remove empty categories
    return {k: v for k, v in categories.items() if v}


# ============================================================================
# SCAN SESSION MANAGEMENT
# ============================================================================

class ScanSessionManager:
    """Manages scan sessions for grouping related scans."""

    def __init__(self):
        self.db = get_db_session()

    def create_session(
        self,
        user_prompt: str,
        target: str,
        session_type: str = None
    ) -> ScanSession:
        """Create a new scan session for a user request."""
        session = ScanSession(
            user_prompt=user_prompt,
            target=target,
            session_type=session_type,
            status="pending",
            current_phase=1
        )
        self.db.add(session)
        self.db.commit()
        return session

    def update_phase(self, session_id: str, phase: int, tools: List[Dict] = None):
        """Update session phase and optionally store selected tools."""
        session = self.db.query(ScanSession).filter_by(id=session_id).first()
        if session:
            session.current_phase = phase
            if phase == 1 and tools:
                session.selected_tools = tools
                session.phase1_completed = datetime.utcnow()
            elif phase == 2:
                session.status = "running"
                session.phase2_completed = datetime.utcnow()
            elif phase == 3:
                session.phase3_completed = datetime.utcnow()
            elif phase == 4:
                session.phase4_completed = datetime.utcnow()
                session.status = "completed"
                session.completed_at = datetime.utcnow()
                if session.started_at:
                    session.elapsed_seconds = (datetime.utcnow() - session.started_at).total_seconds()
            self.db.commit()
        return session

    def set_analysis_results(self, session_id: str, analysis: Dict, risk_score: float, risk_level: str):
        """Store Phase 3 analysis results."""
        session = self.db.query(ScanSession).filter_by(id=session_id).first()
        if session:
            session.analysis_json = analysis
            session.risk_score = risk_score
            session.risk_level = risk_level
            self.db.commit()
        return session

    def get_session(self, session_id: str) -> Optional[ScanSession]:
        """Get a session by ID."""
        return self.db.query(ScanSession).filter_by(id=session_id).first()

    def get_recent_sessions(self, limit: int = 10) -> List[ScanSession]:
        """Get recent scan sessions."""
        return self.db.query(ScanSession).order_by(
            ScanSession.created_at.desc()
        ).limit(limit).all()


# ============================================================================
# TOOL RESULT PERSISTENCE
# ============================================================================

class ToolResultPersister:
    """
    Persists tool results to tool-specific models with enrichment.
    Implements Phase 2 atomic persistence.
    """

    def __init__(self, session_id: str = None):
        self.db = get_db_session()
        self.session_id = session_id

    def save_nmap_result(self, result: Dict[str, Any]) -> NmapResult:
        """
        Save Nmap scan result with parsing and enrichment.

        Args:
            result: Nmap tool result dict with output_xml path

        Returns:
            NmapResult: Persisted model instance
        """
        # Parse XML if available for detailed data
        hosts_data = []
        services = []
        os_detections = []
        script_results = []

        xml_path = result.get('output_xml')
        if xml_path and os.path.exists(xml_path):
            hosts_data, services, os_detections, script_results = self._parse_nmap_xml(xml_path)

        # Fall back to parsed data from result
        if not hosts_data and result.get('hosts'):
            hosts_data = result['hosts']
        if not services and result.get('open_ports'):
            services = result['open_ports']

        # Extract vulnerabilities from script results
        vulnerabilities = []
        if result.get('vulnerabilities'):
            vulnerabilities = result['vulnerabilities']
        for sr in script_results:
            if 'vuln' in sr.get('script_id', '').lower():
                vulnerabilities.append(sr)

        nmap_result = NmapResult(
            session_id=self.session_id,
            target=result.get('target', ''),
            scan_type=result.get('tool', 'nmap_scan').replace('nmap_', ''),
            command=result.get('command'),
            xml_output_path=xml_path,
            elapsed_seconds=result.get('elapsed_seconds'),
            hosts_up=len([h for h in hosts_data if h.get('status') != 'down']),
            hosts_down=len([h for h in hosts_data if h.get('status') == 'down']),
            total_open_ports=result.get('open_ports_count', 0),
            hosts_data=hosts_data,
            services_detected=services,
            vulnerabilities=vulnerabilities if vulnerabilities else None,
            os_detections=os_detections if os_detections else None,
            script_results=script_results if script_results else None,
            raw_stdout=result.get('output', '')[:10000]
        )

        self.db.add(nmap_result)
        self.db.commit()
        return nmap_result

    def _parse_nmap_xml(self, xml_path: str) -> tuple:
        """Parse Nmap XML output for detailed data."""
        hosts_data = []
        services = []
        os_detections = []
        script_results = []

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall('.//host'):
                host_info = {
                    'status': host.find('status').get('state') if host.find('status') is not None else 'unknown'
                }

                # Get addresses
                for addr in host.findall('.//address'):
                    addr_type = addr.get('addrtype', 'ipv4')
                    if addr_type in ('ipv4', 'ipv6'):
                        host_info['ip'] = addr.get('addr')
                    elif addr_type == 'mac':
                        host_info['mac'] = addr.get('addr')

                # Get hostname
                hostname_elem = host.find('.//hostname')
                if hostname_elem is not None:
                    host_info['hostname'] = hostname_elem.get('name')

                # Get ports
                host_ports = []
                for port in host.findall('.//port'):
                    port_info = {
                        'port': int(port.get('portid')),
                        'protocol': port.get('protocol', 'tcp'),
                        'state': port.find('state').get('state') if port.find('state') is not None else 'unknown'
                    }

                    service = port.find('service')
                    if service is not None:
                        port_info['service'] = service.get('name', '')
                        port_info['product'] = service.get('product', '')
                        port_info['version'] = service.get('version', '')
                        port_info['extrainfo'] = service.get('extrainfo', '')

                    host_ports.append(port_info)
                    if port_info['state'] == 'open':
                        services.append(port_info)

                    # Parse scripts
                    for script in port.findall('.//script'):
                        script_results.append({
                            'port': port_info['port'],
                            'script_id': script.get('id'),
                            'output': script.get('output', '')[:1000]
                        })

                host_info['ports'] = host_ports
                hosts_data.append(host_info)

                # OS detection
                for osmatch in host.findall('.//osmatch'):
                    os_detections.append({
                        'ip': host_info.get('ip'),
                        'name': osmatch.get('name'),
                        'accuracy': int(osmatch.get('accuracy', 0))
                    })

        except Exception as e:
            print(f"  Warning: Failed to parse Nmap XML: {e}")

        return hosts_data, services, os_detections, script_results

    def save_shodan_result(self, result: Dict[str, Any]) -> ShodanResult:
        """Save Shodan lookup result with threat enrichment."""
        data = result.get('data', {})

        # Determine threat level
        threat_level = 'UNKNOWN'
        threat_indicators = []

        vulns = data.get('vulns', [])
        if vulns:
            # Check for critical CVEs
            critical_cves = [v for v in vulns if 'critical' in str(v).lower()]
            if critical_cves:
                threat_level = 'CRITICAL'
                threat_indicators.append("Critical CVEs present")
            elif len(vulns) > 5:
                threat_level = 'HIGH'
                threat_indicators.append(f"{len(vulns)} vulnerabilities detected")
            else:
                threat_level = 'MEDIUM'

        tags = data.get('tags', [])
        if any(t in ['honeypot', 'malware', 'c2', 'botnet'] for t in tags):
            threat_level = 'CRITICAL'
            threat_indicators.extend([f"Tagged as: {t}" for t in tags if t in ['honeypot', 'malware', 'c2', 'botnet']])

        shodan_result = ShodanResult(
            session_id=self.session_id,
            ip_address=result.get('ip', data.get('ip_str', '')),
            query_type='host_lookup',
            organization=data.get('org'),
            isp=data.get('isp'),
            asn=data.get('asn'),
            country=data.get('country_name'),
            city=data.get('city'),
            hostnames=data.get('hostnames', []),
            domains=data.get('domains', []),
            open_ports=data.get('ports', []),
            services=self._extract_shodan_services(data),
            vulns=vulns,
            tags=tags,
            threat_level=threat_level,
            threat_indicators=threat_indicators if threat_indicators else None,
            raw_data=data
        )

        self.db.add(shodan_result)
        self.db.commit()

        # Also save to threat intelligence
        self._save_threat_intel_from_shodan(shodan_result)

        return shodan_result

    def _extract_shodan_services(self, data: Dict) -> List[Dict]:
        """Extract structured service info from Shodan data."""
        services = []
        for item in data.get('data', []):
            if isinstance(item, dict):
                services.append({
                    'port': item.get('port'),
                    'transport': item.get('transport', 'tcp'),
                    'product': item.get('product'),
                    'version': item.get('version'),
                    'banner': item.get('data', '')[:500] if item.get('data') else None
                })
        return services

    def _save_threat_intel_from_shodan(self, shodan: ShodanResult):
        """Create/update threat intelligence from Shodan data."""
        existing = self.db.query(ThreatIntelligence).filter_by(
            indicator=shodan.ip_address,
            indicator_type='ip'
        ).first()

        if existing:
            existing.threat_level = shodan.threat_level.lower() if shodan.threat_level else 'unknown'
            existing.last_seen = datetime.utcnow()
            existing.raw_data = {'shodan': shodan.raw_data}
        else:
            threat = ThreatIntelligence(
                indicator=shodan.ip_address,
                indicator_type='ip',
                threat_level=shodan.threat_level.lower() if shodan.threat_level else 'unknown',
                threat_types=shodan.tags,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                sources=['shodan'],
                country_code=shodan.country[:2] if shodan.country else None,
                city=shodan.city,
                asn_org=shodan.organization,
                raw_data={'shodan': shodan.raw_data}
            )
            self.db.add(threat)

        self.db.commit()

    def save_bbot_result(self, result: Dict[str, Any]) -> BBOTResult:
        """Save BBOT scan result with subdomain categorization."""
        subdomains = result.get('subdomains', [])

        # Extract high-value targets
        high_value = extract_high_value_targets(subdomains)

        # Parse technologies if available
        technologies = result.get('technologies', [])

        bbot_result = BBOTResult(
            session_id=self.session_id,
            target=result.get('target', ''),
            preset=result.get('preset'),
            command=result.get('command'),
            output_directory=result.get('output_directory'),
            json_output_path=result.get('json_output_file'),
            elapsed_seconds=result.get('elapsed_seconds'),
            total_events=result.get('findings_count', 0),
            subdomains_found=len(subdomains),
            urls_found=result.get('urls_found', 0),
            technologies_found=len(technologies),
            subdomains=subdomains,
            urls=result.get('urls', [])[:100],
            technologies=technologies,
            event_types=result.get('event_types'),
            high_value_targets=high_value if high_value else None
        )

        self.db.add(bbot_result)
        self.db.commit()
        return bbot_result

    def save_amass_result(self, result: Dict[str, Any]) -> AmassResult:
        """Save Amass enumeration result with categorization."""
        domain = result.get('domain', '')
        subdomains = result.get('subdomains', [])

        # Categorize subdomains
        categorized = categorize_subdomains(subdomains, domain)

        # Extract high-value targets
        high_value = extract_high_value_targets(subdomains)

        amass_result = AmassResult(
            session_id=self.session_id,
            domain=domain,
            mode=result.get('mode', 'active'),
            command=result.get('command'),
            json_output_path=result.get('json_output_file'),
            elapsed_seconds=result.get('elapsed_seconds'),
            subdomains_found=len(subdomains),
            subdomains=subdomains,
            subdomains_by_category=categorized,
            high_value_targets=high_value if high_value else None
        )

        self.db.add(amass_result)
        self.db.commit()
        return amass_result

    def save_tool_result(self, tool_name: str, result: Dict[str, Any]) -> Any:
        """
        Generic method to save any tool result.
        Routes to appropriate persister based on tool name.
        """
        tool_lower = tool_name.lower()

        if 'nmap' in tool_lower:
            return self.save_nmap_result(result)
        elif 'shodan' in tool_lower:
            return self.save_shodan_result(result)
        elif 'bbot' in tool_lower:
            return self.save_bbot_result(result)
        elif 'amass' in tool_lower:
            return self.save_amass_result(result)
        else:
            # Unknown tool - just log
            print(f"  Warning: No persister for tool '{tool_name}'")
            return None


# ============================================================================
# LLM CONTEXT BUILDER
# ============================================================================

class LLMContextBuilder:
    """
    Builds enriched context for LLM analysis (Phase 3).
    Aggregates data from all tool results and enrichment tables.
    """

    def __init__(self, session_id: str = None):
        self.db = get_db_session()
        self.session_id = session_id

    def build_context_for_session(self, session_id: str) -> Dict[str, Any]:
        """Build comprehensive context for a scan session."""
        session = self.db.query(ScanSession).filter_by(id=session_id).first()
        if not session:
            return {"error": "Session not found"}

        context = {
            "session": {
                "id": session.id,
                "user_prompt": session.user_prompt,
                "target": session.target,
                "session_type": session.session_type,
                "tools_used": session.selected_tools
            },
            "nmap_data": self._get_nmap_context(session_id),
            "shodan_data": self._get_shodan_context(session_id),
            "subdomain_data": self._get_subdomain_context(session_id),
            "threat_intel": self._get_threat_context(session_id),
            "summary": {}
        }

        # Build summary
        context["summary"] = self._build_summary(context)

        return context

    def _get_nmap_context(self, session_id: str) -> List[Dict]:
        """Get Nmap results for session."""
        results = self.db.query(NmapResult).filter_by(session_id=session_id).all()
        return [r.to_dict() for r in results]

    def _get_shodan_context(self, session_id: str) -> List[Dict]:
        """Get Shodan results for session."""
        results = self.db.query(ShodanResult).filter_by(session_id=session_id).all()
        return [r.to_dict() for r in results]

    def _get_subdomain_context(self, session_id: str) -> Dict[str, Any]:
        """Get combined subdomain data from BBOT and Amass."""
        bbot = self.db.query(BBOTResult).filter_by(session_id=session_id).all()
        amass = self.db.query(AmassResult).filter_by(session_id=session_id).all()

        all_subdomains = set()
        all_high_value = []

        for b in bbot:
            if b.subdomains:
                all_subdomains.update(b.subdomains)
            if b.high_value_targets:
                all_high_value.extend(b.high_value_targets)

        for a in amass:
            if a.subdomains:
                all_subdomains.update(a.subdomains)
            if a.high_value_targets:
                all_high_value.extend(a.high_value_targets)

        # Deduplicate high-value targets
        seen = set()
        unique_high_value = []
        for hv in all_high_value:
            if hv['subdomain'] not in seen:
                seen.add(hv['subdomain'])
                unique_high_value.append(hv)

        return {
            "total_unique": len(all_subdomains),
            "bbot_count": sum(b.subdomains_found for b in bbot),
            "amass_count": sum(a.subdomains_found for a in amass),
            "high_value_targets": unique_high_value,
            "sample": sorted(list(all_subdomains))[:100]
        }

    def _get_threat_context(self, session_id: str) -> Dict[str, Any]:
        """Get threat intelligence context."""
        shodan = self.db.query(ShodanResult).filter_by(session_id=session_id).all()

        threats = []
        for s in shodan:
            if s.threat_level and s.threat_level != 'UNKNOWN':
                threats.append({
                    "ip": s.ip_address,
                    "level": s.threat_level,
                    "indicators": s.threat_indicators,
                    "vulns_count": len(s.vulns) if s.vulns else 0
                })

        return {
            "threats_found": len(threats),
            "critical_count": len([t for t in threats if t['level'] == 'CRITICAL']),
            "high_count": len([t for t in threats if t['level'] == 'HIGH']),
            "details": threats
        }

    def _build_summary(self, context: Dict) -> Dict[str, Any]:
        """Build executive summary from context."""
        nmap_data = context.get("nmap_data", [])
        shodan_data = context.get("shodan_data", [])
        subdomain_data = context.get("subdomain_data", {})
        threat_intel = context.get("threat_intel", {})

        total_ports = sum(n.get("total_open_ports", 0) for n in nmap_data)
        total_vulns = sum(len(s.get("vulns") or []) for s in shodan_data)

        # Calculate risk score (0-100)
        risk_score = 0
        if threat_intel.get("critical_count", 0) > 0:
            risk_score += 40
        if threat_intel.get("high_count", 0) > 0:
            risk_score += 25
        if total_vulns > 10:
            risk_score += 20
        elif total_vulns > 0:
            risk_score += 10
        if total_ports > 20:
            risk_score += 15

        # Determine risk level
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "total_hosts_scanned": len(nmap_data),
            "total_open_ports": total_ports,
            "total_subdomains": subdomain_data.get("total_unique", 0),
            "high_value_targets": len(subdomain_data.get("high_value_targets", [])),
            "total_vulnerabilities": total_vulns,
            "threats_detected": threat_intel.get("threats_found", 0),
            "risk_score": min(risk_score, 100),
            "risk_level": risk_level
        }

    def cache_context(self, session_id: str, context: Dict) -> LLMContextCache:
        """Cache context for efficient Phase 3 queries."""
        # Estimate tokens (rough: 1 token per 4 chars)
        context_str = json.dumps(context)
        estimated_tokens = len(context_str) // 4

        cache = LLMContextCache(
            context_type="scan_summary",
            session_id=session_id,
            target=context.get("session", {}).get("target"),
            context_json=context,
            context_text=self._generate_narrative(context),
            estimated_tokens=estimated_tokens,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )

        self.db.add(cache)
        self.db.commit()
        return cache

    def _generate_narrative(self, context: Dict) -> str:
        """Generate human-readable narrative from context."""
        summary = context.get("summary", {})
        session = context.get("session", {})

        narrative = f"""
## Scan Summary for {session.get('target', 'Unknown Target')}

### Overview
- **Risk Level**: {summary.get('risk_level', 'UNKNOWN')} (Score: {summary.get('risk_score', 0)}/100)
- **Hosts Scanned**: {summary.get('total_hosts_scanned', 0)}
- **Open Ports Found**: {summary.get('total_open_ports', 0)}
- **Subdomains Discovered**: {summary.get('total_subdomains', 0)}
- **High-Value Targets**: {summary.get('high_value_targets', 0)}
- **Vulnerabilities**: {summary.get('total_vulnerabilities', 0)}
- **Threat Indicators**: {summary.get('threats_detected', 0)}

### High-Value Subdomain Targets
"""
        hv_targets = context.get("subdomain_data", {}).get("high_value_targets", [])
        for hv in hv_targets[:10]:
            narrative += f"- `{hv['subdomain']}` ({hv['category']}, {hv['priority']} priority)\n"

        return narrative


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def persist_tool_results(
    session_id: str,
    results: List[Dict[str, Any]]
) -> List[Any]:
    """
    Persist multiple tool results atomically.

    Args:
        session_id: Scan session ID
        results: List of tool results [{tool: str, result: dict}, ...]

    Returns:
        List of persisted model instances
    """
    persister = ToolResultPersister(session_id=session_id)
    persisted = []

    for r in results:
        tool_name = r.get('tool', '')
        result_data = r.get('result', r)

        try:
            model = persister.save_tool_result(tool_name, result_data)
            if model:
                persisted.append(model)
        except Exception as e:
            print(f"  Warning: Failed to persist {tool_name}: {e}")

    return persisted


def build_and_cache_context(session_id: str) -> Dict[str, Any]:
    """
    Build LLM context for a session and cache it.

    Returns:
        Complete context dictionary
    """
    builder = LLMContextBuilder(session_id=session_id)
    context = builder.build_context_for_session(session_id)
    builder.cache_context(session_id, context)
    return context


def get_cached_context(session_id: str) -> Optional[Dict[str, Any]]:
    """Get cached context if available and valid."""
    db = get_db_session()
    cache = db.query(LLMContextCache).filter(
        LLMContextCache.session_id == session_id,
        LLMContextCache.is_valid == True,
        LLMContextCache.expires_at > datetime.utcnow()
    ).order_by(LLMContextCache.generated_at.desc()).first()

    if cache:
        return cache.context_json
    return None
