"""
Tool Index - ChromaDB-based Tool Registry

Stores tool metadata for retrieval-based selection.
"""
import chromadb
from chromadb.config import Settings
from pathlib import Path
from typing import List, Dict, Optional
import json
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from app.core.config import get_config


# Tool definitions for the index - SECURITY-ENRICHED
# Each tool includes: phase, attack_type, requires for better semantic search
TOOL_DEFINITIONS = [
    # === PORT SCANNING ===
    {
        "name": "nmap",
        "phase": "scanning",
        "attack_type": "active",
        "requires": [],
        "category": "port_scan",
        "description": "Port scanner with service and version detection. Discovers open TCP/UDP ports and identifies running services.",
        "keywords": ["port scan", "service detection", "network scan", "open ports", "tcp", "udp", "version detection"],
        "examples": ["scan ports", "what ports are open", "nmap scan", "check services", "find open ports"],
    },
    {
        "name": "masscan",
        "phase": "scanning",
        "attack_type": "active",
        "requires": [],
        "category": "port_scan",
        "description": "Ultra-fast port scanner for large IP ranges. Scans millions of hosts quickly.",
        "keywords": ["fast port scan", "large scale", "mass scan", "quick scan", "ip range"],
        "examples": ["fast port scan", "scan all ports quickly", "masscan", "scan ip range"],
    },
    {
        "name": "httpx",
        "phase": "scanning",
        "attack_type": "active",
        "requires": ["subdomains"],
        "category": "port_scan",
        "description": "HTTP probe to check live web servers, grab titles, and detect technologies.",
        "keywords": ["http probe", "web servers", "live hosts", "http status", "tech detect", "title"],
        "examples": ["probe hosts", "check web servers", "http probe", "find live websites"],
    },
    
    # === SUBDOMAIN ENUMERATION ===
    {
        "name": "bbot",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "subdomain",
        "description": "OSINT automation for subdomain enumeration and reconnaissance. Discovers subdomains passively.",
        "keywords": ["subdomain", "enumerate", "osint", "discovery", "recon", "passive"],
        "examples": ["find subdomains", "subdomain enumeration", "bbot scan", "discover subdomains"],
    },
    {
        "name": "amass",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "subdomain",
        "description": "In-depth attack surface mapping and subdomain enumeration using multiple sources.",
        "keywords": ["subdomain", "attack surface", "passive recon", "dns", "surface mapping"],
        "examples": ["find subdomains", "amass enum", "attack surface", "map subdomains"],
    },
    {
        "name": "subfinder",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "subdomain",
        "description": "Fast passive subdomain discovery using OSINT sources like certificate logs.",
        "keywords": ["subdomain", "passive", "fast discovery", "certificate transparency"],
        "examples": ["quick subdomain scan", "subfinder", "passive subdomains", "fast subdomain"],
    },
    
    # === VULNERABILITY SCANNING ===
    {
        "name": "nuclei",
        "phase": "scanning",
        "attack_type": "active",
        "requires": ["subdomains"],
        "category": "vuln_scan",
        "description": "Template-based vulnerability scanner with CVE detection. Scans for known vulnerabilities.",
        "keywords": ["vulnerability", "CVE", "security scan", "template scan", "vuln", "cve detection"],
        "examples": ["scan for vulnerabilities", "check CVEs", "nuclei scan", "find vulnerabilities"],
    },
    {
        "name": "nikto",
        "phase": "scanning",
        "attack_type": "active",
        "requires": ["open_ports"],
        "category": "vuln_scan",
        "description": "Web server vulnerability scanner for misconfigurations and known issues.",
        "keywords": ["web vulnerability", "web server scan", "misconfiguration", "web security"],
        "examples": ["scan web server", "nikto scan", "web vulnerabilities", "check web security"],
    },
    {
        "name": "wpscan",
        "phase": "scanning",
        "attack_type": "active",
        "requires": ["open_ports"],
        "category": "vuln_scan",
        "description": "WordPress vulnerability scanner for plugins, themes, and core issues.",
        "keywords": ["wordpress", "cms", "wp vulnerabilities", "wordpress scan", "wp plugins"],
        "examples": ["scan wordpress", "wpscan", "wp vulnerabilities", "wordpress security"],
    },
    
    # === SQL INJECTION ===
    {
        "name": "sqlmap",
        "phase": "exploitation",
        "attack_type": "injection",
        "requires": ["open_ports"],
        "category": "vuln_scan",
        "description": "Automated SQL injection detection and exploitation. Dumps databases.",
        "keywords": ["sql injection", "sqli", "database", "injection", "database dump"],
        "examples": ["test sql injection", "sqlmap", "check for sqli", "dump database"],
    },
    
    # === DIRECTORY/FILE DISCOVERY ===
    {
        "name": "gobuster",
        "phase": "scanning",
        "attack_type": "brute-force",
        "requires": ["open_ports"],
        "category": "web_discovery",
        "description": "Directory and file brute-forcing tool. Finds hidden paths on web servers.",
        "keywords": ["directory", "brute force", "hidden files", "path discovery", "dir busting"],
        "examples": ["find hidden directories", "gobuster", "directory scan", "brute force dirs"],
    },
    {
        "name": "ffuf",
        "phase": "scanning",
        "attack_type": "brute-force",
        "requires": ["open_ports"],
        "category": "web_discovery",
        "description": "Fast web fuzzer for directories, parameters, and endpoints.",
        "keywords": ["fuzz", "web fuzzing", "parameter discovery", "fast fuzzer", "endpoint"],
        "examples": ["fuzz endpoints", "ffuf", "parameter fuzzing", "fuzz parameters"],
    },
    {
        "name": "feroxbuster",
        "phase": "scanning",
        "attack_type": "brute-force",
        "requires": ["open_ports"],
        "category": "web_discovery",
        "description": "Fast recursive content discovery tool for finding hidden paths.",
        "keywords": ["recursive", "content discovery", "directory scan", "fast recursive"],
        "examples": ["recursive directory scan", "feroxbuster", "deep scan directories"],
    },
    {
        "name": "katana",
        "phase": "scanning",
        "attack_type": "passive",
        "requires": ["open_ports"],
        "category": "web_discovery",
        "description": "Web crawler to discover endpoints and URLs by crawling the site.",
        "keywords": ["crawler", "spider", "endpoint discovery", "url discovery", "crawl"],
        "examples": ["crawl website", "katana", "find endpoints", "spider site"],
    },
    
    # === BRUTE FORCE / CREDENTIAL ATTACKS ===
    {
        "name": "hydra",
        "phase": "exploitation",
        "attack_type": "brute-force",
        "requires": ["open_ports"],
        "category": "brute_force",
        "description": "Network login cracker for SSH, FTP, HTTP, RDP, and more. Brute forces credentials.",
        "keywords": ["brute force", "password crack", "login attack", "credential", "ssh brute", "ftp brute"],
        "examples": ["brute force ssh", "hydra attack", "crack password", "brute force login"],
    },
    {
        "name": "medusa",
        "phase": "exploitation",
        "attack_type": "brute-force",
        "requires": ["open_ports"],
        "category": "brute_force",
        "description": "Parallel network login auditor for SSH, FTP, HTTP, MySQL, RDP.",
        "keywords": ["brute force", "parallel", "login cracker", "credential attack"],
        "examples": ["brute force", "medusa attack", "parallel brute force"],
    },
    {
        "name": "john",
        "phase": "post-exploitation",
        "attack_type": "brute-force",
        "requires": ["credentials"],
        "category": "brute_force",
        "description": "John the Ripper password hash cracker. Cracks captured hashes.",
        "keywords": ["hash crack", "password", "john the ripper", "offline crack"],
        "examples": ["crack hash", "john", "password cracking", "crack captured hash"],
    },
    {
        "name": "hashcat",
        "phase": "post-exploitation",
        "attack_type": "brute-force",
        "requires": ["credentials"],
        "category": "brute_force",
        "description": "Advanced GPU-accelerated password recovery. Fastest hash cracker.",
        "keywords": ["hash", "gpu crack", "password recovery", "gpu accelerated"],
        "examples": ["hashcat", "gpu crack", "hash cracking", "fast hash crack"],
    },
    
    # === OSINT ===
    {
        "name": "theHarvester",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "osint",
        "description": "Gather emails, subdomains, hosts from public sources like search engines.",
        "keywords": ["email harvest", "osint", "public sources", "gathering", "emails"],
        "examples": ["gather emails", "theharvester", "osint gathering", "find emails"],
    },
    {
        "name": "shodan",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "osint",
        "description": "Search engine for internet-connected devices. Find exposed services.",
        "keywords": ["shodan", "internet search", "iot", "exposed devices", "device search"],
        "examples": ["shodan search", "find exposed devices", "search shodan", "iot search"],
    },
    {
        "name": "clatscope",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "osint",
        "description": "OSINT toolkit for IP lookup, DNS, WHOIS, SSL certs, and origin IP discovery.",
        "keywords": ["osint", "ip lookup", "dns", "whois", "ssl", "origin ip", "reverse dns"],
        "examples": ["ip lookup", "dns info", "whois", "find origin ip", "osint lookup"],
    },
    
    # === EXPLOITATION ===
    {
        "name": "searchsploit",
        "phase": "exploitation",
        "attack_type": "passive",
        "requires": ["detected_tech"],
        "category": "exploit",
        "description": "Search Exploit-DB for known exploits based on technology or CVE.",
        "keywords": ["exploit", "exploit-db", "known vulnerabilities", "cve exploit", "search exploit"],
        "examples": ["find exploits", "searchsploit", "exploit search", "cve exploit"],
    },
    {
        "name": "msfconsole",
        "phase": "exploitation",
        "attack_type": "active",
        "requires": ["open_ports", "detected_tech"],
        "category": "exploit",
        "description": "Metasploit Framework for CVE exploitation and post-exploitation.",
        "keywords": ["metasploit", "msfconsole", "exploit", "cve", "module", "shell", "payload", "post-exploitation"],
        "examples": ["use metasploit", "msfconsole", "exploit CVE", "run metasploit module", "get shell"],
    },
    {
        "name": "recon-ng",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": ["advanced_user"],  # Requires manual module setup
        "category": "osint",
        "description": "Advanced OSINT framework requiring module installation. Use clatscope for simpler OSINT.",
        "keywords": ["recon-ng framework"],  # Narrowed - only match explicit requests
        "examples": ["run recon-ng"],  # Very specific - only when user explicitly asks
    },
    
    # === DNS/WHOIS ===
    {
        "name": "whois",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "recon",
        "description": "Domain registration and ownership lookup. Find who owns a domain.",
        "keywords": ["whois", "domain info", "registration", "ownership", "registrar"],
        "examples": ["whois lookup", "domain registration", "who owns", "domain owner"],
    },
    {
        "name": "dig",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "recon",
        "description": "DNS lookup and zone transfer testing. Query DNS records.",
        "keywords": ["dns", "zone transfer", "dns lookup", "records", "a record", "mx record"],
        "examples": ["dns lookup", "dig", "zone transfer", "query dns"],
    },
    {
        "name": "dnsrecon",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "recon",
        "description": "DNS enumeration and zone transfer attempts.",
        "keywords": ["dns enumeration", "dns recon", "zone transfer", "dns records"],
        "examples": ["dns enumeration", "dnsrecon", "enumerate dns"],
    },
    
    # === WEB ANALYSIS ===
    {
        "name": "whatweb",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "web_analysis",
        "description": "Web technology fingerprinting. Identify CMS, frameworks, and tech stack.",
        "keywords": ["technology", "fingerprint", "cms", "framework detection", "tech stack"],
        "examples": ["identify technology", "whatweb", "tech stack", "detect cms"],
    },
    {
        "name": "wafw00f",
        "phase": "reconnaissance",
        "attack_type": "passive",
        "requires": [],
        "category": "web_analysis",
        "description": "Web Application Firewall detection. Identify WAF protecting target.",
        "keywords": ["waf", "firewall", "waf detection", "cloudflare", "akamai"],
        "examples": ["detect waf", "wafw00f", "check firewall", "waf scan"],
    },
    
    # === NETWORK / SMB ===
    {
        "name": "nc",
        "phase": "exploitation",
        "attack_type": "active",
        "requires": ["open_ports"],
        "category": "network",
        "description": "Netcat for network connections, port testing, and banner grabbing.",
        "keywords": ["netcat", "connection", "banner grab", "port connect"],
        "examples": ["netcat connect", "banner grab", "nc", "connect to port"],
    },
    {
        "name": "enum4linux",
        "phase": "scanning",
        "attack_type": "active",
        "requires": ["open_ports"],
        "category": "network",
        "description": "Windows/Samba enumeration tool. Find shares, users, and groups.",
        "keywords": ["smb", "windows", "samba", "shares", "enumeration", "users"],
        "examples": ["enumerate windows", "smb shares", "enum4linux", "list shares"],
    },
    {
        "name": "crackmapexec",
        "phase": "exploitation",
        "attack_type": "active",
        "requires": ["open_ports", "credentials"],
        "category": "network",
        "description": "Swiss army knife for pentesting Windows/Active Directory environments.",
        "keywords": ["active directory", "windows", "smb", "ldap", "ad", "lateral movement"],
        "examples": ["cme", "crackmapexec", "ad attack", "move laterally"],
    },
]


class ToolIndex:
    """ChromaDB-based tool index for retrieval.
    
    Can operate in two modes:
    - Legacy: Uses TOOL_DEFINITIONS (tool-level indexing)
    - Unified: Delegates to UnifiedRAG (command-level indexing)
    """
    
    def __init__(self, use_unified: bool = True):
        """
        Initialize tool index.
        
        Args:
            use_unified: If True, use UnifiedRAG for command-level search.
                        If False, use legacy tool-level search.
        """
        self.use_unified = use_unified
        self._unified_rag = None
        
        if not use_unified:
            # Legacy mode
            config = get_config()
            persist_dir = str(config.chroma_persist_dir / "tool_index")
            Path(persist_dir).mkdir(parents=True, exist_ok=True)
            
            self.client = chromadb.PersistentClient(
                path=persist_dir,
                settings=Settings(anonymized_telemetry=False)
            )
            
            self.collection = self.client.get_or_create_collection(
                name="tools",
                metadata={"description": "SNODE security tools"}
            )
            
            if self.collection.count() == 0:
                self._populate()
    
    def _get_unified(self):
        """Get UnifiedRAG instance (lazy load)."""
        if self._unified_rag is None:
            from .unified_memory import get_unified_rag
            self._unified_rag = get_unified_rag()
        return self._unified_rag
    
    def _populate(self):
        """Populate index with security-enriched tool definitions (legacy mode only)."""
        print("📚 Initializing security-enriched tool index...")
        
        documents, metadatas, ids = [], [], []
        
        for tool in TOOL_DEFINITIONS:
            # Build security-enriched embedding document
            requires = ", ".join(tool.get("requires", [])) or "none"
            doc = f"""
TOOL: {tool["name"]}
PHASE: {tool.get("phase", "unknown")} pentest phase
ATTACK TYPE: {tool.get("attack_type", "unknown")} attack technique
REQUIRES: {requires} prerequisites
CATEGORY: {tool["category"]}
DESCRIPTION: {tool["description"]}
KEYWORDS: {" ".join(tool["keywords"])}
USE WHEN: {" ".join(tool["examples"])}
""".strip()
            
            documents.append(doc)
            metadatas.append({
                "name": tool["name"],
                "category": tool["category"],
                "phase": tool.get("phase", "unknown"),
                "attack_type": tool.get("attack_type", "unknown"),
                "requires": ",".join(tool.get("requires", [])),
                "description": tool["description"],
            })
            ids.append(tool["name"])
        
        self.collection.add(documents=documents, metadatas=metadatas, ids=ids)
        print(f"   ✓ Indexed {len(documents)} tools with security metadata")
    
    def search(self, query: str, n_results: int = 5) -> List[Dict]:
        """
        Search for matching tools.
        
        In unified mode: Returns command-level results with tool, command, description.
        In legacy mode: Returns tool-level results with name, category, description.
        """
        if self.use_unified:
            # Use UnifiedRAG for command-level search
            rag = self._get_unified()
            results = rag.search_tools(query, n_results=n_results)
            
            # Convert to expected format for backward compatibility
            tools = []
            seen_tools = set()
            for r in results:
                tool_name = r.get("tool", r.get("name", ""))
                if tool_name not in seen_tools:
                    tools.append({
                        "name": tool_name,
                        "command": r.get("command", ""),
                        "category": r.get("category", ""),
                        "description": r.get("description", ""),
                        "score": r.get("score", 0.5),
                    })
                    seen_tools.add(tool_name)
            return tools
        
        # Legacy mode
        results = self.collection.query(
            query_texts=[query],
            n_results=n_results,
            include=["metadatas", "distances"],
        )
        
        tools = []
        if results["metadatas"] and results["metadatas"][0]:
            for i, meta in enumerate(results["metadatas"][0]):
                distance = results["distances"][0][i] if results["distances"] else 0
                tools.append({
                    "name": meta["name"],
                    "category": meta["category"],
                    "description": meta["description"],
                    "score": 1.0 - (distance / 2.0),
                })
        
        return tools
    
    def refresh(self):
        """Refresh the index."""
        if self.use_unified:
            rag = self._get_unified()
            rag.rebuild_tool_index()
        else:
            self.client.delete_collection("tools")
            self.collection = self.client.create_collection(
                name="tools",
                metadata={"description": "SNODE security tools"}
            )
            self._populate()

