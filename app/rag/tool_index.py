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


# Tool definitions for the index - COMPREHENSIVE LIST
TOOL_DEFINITIONS = [
    # === PORT SCANNING ===
    {
        "name": "nmap",
        "category": "port_scan",
        "description": "Port scanner with service and version detection",
        "keywords": ["port scan", "service detection", "network scan", "open ports", "tcp", "udp"],
        "examples": ["scan ports", "what ports are open", "nmap scan", "check services"],
    },
    {
        "name": "masscan",
        "category": "port_scan",
        "description": "Ultra-fast port scanner for large IP ranges",
        "keywords": ["fast port scan", "large scale", "mass scan", "quick scan"],
        "examples": ["fast port scan", "scan all ports quickly", "masscan"],
    },
    {
        "name": "httpx",
        "category": "port_scan",
        "description": "HTTP probe to check live web servers and grab titles",
        "keywords": ["http probe", "web servers", "live hosts", "http status"],
        "examples": ["probe hosts", "check web servers", "http probe"],
    },
    
    # === SUBDOMAIN ENUMERATION ===
    {
        "name": "bbot",
        "category": "subdomain",
        "description": "OSINT automation for subdomain enumeration and recon",
        "keywords": ["subdomain", "enumerate", "osint", "discovery", "recon"],
        "examples": ["find subdomains", "subdomain enumeration", "bbot scan"],
    },
    {
        "name": "amass",
        "category": "subdomain",
        "description": "In-depth attack surface mapping and subdomain enumeration",
        "keywords": ["subdomain", "attack surface", "passive recon", "dns"],
        "examples": ["find subdomains", "amass enum", "attack surface"],
    },
    {
        "name": "subfinder",
        "category": "subdomain",
        "description": "Fast passive subdomain discovery using OSINT sources",
        "keywords": ["subdomain", "passive", "fast discovery"],
        "examples": ["quick subdomain scan", "subfinder", "passive subdomains"],
    },
    
    # === VULNERABILITY SCANNING ===
    {
        "name": "nuclei",
        "category": "vuln_scan",
        "description": "Template-based vulnerability scanner with CVE detection",
        "keywords": ["vulnerability", "CVE", "security scan", "template scan", "vuln"],
        "examples": ["scan for vulnerabilities", "check CVEs", "nuclei scan"],
    },
    {
        "name": "nikto",
        "category": "vuln_scan",
        "description": "Web server vulnerability scanner for misconfigurations",
        "keywords": ["web vulnerability", "web server scan", "misconfiguration", "web security"],
        "examples": ["scan web server", "nikto scan", "web vulnerabilities", "check web security"],
    },
    {
        "name": "wpscan",
        "category": "vuln_scan",
        "description": "WordPress vulnerability scanner",
        "keywords": ["wordpress", "cms", "wp vulnerabilities", "wordpress scan"],
        "examples": ["scan wordpress", "wpscan", "wp vulnerabilities"],
    },
    
    # === SQL INJECTION ===
    {
        "name": "sqlmap",
        "category": "vuln_scan",
        "description": "Automated SQL injection detection and exploitation",
        "keywords": ["sql injection", "sqli", "database", "injection"],
        "examples": ["test sql injection", "sqlmap", "check for sqli"],
    },
    
    # === DIRECTORY/FILE DISCOVERY ===
    {
        "name": "gobuster",
        "category": "web_discovery",
        "description": "Directory and file brute-forcing tool",
        "keywords": ["directory", "brute force", "hidden files", "path discovery"],
        "examples": ["find hidden directories", "gobuster", "directory scan"],
    },
    {
        "name": "ffuf",
        "category": "web_discovery",
        "description": "Fast web fuzzer for directories, parameters, and endpoints",
        "keywords": ["fuzz", "web fuzzing", "parameter discovery", "fast fuzzer"],
        "examples": ["fuzz endpoints", "ffuf", "parameter fuzzing"],
    },
    {
        "name": "feroxbuster",
        "category": "web_discovery",
        "description": "Fast recursive content discovery tool",
        "keywords": ["recursive", "content discovery", "directory scan"],
        "examples": ["recursive directory scan", "feroxbuster"],
    },
    {
        "name": "katana",
        "category": "web_discovery",
        "description": "Web crawler to discover endpoints and URLs",
        "keywords": ["crawler", "spider", "endpoint discovery", "url discovery"],
        "examples": ["crawl website", "katana", "find endpoints"],
    },
    
    # === BRUTE FORCE ===
    {
        "name": "hydra",
        "category": "brute_force",
        "description": "Network login cracker for SSH, FTP, HTTP, etc.",
        "keywords": ["brute force", "password crack", "login attack", "credential"],
        "examples": ["brute force ssh", "hydra attack", "crack password"],
    },
    {
        "name": "john",
        "category": "brute_force",
        "description": "John the Ripper password hash cracker",
        "keywords": ["hash crack", "password", "john the ripper"],
        "examples": ["crack hash", "john", "password cracking"],
    },
    {
        "name": "hashcat",
        "category": "brute_force",
        "description": "Advanced GPU-accelerated password recovery",
        "keywords": ["hash", "gpu crack", "password recovery"],
        "examples": ["hashcat", "gpu crack", "hash cracking"],
    },
    
    # === OSINT ===
    {
        "name": "theHarvester",
        "category": "osint",
        "description": "Gather emails, subdomains, hosts from public sources",
        "keywords": ["email harvest", "osint", "public sources", "gathering"],
        "examples": ["gather emails", "theharvester", "osint gathering"],
    },
    {
        "name": "shodan",
        "category": "osint",
        "description": "Search engine for internet-connected devices",
        "keywords": ["shodan", "internet search", "iot", "exposed devices"],
        "examples": ["shodan search", "find exposed devices"],
    },
    {
        "name": "searchsploit",
        "category": "exploit",
        "description": "Search Exploit-DB for known exploits",
        "keywords": ["exploit", "exploit-db", "known vulnerabilities", "cve exploit"],
        "examples": ["find exploits", "searchsploit", "exploit search"],
    },
    {
        "name": "msfconsole",
        "category": "exploit",
        "description": "Metasploit Framework for CVE exploitation and post-exploitation",
        "keywords": ["metasploit", "msfconsole", "exploit", "cve", "module", "shell", "payload", "post-exploitation", "msf"],
        "examples": ["use metasploit", "msfconsole", "exploit CVE", "run metasploit module", "get shell"],
    },
    {
        "name": "recon-ng",
        "category": "osint",
        "description": "Full-featured OSINT reconnaissance framework with modules for hosts, contacts, and subdomains",
        "keywords": ["recon-ng", "osint", "reconnaissance", "framework", "contacts", "emails", "hosts", "intelligence"],
        "examples": ["use recon-ng", "osint framework", "gather intelligence", "recon framework", "find contacts"],
    },
    
    # === DNS/WHOIS ===
    {
        "name": "whois",
        "category": "recon",
        "description": "Domain registration and ownership lookup",
        "keywords": ["whois", "domain info", "registration", "ownership"],
        "examples": ["whois lookup", "domain registration", "who owns"],
    },
    {
        "name": "dig",
        "category": "recon",
        "description": "DNS lookup and zone transfer testing",
        "keywords": ["dns", "zone transfer", "dns lookup", "records"],
        "examples": ["dns lookup", "dig", "zone transfer"],
    },
    {
        "name": "dnsrecon",
        "category": "recon",
        "description": "DNS enumeration and zone transfer",
        "keywords": ["dns enumeration", "dns recon", "zone transfer"],
        "examples": ["dns enumeration", "dnsrecon"],
    },
    
    # === WEB ANALYSIS ===
    {
        "name": "whatweb",
        "category": "web_analysis",
        "description": "Web technology fingerprinting",
        "keywords": ["technology", "fingerprint", "cms", "framework detection"],
        "examples": ["identify technology", "whatweb", "tech stack"],
    },
    {
        "name": "wafw00f",
        "category": "web_analysis",
        "description": "Web Application Firewall detection",
        "keywords": ["waf", "firewall", "waf detection"],
        "examples": ["detect waf", "wafw00f", "check firewall"],
    },
    
    # === NETWORK ===
    {
        "name": "nc",
        "category": "network",
        "description": "Netcat for network connections and port testing",
        "keywords": ["netcat", "connection", "banner grab"],
        "examples": ["netcat connect", "banner grab", "nc"],
    },
    {
        "name": "enum4linux",
        "category": "network",
        "description": "Windows/Samba enumeration tool",
        "keywords": ["smb", "windows", "samba", "shares", "enumeration"],
        "examples": ["enumerate windows", "smb shares", "enum4linux"],
    },
    {
        "name": "crackmapexec",
        "category": "network",
        "description": "Swiss army knife for pentesting Windows/Active Directory",
        "keywords": ["active directory", "windows", "smb", "ldap", "ad"],
        "examples": ["cme", "crackmapexec", "ad attack"],
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
        """Populate index with tool definitions (legacy mode only)."""
        print("📚 Initializing tool index...")
        
        documents, metadatas, ids = [], [], []
        
        for tool in TOOL_DEFINITIONS:
            doc = " ".join([
                tool["name"],
                tool["description"],
                " ".join(tool["keywords"]),
                " ".join(tool["examples"]),
            ])
            
            documents.append(doc)
            metadatas.append({
                "name": tool["name"],
                "category": tool["category"],
                "description": tool["description"],
            })
            ids.append(tool["name"])
        
        self.collection.add(documents=documents, metadatas=metadatas, ids=ids)
        print(f"   ✓ Indexed {len(documents)} tools")
    
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

