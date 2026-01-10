"""
Unified RAG System for SNODE
============================

Central RAG manager with multiple ChromaDB collections:
- tools_commands: Tool and command metadata for semantic search
- conversations: Indexed conversation history for context recall
- Integrates with existing cve_rag.py for CVE lookups

Provides:
- Command-level tool search
- Conversation context retrieval  
- CVE-to-tool recommendations (LLM-based)
"""
import os
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
import chromadb
from chromadb.config import Settings

from app.core.config import get_config


class UnifiedRAG:
    """
    Unified RAG system with tools, conversations, and CVE collections.
    
    This is the central interface for all RAG operations in SNODE.
    """
    
    _instance: Optional["UnifiedRAG"] = None
    
    def __init__(self):
        config = get_config()
        persist_dir = str(config.chroma_persist_dir / "unified_rag")
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        
        self.client = chromadb.PersistentClient(
            path=persist_dir,
            settings=Settings(anonymized_telemetry=False)
        )
        
        # Tool + Command collection
        self.tools_collection = self.client.get_or_create_collection(
            name="tools_commands",
            metadata={"description": "SNODE security tools and their commands"}
        )
        
        # Conversation memory collection
        self.conv_collection = self.client.get_or_create_collection(
            name="conversations",
            metadata={"description": "Indexed conversation history"}
        )
        
        # Session findings collection - persistent scan results
        self.findings_collection = self.client.get_or_create_collection(
            name="session_findings",
            metadata={"description": "Persistent scan findings (subdomains, hosts, vulns)"}
        )
        
        # Lazy-loaded components
        self._tool_index_populated = False
        self._cve_db = None
        self._embedding_model = None
        
        # Populate tools on first use
        self._ensure_tools_indexed()
    
    @classmethod
    def get_instance(cls) -> "UnifiedRAG":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = UnifiedRAG()
        return cls._instance
    
    def _get_embedding(self, text: str) -> List[float]:
        """Get embedding for text using Ollama."""
        if self._embedding_model is None:
            try:
                import ollama
                self._embedding_model = "nomic-embed-text"
            except ImportError:
                # Fallback to simple word embedding
                return self._simple_embedding(text)
        
        try:
            import ollama
            response = ollama.embeddings(model=self._embedding_model, prompt=text)
            return response.get("embedding", self._simple_embedding(text))
        except Exception:
            return self._simple_embedding(text)
    
    def _simple_embedding(self, text: str, dim: int = 384) -> List[float]:
        """Simple fallback embedding based on word frequencies."""
        import hashlib
        words = text.lower().split()
        embedding = [0.0] * dim
        
        for word in words:
            h = int(hashlib.md5(word.encode()).hexdigest(), 16)
            for i in range(dim):
                embedding[i] += ((h >> i) & 1) * 0.1 - 0.05
        
        # Normalize
        norm = sum(x * x for x in embedding) ** 0.5
        if norm > 0:
            embedding = [x / norm for x in embedding]
        
        return embedding
    
    def _ensure_tools_indexed(self):
        """Ensure tool metadata is indexed in ChromaDB."""
        if self._tool_index_populated:
            return
        
        # Check if already populated
        if self.tools_collection.count() > 0:
            self._tool_index_populated = True
            return
        
        # Populate from tool_metadata
        from .tool_metadata import TOOL_METADATA
        
        ids = []
        documents = []
        metadatas = []
        
        for tool_name, tool_data in TOOL_METADATA.items():
            for cmd_name, cmd_data in tool_data.get("commands", {}).items():
                # Create searchable document combining all relevant text
                doc_parts = [
                    tool_name,
                    cmd_name,
                    tool_data.get("description", ""),
                    cmd_data.get("description", ""),
                    " ".join(cmd_data.get("use_cases", [])),
                    " ".join(tool_data.get("tags", [])),
                ]
                doc = " ".join(doc_parts)
                
                doc_id = f"{tool_name}:{cmd_name}"
                ids.append(doc_id)
                documents.append(doc)
                metadatas.append({
                    "tool": tool_name,
                    "command": cmd_name,
                    "category": tool_data.get("category", ""),
                    "description": cmd_data.get("description", ""),
                    "params": ",".join(cmd_data.get("params", [])),
                })
        
        if ids:
            # Add in batches to avoid memory issues
            batch_size = 100
            for i in range(0, len(ids), batch_size):
                batch_ids = ids[i:i+batch_size]
                batch_docs = documents[i:i+batch_size]
                batch_meta = metadatas[i:i+batch_size]
                
                self.tools_collection.add(
                    ids=batch_ids,
                    documents=batch_docs,
                    metadatas=batch_meta,
                )
            
            print(f"  📚 Indexed {len(ids)} tool commands in UnifiedRAG")
        
        self._tool_index_populated = True
    
    def search_tools(self, query: str, n_results: int = 5, 
                     category: str = None) -> List[Dict[str, Any]]:
        """
        Semantic search for tools and commands.
        
        Returns list of matches with tool, command, description, and score.
        """
        self._ensure_tools_indexed()
        
        where_filter = None
        if category:
            where_filter = {"category": category}
        
        results = self.tools_collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where_filter,
            include=["metadatas", "documents", "distances"]
        )
        
        matches = []
        if results and results.get("ids") and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results.get("metadatas") else {}
                distance = results["distances"][0][i] if results.get("distances") else 0
                
                # Convert distance to similarity score (0-1, higher is better)
                score = max(0, 1 - distance)
                
                matches.append({
                    "id": doc_id,
                    "tool": meta.get("tool", doc_id.split(":")[0]),
                    "command": meta.get("command", ""),
                    "category": meta.get("category", ""),
                    "description": meta.get("description", ""),
                    "params": meta.get("params", "").split(",") if meta.get("params") else [],
                    "score": score,
                })
        
        return matches
    
    def add_conversation_turn(self, user_msg: str, ai_msg: str,
                              tools_used: List[str] = None,
                              domain: str = None,
                              session_id: str = None):
        """
        Index conversation turn for semantic recall.
        
        Stores both user query and AI response for future context retrieval.
        """
        doc_id = f"conv_{uuid.uuid4().hex[:12]}"
        
        # Create searchable document
        doc_parts = [user_msg]
        if ai_msg:
            # Take first 500 chars of AI response for indexing
            doc_parts.append(ai_msg[:500])
        if tools_used:
            doc_parts.append(f"Tools used: {', '.join(tools_used)}")
        
        doc = " ".join(doc_parts)
        
        metadata = {
            "type": "conversation",
            "domain": domain or "",
            "session_id": session_id or "",
            "tools": ",".join(tools_used) if tools_used else "",
            "user_query": user_msg[:200],  # Truncate for metadata
        }
        
        self.conv_collection.add(
            ids=[doc_id],
            documents=[doc],
            metadatas=[metadata],
        )
    
    def add_tool_execution(self, tool_name: str, command: str,
                          output_summary: str, domain: str = None,
                          session_id: str = None):
        """
        Index tool execution result for semantic recall.
        
        Allows future queries like "what did we find on example.com"
        to retrieve relevant tool outputs.
        """
        doc_id = f"exec_{uuid.uuid4().hex[:12]}"
        
        doc = f"Tool: {tool_name} Command: {command}. Domain: {domain or 'unknown'}. Result: {output_summary[:500]}"
        
        metadata = {
            "type": "tool_execution",
            "tool": tool_name,
            "command": command,
            "domain": domain or "",
            "session_id": session_id or "",
        }
        
        self.conv_collection.add(
            ids=[doc_id],
            documents=[doc],
            metadatas=[metadata],
        )
    
    def get_relevant_context(self, query: str, domain: str = None,
                             n_results: int = 3) -> Dict[str, Any]:
        """
        Get relevant context from conversation history.
        
        Returns:
        - similar_conversations: Past relevant exchanges
        - tool_executions: Past relevant tool outputs
        """
        where_filter = None
        if domain:
            where_filter = {"domain": domain}
        
        results = self.conv_collection.query(
            query_texts=[query],
            n_results=n_results * 2,  # Get more, then filter
            where=where_filter,
            include=["metadatas", "documents", "distances"]
        )
        
        conversations = []
        tool_executions = []
        
        if results and results.get("ids") and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results.get("metadatas") else {}
                doc = results["documents"][0][i] if results.get("documents") else ""
                distance = results["distances"][0][i] if results.get("distances") else 1
                
                item = {
                    "id": doc_id,
                    "content": doc[:300],
                    "domain": meta.get("domain", ""),
                    "score": max(0, 1 - distance),
                }
                
                if meta.get("type") == "tool_execution":
                    item["tool"] = meta.get("tool", "")
                    item["command"] = meta.get("command", "")
                    tool_executions.append(item)
                else:
                    item["user_query"] = meta.get("user_query", "")
                    conversations.append(item)
        
        return {
            "similar_conversations": conversations[:n_results],
            "tool_executions": tool_executions[:n_results],
        }
    
    def search_cves_for_tech(self, technologies: List[str], 
                             n_per_tech: int = 3) -> List[Dict]:
        """
        Search for CVEs related to detected technologies.
        
        Uses the existing CVEDatabase for semantic search.
        """
        if self._cve_db is None:
            try:
                from .cve_rag import get_cve_database
                self._cve_db = get_cve_database()
            except Exception:
                return []
        
        if not self._cve_db:
            return []
        
        all_cves = []
        seen_ids = set()
        
        for tech in technologies[:5]:  # Limit to 5 techs
            try:
                results = self._cve_db.search(
                    query=tech,
                    n_results=n_per_tech,
                    severity_filter=["critical", "high"]
                )
                
                for cve in results:
                    cve_id = cve.get("cve_id", "")
                    if cve_id and cve_id not in seen_ids:
                        seen_ids.add(cve_id)
                        all_cves.append(cve)
            except Exception:
                continue
        
        return all_cves
    
    def get_tool_for_cve(self, cve_id: str) -> List[str]:
        """
        Get recommended tools for a specific CVE.
        
        Returns tools that can detect or exploit the CVE.
        """
        # CVE detection is best done with nuclei
        recommendations = ["nuclei"]
        
        # Get CVE details to determine other relevant tools
        if self._cve_db is None:
            try:
                from .cve_rag import get_cve_database
                self._cve_db = get_cve_database()
            except Exception:
                return recommendations
        
        try:
            cve_info = self._cve_db.get(cve_id)
            if cve_info:
                desc = cve_info.get("description", "").lower()
                
                # Add relevant tools based on CVE description
                if "sql injection" in desc or "sqli" in desc:
                    recommendations.append("sqlmap")
                if "xss" in desc or "cross-site scripting" in desc:
                    recommendations.append("dalfox")
                if "rce" in desc or "remote code execution" in desc:
                    recommendations.extend(["msfconsole", "searchsploit"])
                if "smb" in desc or "samba" in desc:
                    recommendations.extend(["crackmapexec", "enum4linux"])
        except Exception:
            pass
        
        return list(dict.fromkeys(recommendations))  # Remove duplicates
    
    # ============================================================
    # SESSION FINDINGS - Persistent scan results storage
    # ============================================================
    
    def add_subdomain(self, subdomain: str, domain: str, ip: str = None,
                      source: str = None, session_id: str = None):
        """Store discovered subdomain in RAG for cross-session persistence."""
        from datetime import datetime
        
        doc_id = f"sub_{subdomain.replace('.', '_')}_{domain.replace('.', '_')}"
        
        # Create searchable document
        doc = f"Subdomain {subdomain} of {domain}. IP: {ip or 'unknown'}. Source: {source or 'unknown'}."
        
        metadata = {
            "type": "subdomain",
            "subdomain": subdomain,
            "domain": domain,
            "ip": ip or "",
            "source": source or "",
            "session_id": session_id or "",
            "timestamp": datetime.now().isoformat(),
        }
        
        # Upsert to avoid duplicates
        try:
            self.findings_collection.upsert(
                ids=[doc_id],
                documents=[doc],
                metadatas=[metadata],
            )
        except Exception as e:
            print(f"  ⚠️ Failed to store subdomain: {e}")
    
    def add_host(self, ip: str, hostname: str = None, ports: List[int] = None,
                 services: Dict[int, str] = None, domain: str = None,
                 session_id: str = None):
        """Store discovered host with ports in RAG."""
        from datetime import datetime
        
        doc_id = f"host_{ip.replace('.', '_')}"
        
        # Create searchable document
        port_info = ", ".join([f"{p}/{services.get(p, 'unknown')}" for p in (ports or [])]) if ports else "no ports scanned"
        doc = f"Host {ip} ({hostname or 'unknown'}). Open ports: {port_info}. Domain: {domain or 'unknown'}."
        
        metadata = {
            "type": "host",
            "ip": ip,
            "hostname": hostname or "",
            "ports": ",".join(map(str, ports or [])),
            "domain": domain or "",
            "session_id": session_id or "",
            "timestamp": datetime.now().isoformat(),
        }
        
        try:
            self.findings_collection.upsert(
                ids=[doc_id],
                documents=[doc],
                metadatas=[metadata],
            )
        except Exception as e:
            print(f"  ⚠️ Failed to store host: {e}")
    
    def add_vulnerability(self, vuln_type: str, severity: str, target: str,
                         details: str = None, cve_id: str = None,
                         tool: str = None, domain: str = None,
                         session_id: str = None):
        """Store discovered vulnerability in RAG."""
        from datetime import datetime
        import hashlib
        
        # Create unique ID based on content
        hash_input = f"{vuln_type}{target}{details or ''}"
        doc_id = f"vuln_{hashlib.md5(hash_input.encode()).hexdigest()[:12]}"
        
        doc = f"{severity.upper()} vulnerability: {vuln_type} on {target}. {details or ''}. CVE: {cve_id or 'N/A'}."
        
        metadata = {
            "type": "vulnerability",
            "vuln_type": vuln_type,
            "severity": severity,
            "target": target,
            "cve_id": cve_id or "",
            "tool": tool or "",
            "domain": domain or "",
            "session_id": session_id or "",
            "timestamp": datetime.now().isoformat(),
        }
        
        try:
            self.findings_collection.upsert(
                ids=[doc_id],
                documents=[doc],
                metadatas=[metadata],
            )
        except Exception as e:
            print(f"  ⚠️ Failed to store vulnerability: {e}")
    
    def get_findings_for_domain(self, domain: str, finding_type: str = None,
                                n_results: int = 100) -> Dict[str, List[Dict]]:
        """
        Retrieve all findings for a specific domain.
        
        Returns dict with: subdomains, hosts, vulnerabilities
        """
        where_filter = {"domain": domain}
        if finding_type:
            where_filter = {"$and": [{"domain": domain}, {"type": finding_type}]}
        
        try:
            results = self.findings_collection.query(
                query_texts=[f"findings for {domain}"],
                n_results=n_results,
                where=where_filter,
                include=["metadatas", "documents"]
            )
        except Exception:
            # Fallback without filter
            results = self.findings_collection.query(
                query_texts=[domain],
                n_results=n_results,
                include=["metadatas", "documents"]
            )
        
        findings = {"subdomains": [], "hosts": [], "vulnerabilities": []}
        
        if results and results.get("metadatas") and results["metadatas"][0]:
            for meta in results["metadatas"][0]:
                ftype = meta.get("type", "")
                if ftype == "subdomain":
                    findings["subdomains"].append({
                        "subdomain": meta.get("subdomain", ""),
                        "ip": meta.get("ip", ""),
                        "source": meta.get("source", ""),
                    })
                elif ftype == "host":
                    findings["hosts"].append({
                        "ip": meta.get("ip", ""),
                        "hostname": meta.get("hostname", ""),
                        "ports": meta.get("ports", "").split(",") if meta.get("ports") else [],
                    })
                elif ftype == "vulnerability":
                    findings["vulnerabilities"].append({
                        "type": meta.get("vuln_type", ""),
                        "severity": meta.get("severity", ""),
                        "target": meta.get("target", ""),
                        "cve_id": meta.get("cve_id", ""),
                    })
        
        return findings
    
    def search_findings(self, query: str, n_results: int = 20) -> List[Dict]:
        """Semantic search across all session findings."""
        results = self.findings_collection.query(
            query_texts=[query],
            n_results=n_results,
            include=["metadatas", "documents", "distances"]
        )
        
        findings = []
        if results and results.get("metadatas") and results["metadatas"][0]:
            for i, meta in enumerate(results["metadatas"][0]):
                distance = results["distances"][0][i] if results.get("distances") else 1
                findings.append({
                    **meta,
                    "score": max(0, 1 - distance),
                    "content": results["documents"][0][i] if results.get("documents") else "",
                })
        
        return findings
    
    def rebuild_tool_index(self):
        """Force rebuild of tool index (useful after metadata updates)."""
        # Delete existing
        try:
            self.client.delete_collection("tools_commands")
        except Exception:
            pass
        
        # Recreate
        self.tools_collection = self.client.get_or_create_collection(
            name="tools_commands",
            metadata={"description": "SNODE security tools and their commands"}
        )
        
        self._tool_index_populated = False
        self._ensure_tools_indexed()
    
    def get_stats(self) -> Dict[str, int]:
        """Get collection statistics."""
        return {
            "tools_commands": self.tools_collection.count(),
            "conversations": self.conv_collection.count(),
            "session_findings": self.findings_collection.count(),
        }


# Singleton accessor
_unified_rag: Optional[UnifiedRAG] = None


def get_unified_rag() -> UnifiedRAG:
    """Get the singleton UnifiedRAG instance."""
    global _unified_rag
    if _unified_rag is None:
        _unified_rag = UnifiedRAG()
    return _unified_rag
