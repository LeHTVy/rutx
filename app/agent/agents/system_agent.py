"""
System Agent - Handles System Self-Awareness Actions
=====================================================

Handles requests like:
- "create a wordlist"
- "check if tool X is installed"
- "find existing wordlists"
- "what resources do you have?"
"""

from typing import Dict, Any, List
from .base_agent import BaseAgent


class SystemAgent(BaseAgent):
    """
    Agent for system self-awareness and utility actions.
    
    Capabilities:
    - Find and create wordlists
    - Check tool availability
    - Manage workspace
    - Report system resources
    """
    
    AGENT_NAME = "system"
    AGENT_DESCRIPTION = "System utilities - wordlists, resources, workspace management"
    SPECIALIZED_TOOLS = []  # Uses internal system capabilities, not external tools
    PENTEST_PHASES = [1, 2, 3, 4, 5, 6]  
    
    # Keywords that suggest system tasks
    SYSTEM_KEYWORDS = [
        "wordlist", "create wordlist", "generate wordlist", "make wordlist",
        "check tool", "is installed", "have wordlist", "find wordlist",
        "workspace", "resources", "what do you have", "available"
    ]
    
    def __init__(self, llm=None):
        super().__init__(llm)
        self.name = self.AGENT_NAME
        self.description = self.AGENT_DESCRIPTION
        
        # Import system modules
        from app.system.resources import get_system_resources
        from app.system.wordlist_generator import get_wordlist_generator
        
        self.resources = get_system_resources()
        self.wordlist_gen = get_wordlist_generator()
    
    def can_handle(self, phase: int, query: str) -> bool:
        """Check if this is a system request."""
        query_lower = query.lower()
        return any(kw in query_lower for kw in self.SYSTEM_KEYWORDS)
    
    def plan(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan system action based on query.
        """
        action_type = self._classify_action(query, context)
        
        result = {
            "agent": self.AGENT_NAME,
            "tools": [],  # No external tools
            "commands": {},
            "action_type": action_type,
            "reasoning": ""
        }
        
        if action_type == "create_wordlist":
            result["reasoning"] = "Creating custom wordlist for target"
        elif action_type == "find_resource":
            result["reasoning"] = "Searching for existing resources"
        elif action_type == "tool_check":
            result["reasoning"] = "Checking tool availability"
        else:
            result["reasoning"] = "System resource query"
        
        return result
    
    def _classify_action(self, query: str, context: Dict[str, Any]) -> str:
        """Classify the type of system action."""
        query_lower = query.lower()
        
        if any(kw in query_lower for kw in ["create wordlist", "generate wordlist", "make wordlist"]):
            return "create_wordlist"
        if any(kw in query_lower for kw in ["find", "check", "have", "available", "exist"]):
            if "wordlist" in query_lower:
                return "find_wordlist"
            return "find_resource"
        if any(kw in query_lower for kw in ["installed", "tool"]):
            return "tool_check"
        
        return "list_resources"
    
    def execute(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the system action.
        
        Returns structured result with action outcome.
        """
        action_type = self._classify_action(query, context)
        target = context.get("target_domain") or context.get("last_domain") or "target"
        tech_stack = context.get("detected_tech", [])
        
        result = {
            "success": True,
            "action": action_type,
            "output": "",
            "created_files": []
        }
        
        try:
            if action_type == "create_wordlist":
                result = self._create_wordlist(query, target, tech_stack, context)
            elif action_type == "find_wordlist":
                result = self._find_wordlists(query)
            elif action_type == "find_resource":
                result = self._list_resources()
            elif action_type == "tool_check":
                result = self._check_tools(query)
            else:
                result = self._list_resources()
                
        except Exception as e:
            result["success"] = False
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def _create_wordlist(self, query: str, target: str, tech_stack: List[str], context: Dict[str, Any]) -> Dict[str, Any]:
        """Create a custom wordlist."""
        query_lower = query.lower()
        
        # Determine wordlist type
        if "password" in query_lower:
            path = self.wordlist_gen.generate_password_wordlist(target, context)
            wl_type = "password"
        elif "subdomain" in query_lower:
            path = self.wordlist_gen.generate_subdomain_wordlist(target)
            wl_type = "subdomain"
        else:
            # Default to directory wordlist
            path = self.wordlist_gen.generate_directory_wordlist(target, tech_stack)
            wl_type = "directory"
        
        # Count lines
        with open(path, 'r') as f:
            line_count = sum(1 for _ in f)
        
        return {
            "success": True,
            "action": "create_wordlist",
            "output": f"✅ Created {wl_type} wordlist: {path}\n   📊 {line_count:,} entries",
            "created_files": [path],
            "wordlist_path": path
        }
    
    def _find_wordlists(self, query: str) -> Dict[str, Any]:
        """Find existing wordlists."""
        query_lower = query.lower()
        
        # Determine category
        category = None
        if "password" in query_lower:
            category = "passwords"
        elif "dir" in query_lower:
            category = "dirs"
        elif "subdomain" in query_lower:
            category = "subdomains"
        
        wordlists = self.resources.get_wordlists(category)
        
        if not wordlists:
            output = "No wordlists found in system."
            if category:
                output = f"No {category} wordlists found."
        else:
            output = f"Found {len(wordlists)} wordlist(s):\n"
            for w in wordlists[:10]:
                output += f"  • {w.path} ({w.line_count:,} lines, {w.category})\n"
        
        return {
            "success": True,
            "action": "find_wordlist",
            "output": output,
            "wordlists": [w.to_dict() for w in wordlists]
        }
    
    def _list_resources(self) -> Dict[str, Any]:
        """List all available resources."""
        summary = self.resources.get_summary()
        
        return {
            "success": True,
            "action": "list_resources",
            "output": summary
        }
    
    def _check_tools(self, query: str) -> Dict[str, Any]:
        """Check if tools are installed."""
        # Extract tool names from query
        common_tools = [
            "nmap", "masscan", "gobuster", "dirsearch", "nikto", "nuclei",
            "sqlmap", "hydra", "ffuf", "subfinder", "amass", "httpx"
        ]
        
        query_lower = query.lower()
        tools_to_check = [t for t in common_tools if t in query_lower]
        
        if not tools_to_check:
            tools_to_check = common_tools[:6]  # Check first 6 by default
        
        output = "Tool availability:\n"
        for tool in tools_to_check:
            info = self.resources.get_tool(tool)
            status = "✅" if info.available else "❌"
            output += f"  {status} {tool}"
            if info.available:
                output += f" ({info.path})"
            output += "\n"
        
        return {
            "success": True,
            "action": "tool_check",
            "output": output
        }
    
    def analyze_results(self, results: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Format results for display."""
        if "output" in results:
            return results["output"]
        return "System action completed."
