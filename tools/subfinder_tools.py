"""
Subfinder Tool - Passive subdomain enumeration

Subfinder is a subdomain discovery tool that discovers subdomains 
for websites by using passive online sources.
"""
import shutil
from datetime import datetime
from typing import Any, Dict, List, Optional
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from utils.command_runner import CommandRunner


def _find_subfinder_executable() -> Optional[str]:
    """Find subfinder executable - check Go bin paths first"""
    import os
    
    # Check Go paths first (where it's typically installed)
    home = os.path.expanduser("~")
    go_paths = [
        f"{home}/go/bin/subfinder",
        "/home/hellrazor/go/bin/subfinder",  # Explicit for sudo
        "/usr/local/go/bin/subfinder",
    ]
    
    for path in go_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    
    # Check system PATH
    which_result = shutil.which("subfinder")
    if which_result:
        return which_result
    
    return None


def subfinder_enum(
    domain: str,
    all_sources: bool = False,
    recursive: bool = False,
    timeout: int = 1800,
) -> Dict[str, Any]:
    """
    Perform subdomain enumeration using Subfinder.
    Uses passive online sources to discover subdomains.
    
    Args:
        domain: Target domain to enumerate (e.g., 'example.com')
        all_sources: Use all sources for enumeration (slower but more thorough)
        recursive: Use only recursive sources
        timeout: Timeout in seconds (default: 1800 = 30 minutes)
    
    Returns:
        dict: Structured result with subdomains found
    """
    executable = _find_subfinder_executable()
    if not executable:
        return {
            "success": False,
            "error": "Subfinder not found. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "target": domain
        }
    
    try:
        # Build command
        cmd = [executable, "-d", domain, "-silent"]
        
        if all_sources:
            cmd.append("-all")
        
        if recursive:
            cmd.append("-recursive")
        
        # Set max-time in minutes (convert from seconds)
        max_time = max(1, timeout // 60)
        cmd.extend(["-max-time", str(max_time)])
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        if exec_result.returncode != 0 and not exec_result.stdout:
            return {
                "success": False,
                "error": exec_result.stderr or f"Subfinder failed with code {exec_result.returncode}",
                "target": domain
            }
        
        # Parse subdomains from stdout (one per line)
        subdomains = set()
        for line in exec_result.stdout.strip().split("\n"):
            line = line.strip()
            if line and "." in line:
                subdomains.add(line.lower())
        
        return {
            "success": True,
            "target": domain,
            "subdomains": sorted(subdomains),
            "count": len(subdomains),
            "elapsed_time": exec_result.elapsed_time,
            "sources": "passive" if not all_sources else "all",
        }
        
    except TimeoutError:
        return {
            "success": False,
            "error": f"Subfinder timed out after {timeout} seconds",
            "target": domain
        }
    except Exception as ex:
        return {
            "success": False,
            "error": str(ex),
            "target": domain
        }


# ─────────────────────────────────────────────────────────────────
# LangChain Tool Definition
# ─────────────────────────────────────────────────────────────────

class SubfinderEnumInput(BaseModel):
    """Input for subfinder enumeration"""
    domain: str = Field(description="Target domain (e.g., 'example.com')")
    all_sources: bool = Field(default=False, description="Use all sources (slower but thorough)")
    recursive: bool = Field(default=False, description="Use only recursive sources")
    timeout: int = Field(default=1800, description="Timeout in seconds (default: 1800)")


def _subfinder_enum_wrapper(
    domain: str,
    all_sources: bool = False,
    recursive: bool = False,
    timeout: int = 1800,
) -> str:
    """Wrapper for LangChain tool"""
    result = subfinder_enum(domain, all_sources, recursive, timeout)
    
    if not result.get("success"):
        return f"Error: {result.get('error', 'Unknown error')}"
    
    subdomains = result.get("subdomains", [])
    count = result.get("count", 0)
    elapsed = result.get("elapsed_time", 0)
    
    # Format output
    output = [
        f"✓ Subfinder found {count} subdomains for {domain}",
        f"  Sources: {result.get('sources', 'passive')}",
        f"  Time: {elapsed:.1f}s",
        "",
        "Subdomains:"
    ]
    
    for sub in subdomains[:50]:
        output.append(f"  • {sub}")
    
    if len(subdomains) > 50:
        output.append(f"  ... and {len(subdomains) - 50} more")
    
    return "\n".join(output)


# Create LangChain tool
subfinder_enum_tool = StructuredTool.from_function(
    func=_subfinder_enum_wrapper,
    name="subfinder_enum",
    description="Passive subdomain enumeration using Subfinder. Uses online sources like certificate transparency, DNS databases, search engines, etc. Fast and stealthy - no direct target probing.",
    args_schema=SubfinderEnumInput,
    return_direct=False,
)


def get_subfinder_tools() -> List[StructuredTool]:
    """Get all Subfinder tools"""
    return [subfinder_enum_tool]


# Tool metadata for registry
TOOL_METADATA = {
    "subfinder_enum": {
        "name": "subfinder_enum",
        "description": "Passive subdomain enumeration using Subfinder",
        "function": subfinder_enum,
        "args_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain (e.g., 'example.com')"},
                "all_sources": {"type": "boolean", "description": "Use all sources (slower) - default: false"},
                "recursive": {"type": "boolean", "description": "Use only recursive sources - default: false"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 1800)"}
            },
            "required": ["domain"]
        }
    }
}
