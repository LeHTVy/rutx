"""
Function Calling Support for FunctionGemma
==========================================

Converts tool registry to function definitions for FunctionGemma.
"""
from typing import List, Dict, Any


def tools_to_function_definitions(tools: List[str], registry) -> List[Dict[str, Any]]:
    """
    Convert tool names to OpenAI function calling format for FunctionGemma.
    
    Args:
        tools: List of tool names
        registry: ToolRegistry instance
        
    Returns:
        List of function definitions in OpenAI format
    """
    function_definitions = []
    
    for tool_name in tools:
        spec = registry.tools.get(tool_name)
        if not spec:
            continue
        
        properties = {}
        required = []
        
        if tool_name in ["subfinder", "amass", "bbot", "dig", "whois"]:
            properties["domain"] = {
                "type": "string",
                "description": f"Target domain for {tool_name}"
            }
            required.append("domain")
        elif tool_name in ["nmap", "masscan", "rustscan", "naabu"]:
            properties["target"] = {
                "type": "string",
                "description": f"Target host or IP for {tool_name}"
            }
            properties["ports"] = {
                "type": "string",
                "description": "Ports to scan (e.g., '80,443' or '1-1000')",
                "default": "--top-ports 1000"
            }
            required.append("target")
        elif tool_name in ["httpx", "katana", "gobuster", "ffuf", "nikto", "nuclei", "wpscan"]:
            properties["url"] = {
                "type": "string",
                "description": f"Target URL for {tool_name}"
            }
            required.append("url")
        elif tool_name in ["hydra", "medusa"]:
            properties["target"] = {
                "type": "string",
                "description": "Target host or IP"
            }
            properties["service"] = {
                "type": "string",
                "description": "Service to brute force (ssh, ftp, rdp, etc.)"
            }
            required.extend(["target", "service"])
        else:
            # Generic tool
            properties["target"] = {
                "type": "string",
                "description": f"Target for {tool_name}"
            }
            required.append("target")
        
        function_def = {
            "type": "function",
            "function": {
                "name": tool_name,
                "description": spec.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required
                }
            }
        }
        
        function_definitions.append(function_def)
    
    return function_definitions


def parse_tool_calls(tool_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Parse tool_calls from FunctionGemma response.
    
    Args:
        tool_calls: List of tool call objects from FunctionGemma
        
    Returns:
        List of parsed tool calls with name and arguments
    """
    parsed = []
    
    for tool_call in tool_calls:
        function = tool_call.get("function", {})
        name = function.get("name", "")
        arguments_str = function.get("arguments", "{}")
        
        # Parse arguments JSON string
        import json
        try:
            arguments = json.loads(arguments_str) if isinstance(arguments_str, str) else arguments_str
        except:
            arguments = {}
        
        parsed.append({
            "tool": name,
            "arguments": arguments,
            "id": tool_call.get("id", "")
        })
    
    return parsed
