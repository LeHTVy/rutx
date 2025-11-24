"""
Tools Module - Wrapper-Based Architecture
Provides wrapper functions for security scanning tools (Nmap, Amass, BBOT, Shodan)
"""

import json
import os
from datetime import datetime

# Wrapper-based tools
from .nmap_tools import NMAP_TOOLS, execute_tool as execute_nmap_tool
from .amass_tools import AMASS_TOOLS, execute_amass_tool
from .bbot_tools import BBOT_TOOLS, execute_bbot_tool
from .shodan_tools import SHODAN_TOOLS, execute_shodan_tool

# ============================================================================
# OUTPUT MANAGEMENT (inline)
# ============================================================================

SCAN_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "scan_results")


def _ensure_output_dir():
    os.makedirs(SCAN_OUTPUT_DIR, exist_ok=True)
    return SCAN_OUTPUT_DIR


def read_scan_output(filename):
    """Read saved scan output from file"""
    _ensure_output_dir()
    filepath = os.path.join(SCAN_OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filename}"}
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {"error": str(e)}


def list_scan_outputs(tool_name=None, limit=20):
    """List saved scan output files"""
    _ensure_output_dir()
    files = []
    for item in sorted(os.listdir(SCAN_OUTPUT_DIR), reverse=True):
        if tool_name and not item.startswith(tool_name):
            continue
        item_path = os.path.join(SCAN_OUTPUT_DIR, item)
        if os.path.isfile(item_path) and item.endswith('.json'):
            files.append({"filename": item, "path": item_path})
        elif os.path.isdir(item_path):
            files.append({"filename": item, "path": item_path, "type": "directory"})
        if len(files) >= limit:
            break
    return files


# Aliases
list_scan_results = list_scan_outputs
read_tool_output = read_scan_output
process_tool_output = lambda tool_name, target, output, force_save=False: output


OUTPUT_MANAGER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_scan_output",
            "description": "Read complete scan output from a saved file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Name of the output file"}
                },
                "required": ["filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_scan_outputs",
            "description": "List available saved scan output files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string", "description": "Filter by tool name"},
                    "limit": {"type": "integer", "description": "Max files (default: 20)"}
                },
                "required": []
            }
        }
    }
]


def execute_output_manager_tool(tool_name, tool_args):
    if tool_name == "read_scan_output":
        return read_scan_output(**tool_args)
    elif tool_name == "list_scan_outputs":
        return list_scan_outputs(**tool_args)
    return {"error": f"Unknown tool: {tool_name}"}


# ============================================================================
# COMBINE ALL TOOLS
# ============================================================================

ALL_TOOLS = NMAP_TOOLS + AMASS_TOOLS + BBOT_TOOLS + SHODAN_TOOLS + OUTPUT_MANAGER_TOOLS


def get_all_tool_names():
    return [tool['function']['name'] for tool in ALL_TOOLS]


def _coerce_tool_args(tool_args: dict) -> dict:
    """Convert string arguments from LLM to proper Python types."""
    coerced = dict(tool_args)
    for field in ['timeout', 'limit', 'num_ports', 'port']:
        if field in coerced and isinstance(coerced[field], str):
            try:
                coerced[field] = int(coerced[field])
            except ValueError:
                pass
    for field in ['passive', 'brute', 'whois', 'force_save']:
        if field in coerced and isinstance(coerced[field], str):
            coerced[field] = coerced[field].lower() in ('true', '1', 'yes')
    return coerced


def execute_tool(tool_name: str, tool_args: dict):
    """Universal tool executor"""
    tool_args = _coerce_tool_args(tool_args)

    if tool_name in [t['function']['name'] for t in NMAP_TOOLS]:
        return execute_nmap_tool(tool_name, tool_args)
    if tool_name in [t['function']['name'] for t in AMASS_TOOLS]:
        return execute_amass_tool(tool_name, tool_args)
    if tool_name in [t['function']['name'] for t in BBOT_TOOLS]:
        return execute_bbot_tool(tool_name, tool_args)
    if tool_name in [t['function']['name'] for t in SHODAN_TOOLS]:
        return execute_shodan_tool(tool_name, tool_args)
    if tool_name in [t['function']['name'] for t in OUTPUT_MANAGER_TOOLS]:
        return execute_output_manager_tool(tool_name, tool_args)

    return {"error": f"Unknown tool: {tool_name}"}


__all__ = [
    'ALL_TOOLS', 'execute_tool', 'get_all_tool_names',
    'read_scan_output', 'list_scan_outputs', 'list_scan_results',
    'read_tool_output', 'process_tool_output'
]
