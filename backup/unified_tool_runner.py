"""
Output Management Module
Handles saving, reading, and listing scan outputs
(Merged from output_manager.py - native tool runners removed as wrapper tools are used)
"""

import json
import os
from datetime import datetime

# Output directory for all tool results
SCAN_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "scan_results")
MAX_INLINE_SIZE = 2000  # Characters - if output exceeds this, save to file


def ensure_output_dir():
    """Create output directory if it doesn't exist"""
    os.makedirs(SCAN_OUTPUT_DIR, exist_ok=True)
    return SCAN_OUTPUT_DIR


def generate_output_filename(tool_name, target):
    """Generate unique filename for tool output"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace('.', '_').replace('/', '_').replace(':', '_')
    return f"{tool_name}_{safe_target}_{timestamp}.json"


def save_tool_output(tool_name, target, full_output, metadata=None):
    """
    Save tool output to file and return file reference

    Args:
        tool_name: Name of the tool
        target: Target that was scanned
        full_output: Complete tool output (string or dict)
        metadata: Optional metadata dict

    Returns:
        dict: File reference with path and summary
    """
    ensure_output_dir()
    filename = generate_output_filename(tool_name, target)
    filepath = os.path.join(SCAN_OUTPUT_DIR, filename)

    output_data = {
        "tool": tool_name,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "metadata": metadata or {},
        "output": full_output
    }

    with open(filepath, 'w') as f:
        json.dump(output_data, f, indent=2)

    summary = create_output_summary(tool_name, full_output, filepath)

    return {
        "saved_to_file": True,
        "file_path": filepath,
        "file_name": filename,
        "summary": summary,
        "size_bytes": os.path.getsize(filepath)
    }


def create_output_summary(tool_name, output, filepath):
    """Create concise summary of tool output for LLM context"""
    summary_parts = [
        f"Output saved: {os.path.basename(filepath)}",
        f"Tool: {tool_name}",
    ]

    if isinstance(output, dict):
        if "subdomains_found" in output:
            summary_parts.append(f"Subdomains: {output['subdomains_found']}")
        if "ports_found" in output:
            summary_parts.append(f"Open ports: {output.get('ports_found', 0)}")
        if "vulnerabilities" in output:
            summary_parts.append(f"Vulnerabilities: {len(output['vulnerabilities'])}")

    summary_parts.append(f"Use read_scan_output('{os.path.basename(filepath)}') for full data")
    return " | ".join(summary_parts)


def should_save_to_file(output):
    """Determine if output should be saved to file based on size"""
    output_str = json.dumps(output) if isinstance(output, dict) else str(output)
    return len(output_str) > MAX_INLINE_SIZE


def process_tool_output(tool_name, target, output, force_save=False):
    """Process tool output - either return inline or save to file"""
    if force_save or should_save_to_file(output):
        return save_tool_output(tool_name, target, output)
    return output


def read_scan_output(filename):
    """Read saved scan output from file"""
    filepath = os.path.join(SCAN_OUTPUT_DIR, filename)

    if not os.path.exists(filepath):
        return {
            "error": f"File not found: {filename}",
            "available_files": [f["filename"] for f in list_scan_outputs()]
        }

    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {"error": f"Failed to read file: {e}", "file": filename}


def list_scan_outputs(tool_name=None, limit=20):
    """List saved scan output files"""
    ensure_output_dir()

    files = []
    for item in sorted(os.listdir(SCAN_OUTPUT_DIR), reverse=True):
        item_path = os.path.join(SCAN_OUTPUT_DIR, item)

        if tool_name and not item.startswith(tool_name):
            continue

        if os.path.isfile(item_path) and item.endswith('.json'):
            stat = os.stat(item_path)
            files.append({
                "type": "file",
                "filename": item,
                "path": item_path,
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        elif os.path.isdir(item_path):
            stat = os.stat(item_path)
            files.append({
                "type": "directory",
                "filename": item,
                "path": item_path,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })

        if len(files) >= limit:
            break

    return files


def read_tool_output(file_path):
    """Read and parse tool output JSON file (alias for compatibility)"""
    if os.path.basename(file_path) == file_path:
        return read_scan_output(file_path)
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {"error": f"Error reading file: {e}"}


def list_scan_results(tool_name=None, limit=20):
    """Alias for list_scan_outputs (compatibility)"""
    return list_scan_outputs(tool_name, limit)


def cleanup_old_outputs(days=7):
    """Clean up output files older than specified days"""
    ensure_output_dir()
    cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
    deleted_count = 0
    deleted_size = 0

    for filename in os.listdir(SCAN_OUTPUT_DIR):
        if not filename.endswith('.json'):
            continue

        filepath = os.path.join(SCAN_OUTPUT_DIR, filename)
        stat = os.stat(filepath)

        if stat.st_mtime < cutoff_time:
            deleted_size += stat.st_size
            os.remove(filepath)
            deleted_count += 1

    return {
        "deleted_files": deleted_count,
        "freed_bytes": deleted_size,
        "freed_mb": round(deleted_size / (1024 * 1024), 2)
    }


# ============================================================================
# LLM TOOL DEFINITIONS
# ============================================================================

OUTPUT_MANAGER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_scan_output",
            "description": "Read complete scan output from a saved file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Name of the output file to read"}
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
                    "tool_name": {"type": "string", "description": "Filter by tool name (nmap, shodan, amass, bbot)"},
                    "limit": {"type": "integer", "description": "Max files to return (default: 20)"}
                },
                "required": []
            }
        }
    }
]


def execute_output_manager_tool(tool_name, tool_args):
    """Execute output manager tool"""
    tools_map = {
        "read_scan_output": read_scan_output,
        "list_scan_outputs": list_scan_outputs
    }

    if tool_name not in tools_map:
        return {"error": f"Unknown tool: {tool_name}"}

    try:
        return tools_map[tool_name](**tool_args)
    except Exception as e:
        return {"error": f"Error: {e}"}
