"""
Output Manager Module
Handles large tool outputs by saving to files and providing summaries to LLM
Reduces token usage and improves performance for long scan results
"""

import json
import os
from datetime import datetime
from pathlib import Path


# Output directory configuration
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "scan_outputs")
MAX_INLINE_SIZE = 2000  # Characters - if output exceeds this, save to file


def ensure_output_dir():
    """Create output directory if it doesn't exist"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    return OUTPUT_DIR


def generate_output_filename(tool_name, target):
    """
    Generate unique filename for tool output

    Args:
        tool_name: Name of the tool that generated output
        target: Target that was scanned

    Returns:
        str: Filename for saving output
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace('.', '_').replace('/', '_').replace(':', '_')
    filename = f"{tool_name}_{safe_target}_{timestamp}.json"
    return filename


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
    filepath = os.path.join(OUTPUT_DIR, filename)

    # Prepare data structure
    output_data = {
        "tool": tool_name,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "metadata": metadata or {},
        "output": full_output
    }

    # Save to file
    with open(filepath, 'w') as f:
        json.dump(output_data, f, indent=2)

    # Create summary for LLM
    summary = create_output_summary(tool_name, full_output, filepath)

    return {
        "saved_to_file": True,
        "file_path": filepath,
        "file_name": filename,
        "summary": summary,
        "size_bytes": os.path.getsize(filepath)
    }


def create_output_summary(tool_name, output, filepath):
    """
    Create concise summary of tool output for LLM context

    Args:
        tool_name: Tool name
        output: Full output (string or dict)
        filepath: Path where full output is saved

    Returns:
        str: Concise summary
    """
    summary_parts = [
        f"📁 Output saved to file: {os.path.basename(filepath)}",
        f"🔧 Tool: {tool_name}",
        ""
    ]

    # Tool-specific summary extraction
    if isinstance(output, dict):
        # Extract key metrics
        if "subdomains_found" in output:
            summary_parts.append(f"✓ Subdomains found: {output['subdomains_found']}")
            if output.get('subdomains'):
                sample = output['subdomains'][:5]
                summary_parts.append(f"  Sample: {', '.join(sample)}")
                if len(output['subdomains']) > 5:
                    summary_parts.append(f"  ... and {len(output['subdomains']) - 5} more")

        if "ports_found" in output:
            summary_parts.append(f"✓ Open ports: {output.get('ports_found', 0)}")

        if "vulnerabilities" in output:
            summary_parts.append(f"⚠️  Vulnerabilities: {len(output['vulnerabilities'])}")

        # Generic key-value extraction
        for key in ["success", "host_status", "scan_type", "domain", "ip"]:
            if key in output:
                summary_parts.append(f"  {key}: {output[key]}")

        # Extract raw output preview
        if "raw_output" in output:
            raw = str(output["raw_output"])
            if len(raw) > 500:
                preview = raw[:500] + "... (truncated)"
            else:
                preview = raw
            summary_parts.append(f"\nOutput preview:\n{preview}")

    elif isinstance(output, str):
        # String output - provide preview
        if len(output) > 500:
            preview = output[:500] + "... (truncated)"
        else:
            preview = output
        summary_parts.append(f"Output preview:\n{preview}")

    summary_parts.append(f"\n💾 Full output available at: {filepath}")
    summary_parts.append(f"   Use read_scan_output('{os.path.basename(filepath)}') to access complete data")

    return "\n".join(summary_parts)


def should_save_to_file(output):
    """
    Determine if output should be saved to file based on size

    Args:
        output: Tool output (string or dict)

    Returns:
        bool: True if should save to file
    """
    output_str = json.dumps(output) if isinstance(output, dict) else str(output)
    return len(output_str) > MAX_INLINE_SIZE


def process_tool_output(tool_name, target, output, force_save=False):
    """
    Process tool output - either return inline or save to file

    Args:
        tool_name: Name of the tool
        target: Target that was scanned
        output: Tool output
        force_save: Force saving to file regardless of size

    Returns:
        dict or str: Processed output (inline or file reference)
    """
    if force_save or should_save_to_file(output):
        # Large output - save to file
        file_ref = save_tool_output(tool_name, target, output)
        return file_ref
    else:
        # Small output - return inline
        return output


def read_scan_output(filename):
    """
    Read saved scan output from file

    Args:
        filename: Name of the output file

    Returns:
        dict: Scan output data
    """
    filepath = os.path.join(OUTPUT_DIR, filename)

    if not os.path.exists(filepath):
        return {
            "error": f"File not found: {filename}",
            "available_files": list_scan_outputs()
        }

    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        return {
            "error": f"Failed to read file: {e}",
            "file": filename
        }


def list_scan_outputs(tool_name=None, limit=20):
    """
    List saved scan output files

    Args:
        tool_name: Optional filter by tool name
        limit: Maximum number of files to return

    Returns:
        list: List of output files with metadata
    """
    ensure_output_dir()

    files = []
    for filename in sorted(os.listdir(OUTPUT_DIR), reverse=True):
        if not filename.endswith('.json'):
            continue

        if tool_name and not filename.startswith(tool_name):
            continue

        filepath = os.path.join(OUTPUT_DIR, filename)
        stat = os.stat(filepath)

        files.append({
            "filename": filename,
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "path": filepath
        })

        if len(files) >= limit:
            break

    return files


def cleanup_old_outputs(days=7):
    """
    Clean up output files older than specified days

    Args:
        days: Delete files older than this many days

    Returns:
        dict: Cleanup statistics
    """
    ensure_output_dir()

    cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
    deleted_count = 0
    deleted_size = 0

    for filename in os.listdir(OUTPUT_DIR):
        if not filename.endswith('.json'):
            continue

        filepath = os.path.join(OUTPUT_DIR, filename)
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
# TOOL DEFINITIONS FOR LLM ACCESS
# ============================================================================

OUTPUT_MANAGER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_scan_output",
            "description": "Read complete scan output from a saved file. Use when you need to access full details from a previous scan that was saved to file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Name of the output file to read (e.g., 'nmap_192_168_1_1_20250121_143022.json')"
                    }
                },
                "required": ["filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_scan_outputs",
            "description": "List available saved scan output files. Use to see what scan results are available for analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Optional: Filter by tool name (e.g., 'nmap', 'shodan', 'amass')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of files to return (default: 20)"
                    }
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
        return {"error": f"Unknown output manager tool: {tool_name}"}

    try:
        return tools_map[tool_name](**tool_args)
    except Exception as e:
        return {"error": f"Error executing {tool_name}: {e}"}
