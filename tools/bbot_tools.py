"""
BBOT Tools Module
BinaryEdge Bot (BBOT) - Recursive internet scanner

Correct Usage:
  bbot -t TARGET -p PRESET       # Use preset
  bbot -t TARGET -f FLAG         # Use flag (safe, passive, etc.)
  bbot -t TARGET -m MODULE       # Use specific modules
  bbot -t TARGET -o DIR --json   # Output to directory with JSON
  bbot -t TARGET -y              # Skip confirmation

Examples:
  bbot -t evilcorp.com -p subdomain-enum
  bbot -t evilcorp.com -p subdomain-enum -rf passive
  bbot -t evilcorp.com -p web-basic
"""

import subprocess
import json
import os
import time
from datetime import datetime
from pathlib import Path


def _run_subprocess_with_drain(cmd, timeout):
    """
    Run subprocess while draining stdout/stderr to prevent blocking.
    Returns (returncode, elapsed_time) - output is written to files by bbot.

    Uses DEVNULL to completely suppress output and avoid terminal I/O issues.
    """
    # Completely suppress stdout/stderr to avoid terminal I/O blocking
    # BBOT writes its results to JSON files anyway
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL
    )

    start_time = time.time()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise

    elapsed = time.time() - start_time

    return process.returncode, elapsed


def bbot_scan(target, preset=None, modules=None, flags=None, output_dir=None, timeout=600):
    """Perform BBOT scan on target with specified preset or modules."""
    try:
        if output_dir is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = target.replace('.', '_').replace('/', '_').replace(':', '_')
            output_dir = f"/tmp/bbot_{safe_target}_{timestamp}"

        os.makedirs(output_dir, exist_ok=True)

        cmd = ["bbot", "-t", target]

        if preset:
            cmd.extend(["-p", preset])
        elif modules:
            module_list = [m.strip() for m in modules.split(',')]
            cmd.extend(["-m"] + module_list)
        elif flags:
            cmd.extend(["-f", flags])
        else:
            cmd.extend(["-f", "safe"])

        # BBOT exports JSON and other outputs by default
        cmd.extend(["-o", output_dir, "-y"])

        print(f"  Running: {' '.join(cmd)}")

        # Use non-blocking subprocess execution
        _, elapsed = _run_subprocess_with_drain(cmd, timeout)

        findings = []
        subdomains = []
        event_types = {}

        # Normalize target for filtering (e.g., "snode.com" -> ".snode.com")
        target_lower = target.lower().strip()
        target_suffix = f".{target_lower}" if not target_lower.startswith('.') else target_lower

        # BBOT creates output in nested directories with JSON/NDJSON files
        files_to_check = list(Path(output_dir).rglob("*.json"))
        files_to_check.extend(list(Path(output_dir).rglob("*.ndjson")))

        # Track first JSON file for database integration
        json_output_file = None

        for json_file in files_to_check:
            if json_output_file is None:
                json_output_file = str(json_file)
            try:
                with open(json_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                entry = json.loads(line.strip())
                                findings.append(entry)
                                event_type = entry.get('type', 'unknown')
                                event_types[event_type] = event_types.get(event_type, 0) + 1
                                if event_type in ('DNS_NAME', 'HOST'):
                                    data = entry.get('data', '')
                                    if isinstance(data, dict):
                                        data = data.get('host', '') or data.get('dns_name', '')
                                    if data:
                                        data_str = str(data).lower().strip()
                                        # Only include if it's the target or a subdomain of target
                                        if data_str == target_lower or data_str.endswith(target_suffix):
                                            subdomains.append(str(data))
                            except json.JSONDecodeError:
                                continue
            except Exception:
                continue

        # Also check for subdomains.txt
        for txt_file in Path(output_dir).rglob("subdomains.txt"):
            try:
                with open(txt_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            line_lower = line.lower()
                            # Only include if it's the target or a subdomain of target
                            if line_lower == target_lower or line_lower.endswith(target_suffix):
                                subdomains.append(line)
            except Exception:
                continue

        # Deduplicate and sort subdomains
        unique_subdomains = sorted(set(subdomains))

        return {
            "success": True,
            "tool": "bbot_scan",
            "target": target,
            "preset": preset,
            "output_directory": output_dir,
            "json_output_file": json_output_file,  # For database integration
            "elapsed_seconds": round(elapsed, 2),
            "findings_count": len(findings),
            "subdomains_found": len(unique_subdomains),
            "subdomains": unique_subdomains[:100],  # Increased limit
            "event_types": event_types,
            "command": ' '.join(cmd),
            "summary": f"BBOT scan: {len(findings)} events, {len(unique_subdomains)} unique subdomains",
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timed out after {timeout}s", "target": target}
    except FileNotFoundError:
        return {"success": False, "error": "bbot not found. Install: pipx install bbot"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": target}


def bbot_subdomain_enum(target, passive=False, timeout=600):
    """Subdomain enumeration using BBOT subdomain-enum preset."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace('.', '_').replace('/', '_')
        output_dir = f"/tmp/bbot_subdomain_{safe_target}_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        # BBOT exports JSON and subdomains.txt by default
        cmd = ["bbot", "-t", target, "-p", "subdomain-enum"]
        if passive:
            cmd.extend(["-rf", "passive"])
        cmd.extend(["-o", output_dir, "-y"])

        print(f"  Running: {' '.join(cmd)}")

        # Use non-blocking subprocess execution
        _, elapsed = _run_subprocess_with_drain(cmd, timeout)

        subdomains = []
        findings = []

        # Normalize target for filtering (e.g., "snode.com" -> ".snode.com")
        target_lower = target.lower().strip()
        target_suffix = f".{target_lower}" if not target_lower.startswith('.') else target_lower

        # BBOT creates output in: output_dir/scan_name/output.json
        # Also check for output.ndjson and subdomains.txt
        files_to_check = list(Path(output_dir).rglob("*.json"))
        files_to_check.extend(list(Path(output_dir).rglob("*.ndjson")))

        # Track first JSON file for database integration
        json_output_file = None

        for json_file in files_to_check:
            if json_output_file is None:
                json_output_file = str(json_file)
            try:
                with open(json_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                entry = json.loads(line.strip())
                                findings.append(entry)
                                event_type = entry.get('type', '')
                                # Capture DNS_NAME and HOST events that are in-scope
                                if event_type in ('DNS_NAME', 'HOST'):
                                    data = entry.get('data', '')
                                    # Extract domain from data (may be dict or string)
                                    if isinstance(data, dict):
                                        data = data.get('host', '') or data.get('dns_name', '')
                                    if data:
                                        data_str = str(data).lower().strip()
                                        # Only include if it's the target or a subdomain of target
                                        if data_str == target_lower or data_str.endswith(target_suffix):
                                            subdomains.append(str(data))
                            except json.JSONDecodeError:
                                continue
            except Exception:
                continue

        # Also check for subdomains.txt (BBOT may output this - already filtered by BBOT)
        for txt_file in Path(output_dir).rglob("subdomains.txt"):
            try:
                with open(txt_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            line_lower = line.lower()
                            # Only include if it's the target or a subdomain of target
                            if line_lower == target_lower or line_lower.endswith(target_suffix):
                                subdomains.append(line)
            except Exception:
                continue

        subdomains = sorted(set(subdomains))

        return {
            "success": True,
            "tool": "bbot_subdomain_enum",
            "target": target,
            "mode": "passive" if passive else "active",
            "subdomains_found": len(subdomains),
            "subdomains": subdomains,
            "findings_count": len(findings),
            "output_directory": output_dir,
            "json_output_file": json_output_file,  # For database integration
            "elapsed_seconds": round(elapsed, 2),
            "command": ' '.join(cmd),
            "summary": f"BBOT subdomain-enum: {len(subdomains)} subdomains for {target}",
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timed out after {timeout}s", "target": target}
    except FileNotFoundError:
        return {"success": False, "error": "bbot not found. Install: pipx install bbot"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": target}


def bbot_web_scan(target, timeout=600):
    """Web-focused reconnaissance using BBOT web-basic preset."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace('.', '_').replace('/', '_').replace(':', '_')
        output_dir = f"/tmp/bbot_web_{safe_target}_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        # BBOT exports JSON and other outputs by default
        cmd = ["bbot", "-t", target, "-p", "web-basic", "-o", output_dir, "-y"]

        print(f"  Running: {' '.join(cmd)}")

        # Use non-blocking subprocess execution
        _, elapsed = _run_subprocess_with_drain(cmd, timeout)

        findings = []
        technologies = []
        urls = []
        json_output_file = None

        for json_file in Path(output_dir).rglob("*.json"):
            if json_output_file is None:
                json_output_file = str(json_file)
            try:
                with open(json_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                entry = json.loads(line.strip())
                                findings.append(entry)
                                if entry.get('type') == 'TECHNOLOGY':
                                    technologies.append(entry.get('data', ''))
                                elif entry.get('type') == 'URL':
                                    urls.append(entry.get('data', ''))
                            except json.JSONDecodeError:
                                continue
            except Exception:
                continue

        return {
            "success": True,
            "tool": "bbot_web_scan",
            "target": target,
            "preset": "web-basic",
            "findings_count": len(findings),
            "technologies": technologies[:20],
            "urls_found": len(urls),
            "output_directory": output_dir,
            "json_output_file": json_output_file,  # For database integration
            "elapsed_seconds": round(elapsed, 2),
            "command": ' '.join(cmd),
            "summary": f"BBOT web-basic: {len(findings)} events, {len(technologies)} technologies",
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timed out after {timeout}s", "target": target}
    except FileNotFoundError:
        return {"success": False, "error": "bbot not found. Install: pipx install bbot"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": target}


def bbot_quick_scan(target, timeout=300):
    """Quick scan with safe modules and fast mode."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace('.', '_').replace('/', '_').replace(':', '_')
        output_dir = f"/tmp/bbot_quick_{safe_target}_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        # BBOT exports JSON and other outputs by default
        cmd = ["bbot", "-t", target, "-f", "safe", "--fast-mode", "-o", output_dir, "-y"]

        print(f"  Running: {' '.join(cmd)}")

        # Use non-blocking subprocess execution
        _, elapsed = _run_subprocess_with_drain(cmd, timeout)

        findings = []
        event_types = {}
        json_output_file = None

        for json_file in Path(output_dir).rglob("*.json"):
            if json_output_file is None:
                json_output_file = str(json_file)
            try:
                with open(json_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                entry = json.loads(line.strip())
                                findings.append(entry)
                                event_type = entry.get('type', 'unknown')
                                event_types[event_type] = event_types.get(event_type, 0) + 1
                            except json.JSONDecodeError:
                                continue
            except Exception:
                continue

        return {
            "success": True,
            "tool": "bbot_quick_scan",
            "target": target,
            "flags": "safe",
            "findings_count": len(findings),
            "event_types": event_types,
            "output_directory": output_dir,
            "json_output_file": json_output_file,  # For database integration
            "elapsed_seconds": round(elapsed, 2),
            "command": ' '.join(cmd),
            "summary": f"BBOT quick scan: {len(findings)} events",
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timed out after {timeout}s", "target": target}
    except FileNotFoundError:
        return {"success": False, "error": "bbot not found. Install: pipx install bbot"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": target}


BBOT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "bbot_scan",
            "description": "Comprehensive BBOT scan with presets (subdomain-enum, web-basic, spider, kitchen-sink) or custom modules.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target domain, IP, or CIDR"},
                    "preset": {"type": "string", "description": "BBOT preset: subdomain-enum, web-basic, spider, kitchen-sink"},
                    "modules": {"type": "string", "description": "Comma-separated modules"},
                    "flags": {"type": "string", "description": "Module flags: safe, passive, aggressive"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 600)"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bbot_subdomain_enum",
            "description": "Subdomain enumeration using BBOT subdomain-enum preset. Best for finding subdomains.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target domain"},
                    "passive": {"type": "boolean", "description": "Use passive techniques only (default: false)"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 600)"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bbot_web_scan",
            "description": "Web reconnaissance using BBOT web-basic preset. Discovers technologies and endpoints.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target domain or URL"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 600)"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bbot_quick_scan",
            "description": "Quick BBOT scan with safe modules and fast mode.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target domain, IP, or range"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 300)"}
                },
                "required": ["target"]
            }
        }
    }
]


def execute_bbot_tool(tool_name, tool_args):
    """Execute a BBOT tool by name with given arguments"""
    tools_map = {
        "bbot_scan": bbot_scan,
        "bbot_subdomain_enum": bbot_subdomain_enum,
        "bbot_web_scan": bbot_web_scan,
        "bbot_quick_scan": bbot_quick_scan
    }

    if tool_name not in tools_map:
        return {"success": False, "error": f"Unknown BBOT tool '{tool_name}'"}

    try:
        return tools_map[tool_name](**tool_args)
    except TypeError as e:
        return {"success": False, "error": f"Invalid arguments for {tool_name}: {e}"}
    except Exception as e:
        return {"success": False, "error": f"Error executing {tool_name}: {e}"}
