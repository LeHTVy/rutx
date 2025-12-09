"""
Amass Tools Module
OWASP Amass - In-depth attack surface mapping and asset discovery

Correct Usage:
  amass enum -d example.com                    # Basic enumeration
  amass enum -passive -d example.com           # Passive only
  amass enum -active -d example.com -p 80,443  # Active mode with ports
  amass enum -brute -d example.com             # With brute forcing
  amass intel -d example.com -whois            # Intelligence gathering

Examples from docs:
  amass enum -d example.com
  amass enum -brute -min-for-recursive 2 -d example.com
  amass enum --passive -d example.com
  amass intel -whois -d example.com
"""

import subprocess
import json
import os
import shutil
import time
import threading
from datetime import datetime
from utils.command_runner import CommandRunner


def _find_amass_executable() -> str:
    """Find amass executable - check snap and common paths"""
    # Check common paths first (snap is where it's often installed on Ubuntu)
    home = os.path.expanduser("~")
    paths = [
        "/snap/bin/amass",  # Ubuntu snap
        f"{home}/go/bin/amass",
        "/home/hellrazor/go/bin/amass",  # Explicit for sudo
        "/usr/local/bin/amass",
        "/usr/bin/amass",
    ]
    
    for path in paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    
    # Check system PATH
    which_result = shutil.which("amass")
    if which_result:
        return which_result
    
    return "amass"  # Fallback


def _run_subprocess_with_output(cmd, timeout):
    """
    Run subprocess while draining output to prevent blocking.
    Returns (stdout_lines, elapsed_time).
    """
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    stdout_lines = []

    # Collect stdout, drain stderr
    def drain_stderr(pipe):
        try:
            for _ in pipe:
                pass
        except Exception:
            pass
        finally:
            pipe.close()

    def collect_stdout(pipe):
        try:
            for line in pipe:
                stdout_lines.append(line)
        except Exception:
            pass
        finally:
            pipe.close()

    stdout_thread = threading.Thread(target=collect_stdout, args=(process.stdout,))
    stderr_thread = threading.Thread(target=drain_stderr, args=(process.stderr,))
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()

    start_time = time.time()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise

    elapsed = time.time() - start_time

    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)

    return ''.join(stdout_lines), elapsed


def amass_enum(domain, passive=False, brute=False, timeout=1800):
    """
    Perform subdomain enumeration using Amass enum subcommand.
    Uses stdout parsing for reliable subdomain extraction.

    Commands:
      amass enum -d example.com
      amass enum -passive -d example.com
      amass enum -brute -d example.com

    Args:
        domain: Target domain to enumerate
        passive: Use passive reconnaissance only (no active probing)
        brute: Enable brute force subdomain enumeration
        timeout: Timeout in seconds (default: 1800 = 30 minutes)

    Returns:
        dict: Structured result with subdomains found
    """
    try:
        # Generate output file path for saving results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = domain.replace('.', '_').replace('/', '_')
        output_dir = "/tmp/amass_scans"
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"amass_{safe_domain}_{timestamp}.txt")

        # Build command - note: -json flag has issues in some amass versions
        # So we parse stdout instead which is more reliable
        cmd = [_find_amass_executable(), "enum", "-d", domain]

        if passive:
            cmd.append("-passive")
        elif brute:
            cmd.append("-brute")

        print(f"  Running: {' '.join(cmd)}")

        # Use non-blocking subprocess execution
        stdout, elapsed = _run_subprocess_with_output(cmd, timeout)

        # Parse stdout - Amass outputs one subdomain per line, then ASN info
        subdomains = []
        asn_info = []
        ip_ranges = []
        current_asn = None
        
        if stdout:
            for line in stdout.strip().split('\n'):
                line = line.strip()
                # Skip empty lines and error messages
                if not line or line.startswith('Error') or line.startswith('Failed'):
                    continue
                if line.startswith('OWASP Amass') or line.startswith('---') or 'has finished' in line.lower():
                    continue
                if 'names discovered' in line.lower():
                    continue
                if 'being migrat' in line.lower():
                    continue
                    
                # Parse ASN lines: "ASN: 14061 - DIGITALOCEAN-ASN - DigitalOcean, LLC"
                if line.startswith('ASN:'):
                    import re
                    asn_match = re.match(r'ASN:\s*(\d+)\s*-\s*(\S+)\s*-?\s*(.*)', line)
                    if asn_match:
                        current_asn = {
                            "asn": asn_match.group(1),
                            "name": asn_match.group(2),
                            "org": asn_match.group(3).strip() if asn_match.group(3) else asn_match.group(2),
                            "ranges": []
                        }
                        asn_info.append(current_asn)
                    continue
                
                # Parse IP range lines (indented, under ASN)
                if line.startswith('\t') or (current_asn and '/' in line and 'Subdomain' in line):
                    import re
                    range_match = re.match(r'\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+(\d+)\s+Subdomain', line)
                    if range_match and current_asn:
                        current_asn["ranges"].append({
                            "cidr": range_match.group(1),
                            "subdomain_count": int(range_match.group(2))
                        })
                        ip_ranges.append(range_match.group(1))
                    continue
                
                # Check if line contains the domain (is a valid subdomain)
                if domain in line and '.' in line:
                    # Handle case where line might have extra info
                    if ' ' not in line:
                        subdomains.append(line)
                    else:
                        # Extract subdomain from line with spaces
                        parts = line.split()
                        for part in parts:
                            if domain in part and '.' in part:
                                subdomains.append(part)
                                break

        subdomains = sorted(set(subdomains))  # Remove duplicates and sort

        # Save subdomains to file for database integration
        if subdomains:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(subdomains))
            except Exception:
                pass

        return {
            "success": True,
            "tool": "amass_enum",
            "domain": domain,
            "mode": "passive" if passive else ("brute" if brute else "active"),
            "subdomains_found": len(subdomains),
            "subdomains": subdomains,
            # NEW: ASN/ISP information for security analysis
            "asn_info": asn_info,
            "ip_ranges": ip_ranges,
            "hosting_providers": [asn["org"] for asn in asn_info] if asn_info else [],
            "json_output_file": output_file if os.path.exists(output_file) else None,
            "elapsed_seconds": round(elapsed, 2),
            "command": ' '.join(cmd),
            "summary": f"Amass enum found {len(subdomains)} subdomains for {domain}" + (f" across {len(asn_info)} ASNs" if asn_info else ""),
            "raw_output": stdout[:2000] if stdout else None,
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Amass enumeration timed out after {timeout} seconds",
            "domain": domain,
            "hint": "Try using -passive for faster results"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "amass command not found.",
            "install_hint": "Install: sudo apt install amass"
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "domain": domain
        }


def amass_intel(domain, whois=True, timeout=1800):
    """
    Gather intelligence on a target domain using Amass intel subcommand.

    Correct commands:
      amass intel -d example.com
      amass intel -whois -d example.com

    Args:
        domain: Target domain
        whois: Include WHOIS information (default: True)
        timeout: Timeout in seconds (default: 1800 = 30 minutes)

    Returns:
        dict: Intelligence data about the target
    """
    try:
        cmd = [_find_amass_executable(), "intel", "-d", domain]

        if whois:
            cmd.append("-whois")

        print(f"  Running: {' '.join(cmd)}")

        # Use non-blocking subprocess execution
        stdout, elapsed = _run_subprocess_with_output(cmd, timeout)

        # Parse intelligence data
        intel_data = []
        if stdout:
            for line in stdout.strip().split('\n'):
                line = line.strip()
                if line:
                    intel_data.append(line)

        return {
            "success": True,
            "tool": "amass_intel",
            "domain": domain,
            "whois": whois,
            "intelligence_entries": len(intel_data),
            "data": intel_data,
            "elapsed_seconds": round(elapsed, 2),
            "command": ' '.join(cmd),
            "summary": f"Amass intel found {len(intel_data)} entries for {domain}",
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Amass intel timed out after {timeout} seconds",
            "domain": domain
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "amass command not found."
        }
    except Exception as ex:
        return {
            "success": False,
            "error": f"{type(ex).__name__}: {ex}",
            "domain": domain
        }


def amass_db_list(domain=None):
    """
    List data in the Amass graph database.

    Command: amass db -list [-d domain]

    Args:
        domain: Optional domain to filter results

    Returns:
        dict: Database contents
    """
    try:
        cmd = [_find_amass_executable(), "db", "-list"]

        if domain:
            cmd.extend(["-d", domain])

        exec_result = CommandRunner.run(cmd, timeout=60)

        if not exec_result.success:
            return {
                "success": False,
                "error": exec_result.error,
                "stderr": exec_result.stderr
            }

        db_entries = []
        if exec_result.stdout:
            db_entries = [line.strip() for line in exec_result.stdout.strip().split('\n') if line.strip()]

        return {
            "success": True,
            "tool": "amass_db_list",
            "domain": domain or "all",
            "entries_found": len(db_entries),
            "entries": db_entries,
            "command": ' '.join(cmd),
            "timestamp": datetime.now().isoformat()
        }

    except Exception as ex:
        return {"success": False, "error": str(ex)}


AMASS_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "amass_enum",
            "description": "Subdomain enumeration using OWASP Amass. Best for: 'find subdomains', 'enumerate subdomains', 'discover assets'. Supports passive, active, and brute force modes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain (e.g., 'example.com')"},
                    "passive": {"type": "boolean", "description": "Use passive reconnaissance only (no probing) - default: false"},
                    "brute": {"type": "boolean", "description": "Enable brute force subdomain enumeration - default: false"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 1800)"}
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "amass_intel",
            "description": "Gather intelligence on target domain using Amass intel. Best for: 'domain intelligence', 'WHOIS lookup', 'organization reconnaissance'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain for intelligence gathering"},
                    "whois": {"type": "boolean", "description": "Include WHOIS information - default: true"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 1800)"}
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "amass_db_list",
            "description": "List historical data from Amass graph database. Shows previously discovered assets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Optional domain to filter database results"}
                },
                "required": []
            }
        }
    }
]


def execute_amass_tool(tool_name, tool_args):
    """Execute an Amass tool by name with given arguments"""
    tools_map = {
        "amass_enum": amass_enum,
        "amass_intel": amass_intel,
        "amass_db_list": amass_db_list
    }

    if tool_name not in tools_map:
        return {"success": False, "error": f"Unknown Amass tool '{tool_name}'"}

    try:
        return tools_map[tool_name](**tool_args)
    except TypeError as e:
        return {"success": False, "error": f"Invalid arguments for {tool_name}: {e}"}
    except Exception as e:
        return {"success": False, "error": f"Error executing {tool_name}: {e}"}
