"""
Nikto Tools Module
Web server scanner for security testing
Provides comprehensive web vulnerability scanning capabilities
"""

import subprocess
import shlex
import json


def nikto_scan(target, port="80", ssl=False, options=""):
    """
    Run a basic Nikto web vulnerability scan on the specified target.

    Args:
        target: The target to scan (IP address or hostname)
        port: Port to scan (default: 80)
        ssl: Use SSL/HTTPS (default: False)
        options: Additional Nikto command line options

    Returns:
        str: The output of the Nikto scan
    """
    cmd_parts = ["nikto", "-h", target, "-p", str(port)]

    if ssl:
        cmd_parts.append("-ssl")

    # Add format output for better parsing
    cmd_parts.extend(["-Format", "txt"])

    if options:
        cmd_parts.extend(shlex.split(options))

    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=1800,  # 30 minutes timeout for comprehensive scans
            check=False
        )

        output = result.stdout if result.stdout else result.stderr

        if result.returncode != 0 and not output:
            return f"Error: Nikto returned non-zero exit code {result.returncode}\nStderr: {result.stderr}"

        return output

    except subprocess.TimeoutExpired:
        return "Error: Nikto scan timed out after 30 minutes"
    except FileNotFoundError:
        return "Error: nikto command not found. Please install Nikto first.\nInstall: apt-get install nikto (Linux) or download from https://github.com/sullo/nikto"
    except Exception as ex:
        return f"Error: {type(ex).__name__}: {ex}"


def nikto_quick_scan(target, port="80", ssl=False):
    """
    Perform a quick Nikto scan (limited tests for faster results).
    Equivalent to: nikto -h target -p port -Tuning x 1

    Args:
        target: The target to scan
        port: Port to scan (default: 80)
        ssl: Use SSL/HTTPS (default: False)

    Returns:
        str: Quick scan results
    """
    options = "-Tuning 1"
    return nikto_scan(target, port, ssl, options)


def nikto_full_scan(target, port="80", ssl=False):
    """
    Perform a comprehensive Nikto scan (all tests, very thorough).
    This will take longer but provide complete vulnerability assessment.

    Args:
        target: The target to scan
        port: Port to scan (default: 80)
        ssl: Use SSL/HTTPS (default: False)

    Returns:
        str: Comprehensive scan results
    """
    options = "-Tuning 123456789abc"
    return nikto_scan(target, port, ssl, options)


def nikto_ssl_scan(target, port="443"):
    """
    Scan HTTPS/SSL web server for vulnerabilities.
    Equivalent to: nikto -h target -p port -ssl

    Args:
        target: The target to scan
        port: SSL port to scan (default: 443)

    Returns:
        str: SSL scan results
    """
    return nikto_scan(target, port, ssl=True)


def nikto_common_ports_scan(target):
    """
    Scan common web ports (80, 443, 8080, 8443).

    Args:
        target: The target to scan

    Returns:
        str: Results from scanning multiple ports
    """
    ports = ["80", "443", "8080", "8443"]
    results = []

    for port in ports:
        ssl = True if port in ["443", "8443"] else False
        result = f"\n{'='*60}\nScanning port {port} ({'HTTPS' if ssl else 'HTTP'})\n{'='*60}\n"
        result += nikto_scan(target, port, ssl)
        results.append(result)

    return "\n".join(results)


def nikto_vulnerability_scan(target, port="80", ssl=False):
    """
    Focus on vulnerability detection (XSS, SQL injection, etc.).
    Equivalent to: nikto -h target -Tuning 9

    Args:
        target: The target to scan
        port: Port to scan (default: 80)
        ssl: Use SSL/HTTPS (default: False)

    Returns:
        str: Vulnerability scan results
    """
    options = "-Tuning 9"
    return nikto_scan(target, port, ssl, options)


def nikto_plugin_scan(target, plugins, port="80", ssl=False):
    """
    Run specific Nikto plugins for targeted scanning.

    Args:
        target: The target to scan
        plugins: Plugin name or list (e.g., "apache", "headers")
        port: Port to scan (default: 80)
        ssl: Use SSL/HTTPS (default: False)

    Returns:
        str: Plugin scan results
    """
    options = f"-Plugins {plugins}"
    return nikto_scan(target, port, ssl, options)


def nikto_mutation_scan(target, port="80", ssl=False):
    """
    Scan with mutation techniques for thorough testing.
    Equivalent to: nikto -h target -mutate 1

    Args:
        target: The target to scan
        port: Port to scan (default: 80)
        ssl: Use SSL/HTTPS (default: False)

    Returns:
        str: Mutation scan results
    """
    options = "-mutate 1"
    return nikto_scan(target, port, ssl, options)


def nikto_evasion_scan(target, port="80", ssl=False):
    """
    Scan using evasion techniques to bypass IDS/IPS.
    Equivalent to: nikto -h target -evasion 1

    Args:
        target: The target to scan
        port: Port to scan (default: 80)
        ssl: Use SSL/HTTPS (default: False)

    Returns:
        str: Evasion scan results
    """
    options = "-evasion 1"
    return nikto_scan(target, port, ssl, options)


def nikto_cgi_scan(target, port="80", ssl=False):
    """
    Scan for CGI vulnerabilities and issues.
    Equivalent to: nikto -h target -Tuning 8

    Args:
        target: The target to scan
        port: Port to scan (default: 80)
        ssl: Use SSL/HTTPS (default: False)

    Returns:
        str: CGI scan results
    """
    options = "-Tuning 8"
    return nikto_scan(target, port, ssl, options)


def nikto_auth_scan(target, username, password, port="80", ssl=False):
    """
    Scan with HTTP authentication.

    Args:
        target: The target to scan
        username: Username for authentication
        password: Password for authentication
        port: Port to scan (default: 80)
        ssl: Use SSL/HTTPS (default: False)

    Returns:
        str: Authenticated scan results
    """
    options = f"-id {username}:{password}"
    return nikto_scan(target, port, ssl, options)


# ============================================================================
# TOOL DEFINITIONS FOR OLLAMA
# ============================================================================

NIKTO_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "nikto_scan",
            "description": "Basic Nikto web vulnerability scan. Use for: 'scan website', 'web vulnerability check', 'nikto scan'. Checks for common web vulnerabilities, misconfigurations, and security issues.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port to scan (default: '80')"
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Use SSL/HTTPS (default: false)"
                    },
                    "options": {
                        "type": "string",
                        "description": "Additional Nikto options"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_quick_scan",
            "description": "Quick Nikto scan for faster results. Use for: 'quick web scan', 'fast nikto check'. Runs limited tests for rapid assessment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port to scan (default: '80')"
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Use SSL/HTTPS (default: false)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_full_scan",
            "description": "Comprehensive Nikto scan with all tests. Use for: 'thorough web scan', 'complete nikto scan', 'full web vulnerability assessment'. Very thorough but slower.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port to scan (default: '80')"
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Use SSL/HTTPS (default: false)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_ssl_scan",
            "description": "Scan HTTPS/SSL web server. Use for: 'scan HTTPS', 'SSL web scan', 'secure website scan', 'check port 443'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "string",
                        "description": "SSL port to scan (default: '443')"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_common_ports_scan",
            "description": "Scan common web ports (80, 443, 8080, 8443). Use for: 'scan all web ports', 'check common web services', 'comprehensive web port scan'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_vulnerability_scan",
            "description": "Focus on detecting web vulnerabilities (XSS, SQLi, etc.). Use for: 'check web vulnerabilities', 'find XSS', 'SQL injection scan', 'web security audit'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port to scan (default: '80')"
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Use SSL/HTTPS (default: false)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_plugin_scan",
            "description": "Run specific Nikto plugins for targeted scanning. Use for custom plugin-based tests.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "plugins": {
                        "type": "string",
                        "description": "Plugin name or list (e.g., 'apache', 'headers')"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port to scan (default: '80')"
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Use SSL/HTTPS (default: false)"
                    }
                },
                "required": ["target", "plugins"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_mutation_scan",
            "description": "Scan with mutation techniques for thorough testing. Use for enhanced vulnerability detection.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port to scan (default: '80')"
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Use SSL/HTTPS (default: false)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_cgi_scan",
            "description": "Scan for CGI vulnerabilities and issues. Use for: 'CGI scan', 'check CGI scripts', 'CGI security'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port to scan (default: '80')"
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Use SSL/HTTPS (default: false)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_auth_scan",
            "description": "Scan with HTTP authentication. Use when target requires username/password.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port to scan (default: '80')"
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Use SSL/HTTPS (default: false)"
                    }
                },
                "required": ["target", "username", "password"]
            }
        }
    }
]


# ============================================================================
# FUNCTION DISPATCHER
# ============================================================================

def execute_nikto_tool(tool_name, tool_args):
    """
    Execute a Nikto tool by name with given arguments

    Args:
        tool_name: Name of the tool function
        tool_args: Dictionary of arguments

    Returns:
        The result of the tool execution
    """
    tools_map = {
        "nikto_scan": nikto_scan,
        "nikto_quick_scan": nikto_quick_scan,
        "nikto_full_scan": nikto_full_scan,
        "nikto_ssl_scan": nikto_ssl_scan,
        "nikto_common_ports_scan": nikto_common_ports_scan,
        "nikto_vulnerability_scan": nikto_vulnerability_scan,
        "nikto_plugin_scan": nikto_plugin_scan,
        "nikto_mutation_scan": nikto_mutation_scan,
        "nikto_cgi_scan": nikto_cgi_scan,
        "nikto_auth_scan": nikto_auth_scan
    }

    if tool_name not in tools_map:
        return f"Error: Unknown Nikto tool '{tool_name}'"

    try:
        func = tools_map[tool_name]
        result = func(**tool_args)
        return result
    except TypeError as e:
        return f"Error: Invalid arguments for {tool_name}: {e}"
    except Exception as e:
        return f"Error executing {tool_name}: {e}"
