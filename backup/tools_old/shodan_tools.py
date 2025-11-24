"""
Shodan Tools Module
Threat intelligence and reconnaissance using Shodan API
"""

import requests
import json
from config import SHODAN_API_KEY

SHODAN_API_BASE = "https://api.shodan.io"


def shodan_lookup(ip):
    """
    Look up an IP address in Shodan to get host information and threat intelligence.

    Args:
        ip: IP address to look up

    Returns:
        dict: Shodan host information including open ports, services, vulnerabilities, and tags
    """
    try:
        url = f"{SHODAN_API_BASE}/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            data = response.json()

            # Extract key information
            result = {
                "ip": data.get("ip_str", ip),
                "organization": data.get("org", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "asn": data.get("asn", "Unknown"),
                "country": data.get("country_name", "Unknown"),
                "city": data.get("city", "Unknown"),
                "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []),
                "ports": data.get("ports", []),
                "tags": data.get("tags", []),
                "vulns": data.get("vulns", []),
                "last_update": data.get("last_update", "Unknown"),
                "services": []
            }

            # Extract service information
            for service in data.get("data", []):
                service_info = {
                    "port": service.get("port"),
                    "transport": service.get("transport", "tcp"),
                    "product": service.get("product", "Unknown"),
                    "version": service.get("version", ""),
                    "banner": service.get("data", "")[:200],  # Limit banner length
                    "timestamp": service.get("timestamp", "")
                }
                result["services"].append(service_info)

            # Threat assessment
            threat_indicators = []
            if data.get("tags"):
                for tag in data["tags"]:
                    if tag.lower() in ["malware", "botnet", "malicious", "compromised", "honeypot"]:
                        threat_indicators.append(f"Tagged as: {tag}")

            if data.get("vulns"):
                threat_indicators.append(f"Known vulnerabilities: {len(data['vulns'])} CVEs found")

            result["threat_indicators"] = threat_indicators
            result["threat_level"] = "HIGH" if threat_indicators else "UNKNOWN"

            return {
                "success": True,
                "data": result,
                "summary": f"Shodan lookup for {ip}: {len(result['ports'])} ports, {len(result['services'])} services, "
                          f"{len(result['vulns'])} known CVEs, Threat level: {result['threat_level']}"
            }

        elif response.status_code == 404:
            return {
                "success": True,
                "data": {"ip": ip, "status": "not_found"},
                "summary": f"IP {ip} not found in Shodan database (may indicate low internet exposure)"
            }

        else:
            return {
                "success": False,
                "error": f"Shodan API error: {response.status_code} - {response.text}",
                "summary": f"Failed to query Shodan for {ip}"
            }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "Shodan API request timed out",
            "summary": f"Timeout while querying Shodan for {ip}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"{type(e).__name__}: {str(e)}",
            "summary": f"Error querying Shodan for {ip}"
        }


def shodan_search(query, limit=10):
    """
    Search the Shodan database using a query string.

    Args:
        query: Shodan search query (e.g., "apache country:US", "port:22 country:CN")
        limit: Maximum number of results to return (default: 10, max: 100)

    Returns:
        dict: Search results with matching hosts
    """
    try:
        # Limit the number of results
        limit = min(limit, 100)

        url = f"{SHODAN_API_BASE}/shodan/host/search?key={SHODAN_API_KEY}&query={query}&limit={limit}"
        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            data = response.json()

            results = []
            for match in data.get("matches", []):
                result = {
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "organization": match.get("org", "Unknown"),
                    "hostnames": match.get("hostnames", []),
                    "product": match.get("product", "Unknown"),
                    "version": match.get("version", ""),
                    "banner": match.get("data", "")[:150]
                }
                results.append(result)

            return {
                "success": True,
                "data": {
                    "total": data.get("total", 0),
                    "results": results,
                    "query": query
                },
                "summary": f"Shodan search '{query}': Found {data.get('total', 0)} total results, showing {len(results)}"
            }

        else:
            return {
                "success": False,
                "error": f"Shodan API error: {response.status_code} - {response.text}",
                "summary": f"Failed to search Shodan for query: {query}"
            }

    except Exception as e:
        return {
            "success": False,
            "error": f"{type(e).__name__}: {str(e)}",
            "summary": f"Error searching Shodan for: {query}"
        }


def shodan_host(ip):
    """
    Get detailed host information including all available data.
    This is an alias for shodan_lookup with additional formatting.

    Args:
        ip: IP address to query

    Returns:
        dict: Comprehensive host information
    """
    return shodan_lookup(ip)


def execute_shodan_tool(tool_name, tool_args):
    """
    Execute a Shodan tool by name with given arguments

    Args:
        tool_name: Name of the Shodan function to execute
        tool_args: Dictionary of arguments for the function

    Returns:
        Result from the Shodan function
    """
    tool_map = {
        "shodan_lookup": shodan_lookup,
        "shodan_search": shodan_search,
        "shodan_host": shodan_host
    }

    if tool_name not in tool_map:
        return {
            "success": False,
            "error": f"Unknown Shodan tool: {tool_name}",
            "summary": f"Tool '{tool_name}' not found"
        }

    try:
        result = tool_map[tool_name](**tool_args)
        return result
    except TypeError as e:
        return {
            "success": False,
            "error": f"Invalid arguments for {tool_name}: {e}",
            "summary": f"Failed to execute {tool_name} with provided arguments"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"{type(e).__name__}: {str(e)}",
            "summary": f"Error executing {tool_name}"
        }


# Tool definitions for Ollama function calling
SHODAN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "shodan_lookup",
            "description": "Look up an IP address in Shodan to get host information, open ports, services, vulnerabilities, and threat intelligence. Use this to check if an IP is malicious or has known security issues.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "The IP address to look up (e.g., '8.8.8.8')"
                    }
                },
                "required": ["ip"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "shodan_search",
            "description": "Search the Shodan database for hosts matching a query. Useful for finding similar vulnerable systems or researching attack patterns. Query examples: 'apache country:US', 'port:22', 'nginx version:1.10'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Shodan search query (e.g., 'apache country:US', 'port:22 country:CN')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 10, max: 100)",
                        "default": 10
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "shodan_host",
            "description": "Get comprehensive host information from Shodan including all historical data, services, and vulnerabilities. This is similar to shodan_lookup but with additional details.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "The IP address to query (e.g., '1.2.3.4')"
                    }
                },
                "required": ["ip"]
            }
        }
    }
]


if __name__ == "__main__":
    # Test the Shodan tools
    print("Testing Shodan tools...")
    print("\n1. Looking up 8.8.8.8 (Google DNS):")
    result = shodan_lookup("8.8.8.8")
    print(json.dumps(result, indent=2))

    print("\n2. Searching for Apache servers:")
    result = shodan_search("apache", limit=3)
    print(json.dumps(result, indent=2))
