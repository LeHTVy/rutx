#!/usr/bin/env python3
"""
Test the masscan DNS resolution fix
Tests that the tool can handle string representation of Python lists
"""

import sys
sys.path.insert(0, 'e:\\Wireless')

from tools.masscan_tools import execute_masscan_tool

# Test case 1: String representation of list (the bug)
print("=" * 60)
print("TEST 1: String representation of list (the bug)")
print("=" * 60)

result = execute_masscan_tool(
    "masscan_port_scan",
    {
        "targets": "['api.snode.com', 'admin.snode.com', 'dev.snode.com']",  # Malformed input
        "ports": "80,443"
    }
)

print(f"\nResult: {result.get('success')}")
if result.get('success'):
    print(f"Targets: {result.get('targets')}")
    print(f"Resolved: {result.get('resolved_targets')}")
    print(f"DNS mapping: {result.get('hostname_to_ip')}")
else:
    print(f"Error: {result.get('error')}")

# Test case 2: Normal comma-separated string
print("\n" + "=" * 60)
print("TEST 2: Normal comma-separated string")
print("=" * 60)

result = execute_masscan_tool(
    "masscan_port_scan",
    {
        "targets": "api.snode.com,admin.snode.com,dev.snode.com",  # Proper format
        "ports": "80,443"
    }
)

print(f"\nResult: {result.get('success')}")
if result.get('success'):
    print(f"Targets: {result.get('targets')}")
    print(f"Resolved: {result.get('resolved_targets')}")
    print(f"DNS mapping: {result.get('hostname_to_ip')}")
else:
    print(f"Error: {result.get('error')}")

# Test case 3: Single target
print("\n" + "=" * 60)
print("TEST 3: Single target")
print("=" * 60)

result = execute_masscan_tool(
    "masscan_port_scan",
    {
        "targets": "api.snode.com",  # Single target
        "ports": "80,443"
    }
)

print(f"\nResult: {result.get('success')}")
if result.get('success'):
    print(f"Targets: {result.get('targets')}")
    print(f"Resolved: {result.get('resolved_targets')}")
    print(f"DNS mapping: {result.get('hostname_to_ip')}")
else:
    print(f"Error: {result.get('error')}")

print("\n" + "=" * 60)
print("All tests completed!")
print("=" * 60)
