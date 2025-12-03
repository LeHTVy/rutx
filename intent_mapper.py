"""
Intent Recognition and Fallback Tool Selection

This module provides fallback logic when the LLM fails to select appropriate tools.
It maps user intents to predefined tool workflows based on keyword matching.
"""

from typing import List, Dict, Optional, Tuple
import re


class IntentMapper:
    """Maps user requests to tool selection workflows"""

    # Intent patterns with keywords and workflows
    INTENT_PATTERNS = {
        "os_detection": {
            "keywords": ["os detection", "fingerprint", "what os", "operating system", "detect os", "os finger"],
            "priority": 10,
            "workflow": [
                {
                    "name": "nmap_ping_scan",
                    "arguments": {"target": "{target}"},
                    "justification": "Discover live hosts before OS detection"
                },
                {
                    "name": "nmap_os_detection",
                    "arguments": {"target": "{target}"},
                    "justification": "Detect operating system with Nmap fingerprinting"
                }
            ]
        },

        "vulnerability_scan": {
            "keywords": ["vuln", "vulnerability", "cve", "check for vulnerabilities", "security scan"],
            "priority": 9,
            "workflow": [
                {
                    "name": "nmap_service_detection",
                    "arguments": {"target": "{target}"},
                    "justification": "Detect services and versions for vulnerability assessment"
                },
                {
                    "name": "nmap_vuln_scan",
                    "arguments": {"target": "{target}"},
                    "justification": "Scan for known vulnerabilities using NSE scripts"
                }
            ]
        },

        "port_scan_subdomains": {
            "keywords": ["port scan", "scan ports", "open ports", "subdomains"],
            "priority": 8,
            "requires_subdomains": True,
            "workflow": "4stage",  # Special: uses 4-stage workflow
            "justification": "Use 4-stage workflow for efficient subdomain port scanning"
        },

        "subdomain_enumeration": {
            "keywords": ["find subdomains", "enumerate subdomains", "subdomain discovery", "list subdomains"],
            "priority": 7,
            "workflow": [
                {
                    "name": "bbot_subdomain_enum",
                    "arguments": {"domain": "{target}"},
                    "justification": "Fast modern subdomain enumeration with BBOT"
                }
            ]
        },

        "service_detection": {
            "keywords": ["service detection", "version detection", "what services", "detect services", "banner grab"],
            "priority": 6,
            "workflow": [
                {
                    "name": "nmap_service_detection",
                    "arguments": {"target": "{target}"},
                    "justification": "Detailed service and version detection"
                }
            ]
        },

        "quick_scan": {
            "keywords": ["quick scan", "fast scan", "quick recon", "rapid scan"],
            "priority": 5,
            "workflow": [
                {
                    "name": "nmap_fast_scan",
                    "arguments": {"target": "{target}"},
                    "justification": "Fast reconnaissance scan (top 100 ports)"
                }
            ]
        },

        "web_scan": {
            "keywords": ["web scan", "http scan", "https scan", "web service"],
            "priority": 4,
            "workflow": [
                {
                    "name": "nmap_web_scan",
                    "arguments": {"target": "{target}"},
                    "justification": "Scan web ports (80, 443, 8080, 8443)"
                }
            ]
        },

        "default_port_scan": {
            "keywords": ["scan", "port", "check"],  # Very generic - low priority
            "priority": 1,
            "workflow": [
                {
                    "name": "nmap_service_detection",
                    "arguments": {"target": "{target}"},
                    "justification": "Standard port scan with service detection"
                }
            ]
        }
    }

    @classmethod
    def detect_intent(cls, user_prompt: str) -> Optional[Tuple[str, int]]:
        """
        Detect user intent from prompt using keyword matching.

        Args:
            user_prompt: User's request string

        Returns:
            Tuple of (intent_name, priority) or None if no match
        """
        prompt_lower = user_prompt.lower()

        # Find all matching intents with their priorities
        matches = []
        for intent_name, intent_data in cls.INTENT_PATTERNS.items():
            keywords = intent_data["keywords"]
            priority = intent_data["priority"]

            # Check if any keyword matches
            if any(keyword in prompt_lower for keyword in keywords):
                matches.append((intent_name, priority))

        if not matches:
            return None

        # Return intent with highest priority
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[0]

    @classmethod
    def get_tools_for_intent(cls, intent_name: str, target: str, subdomains: Optional[List[str]] = None) -> List[Dict]:
        """
        Get tool workflow for detected intent.

        Args:
            intent_name: Name of detected intent
            target: Target IP/domain
            subdomains: Optional list of subdomains (for 4-stage workflow)

        Returns:
            List of tool selections with arguments
        """
        if intent_name not in cls.INTENT_PATTERNS:
            return []

        intent_data = cls.INTENT_PATTERNS[intent_name]
        workflow = intent_data["workflow"]

        # Special case: 4-stage workflow
        if workflow == "4stage":
            if not subdomains:
                # Fallback to regular port scan if no subdomains
                return cls.get_tools_for_intent("default_port_scan", target)

            # Return 4-stage workflow placeholder
            # Agent will handle this specially
            return [{
                "name": "_4stage_workflow",
                "arguments": {"subdomains": subdomains},
                "justification": intent_data.get("justification", "4-stage port scanning workflow")
            }]

        # Regular workflow: substitute target
        tools = []
        for tool_spec in workflow:
            tool = tool_spec.copy()

            # Substitute {target} placeholder
            if "arguments" in tool:
                args = {}
                for key, value in tool["arguments"].items():
                    if isinstance(value, str) and "{target}" in value:
                        args[key] = value.replace("{target}", target)
                    else:
                        args[key] = value
                tool["arguments"] = args

            tools.append(tool)

        return tools

    @classmethod
    def get_fallback_tools(cls, user_prompt: str, target: str, subdomains: Optional[List[str]] = None) -> Tuple[List[Dict], str]:
        """
        Main fallback function: detect intent and return tools.

        Args:
            user_prompt: User's request
            target: Target IP/domain
            subdomains: Optional subdomains list

        Returns:
            Tuple of (tool_list, reasoning_explanation)
        """
        # Detect intent
        intent_result = cls.detect_intent(user_prompt)

        if not intent_result:
            # No intent detected - use default
            tools = cls.get_tools_for_intent("default_port_scan", target)
            reasoning = "No specific intent detected. Using default port scan with service detection."
            return tools, reasoning

        intent_name, priority = intent_result

        # Get tools for intent
        tools = cls.get_tools_for_intent(intent_name, target, subdomains)

        reasoning = f"Detected intent: '{intent_name}' (priority {priority}). "
        reasoning += f"Matched keywords in user request. Selecting appropriate tool workflow."

        return tools, reasoning

    @classmethod
    def extract_target(cls, user_prompt: str) -> Optional[str]:
        """
        Extract target IP/domain from user prompt.

        Args:
            user_prompt: User's request

        Returns:
            Extracted target or None
        """
        # Try to find IP address
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, user_prompt)
        if ip_match:
            return ip_match.group(0)

        # Try to find domain name
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domain_match = re.search(domain_pattern, user_prompt.lower())
        if domain_match:
            return domain_match.group(0)

        return None

    @classmethod
    def should_use_fallback(cls, llm_tools: List[Dict], user_prompt: str) -> bool:
        """
        Determine if fallback should be used instead of LLM selection.

        Args:
            llm_tools: Tools selected by LLM
            user_prompt: User's original request

        Returns:
            True if fallback should be used
        """
        # Use fallback if LLM didn't select any tools
        if not llm_tools:
            return True

        # Use fallback if LLM selected forbidden tools
        forbidden_tools = ["nmap_all_ports", "nmap_comprehensive_scan"]
        if any(tool.get("name") in forbidden_tools for tool in llm_tools):
            return True

        # Use fallback if LLM selection doesn't match intent
        intent_result = cls.detect_intent(user_prompt)
        if intent_result:
            intent_name, _ = intent_result

            # For OS detection, require both ping and os_detection
            if intent_name == "os_detection":
                tool_names = [t.get("name") for t in llm_tools]
                if "nmap_os_detection" not in tool_names:
                    return True

            # For vuln scan, require vuln_scan tool
            if intent_name == "vulnerability_scan":
                tool_names = [t.get("name") for t in llm_tools]
                if "nmap_vuln_scan" not in tool_names:
                    return True

        return False


# Convenience functions for agent.py integration

def detect_user_intent(prompt: str) -> Optional[str]:
    """Detect intent from user prompt"""
    result = IntentMapper.detect_intent(prompt)
    return result[0] if result else None


def get_fallback_tool_selection(prompt: str, target: str, subdomains: Optional[List[str]] = None) -> Dict:
    """Get fallback tool selection with reasoning"""
    tools, reasoning = IntentMapper.get_fallback_tools(prompt, target, subdomains)
    return {
        "tools": tools,
        "reasoning": reasoning,
        "fallback_used": True
    }


def should_use_fallback_selection(llm_tools: List[Dict], user_prompt: str) -> bool:
    """Check if fallback should override LLM selection"""
    return IntentMapper.should_use_fallback(llm_tools, user_prompt)


# Testing
if __name__ == "__main__":
    print("Testing Intent Mapper...\n")

    test_cases = [
        ("OS Detection on snode.com", "snode.com"),
        ("Vulnerability scan on 192.168.1.1", "192.168.1.1"),
        ("Port scan those subdomains", "example.com"),
        ("Find subdomains of example.com", "example.com"),
        ("Quick scan on 10.0.0.1", "10.0.0.1"),
    ]

    for prompt, target in test_cases:
        print(f"Prompt: '{prompt}'")
        print(f"Target: {target}")

        intent = detect_user_intent(prompt)
        print(f"Detected Intent: {intent}")

        result = get_fallback_tool_selection(prompt, target)
        print(f"Tools: {len(result['tools'])} selected")
        print(f"Reasoning: {result['reasoning']}")
        print("-" * 60)
