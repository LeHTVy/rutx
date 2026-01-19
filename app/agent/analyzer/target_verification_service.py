"""
Target verification helpers (LLM-adjacent, but mostly deterministic).

This module exists to keep `TargetVerificationTool` smaller and to isolate
pure operations (regex extraction, formatting) from the orchestration code.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


_DOMAIN_RE = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_domain(query: str) -> Optional[str]:
    """Extract the first domain-like token from query."""
    if not query:
        return None
    m = _DOMAIN_RE.search(query)
    return m.group(0) if m else None


def extract_ip(query: str) -> Optional[str]:
    """Extract the first IP-like token from query."""
    if not query:
        return None
    m = _IP_RE.search(query)
    return m.group(0) if m else None


def build_conversation_context(
    messages: List[Dict[str, Any]],
    last_candidate: Optional[str] = None,
    resolved_domain: Optional[str] = None,
    max_messages: int = 6,
    max_chars_per_message: int = 200,
) -> str:
    """Build a compact conversation context string for LLM prompts."""
    if not messages:
        base = "None"
    else:
        recent = messages[-max_messages:]
        context_lines: List[str] = []
        for msg in recent:
            role = str(msg.get("role", "user")).upper()
            content = str(msg.get("content", ""))[:max_chars_per_message]
            context_lines.append(f"{role}: {content}")
        base = "\n".join(context_lines) if context_lines else "None"

    if last_candidate:
        base += f"\n(Previously discussed: {last_candidate})"
    if resolved_domain:
        base += f"\n(Resolved domain: {resolved_domain})"
    return base


def format_research_results(research: Dict[str, Any]) -> str:
    """
    Turn `web_search()` results into a compact string for LLM consumption.

    Expected input shape (current code): {"snippets": [...], "sources": [...]}
    """
    snippets = research.get("snippets") or []
    sources = research.get("sources") or []

    out = []
    for i, (snip, src) in enumerate(zip(snippets, sources)):
        title = (src or {}).get("title", "N/A")
        url = (src or {}).get("url", "")
        out.append(f"Source {i+1}: {title} ({url})\nSnippet: {snip}\n")
    return "\n".join(out)

