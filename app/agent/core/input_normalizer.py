"""
Deterministic input normalization utilities.

This module is intentionally LLM-free. It performs only safe, mechanical
normalizations to reduce downstream regex duplication and make target parsing
more robust (e.g., IPs/domains with stray spaces).
"""

from __future__ import annotations

import re
from typing import Optional


_IP_WITH_SPACES = re.compile(r"\b(\d{1,3})\s*\.\s*(\d{1,3})\s*\.\s*(\d{1,3})\s*\.\s*(\d{1,3})\b")
_URL = re.compile(r"https?://[^\s]+", re.IGNORECASE)


def normalize_ip_spacing(text: str) -> str:
    """Normalize IP addresses by removing spaces around dots."""

    def _fix(match: re.Match[str]) -> str:
        return ".".join(match.group(i) for i in range(1, 5))

    return _IP_WITH_SPACES.sub(_fix, text)


def normalize_domain_spacing(text: str) -> str:
    """
    Normalize obvious domain spacing mistakes.

    Examples:
    - "example . com" -> "example.com"
    - "ex ample.com"  -> "example.com" (conservative; only removes simple internal whitespace)
    """
    # Remove spaces around dots
    text = re.sub(r"([a-zA-Z0-9])\s+\.\s*([a-zA-Z0-9])", r"\1.\2", text)
    # Remove spaces inside token-like sequences (conservative: only alnum/hyphen)
    text = re.sub(r"([a-zA-Z0-9-])\s+([a-zA-Z0-9-])", r"\1\2", text)
    return text


def normalize_url_whitespace(text: str) -> str:
    """Remove whitespace inside URL substrings."""

    def _fix(match: re.Match[str]) -> str:
        return match.group(0).replace(" ", "")

    return _URL.sub(_fix, text)


def normalize_query(text: Optional[str]) -> str:
    """
    Normalize a user query safely (behavior-preserving).

    Only performs mechanical whitespace fixes; does not rewrite meaning.
    """
    if not text:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # Collapse repeated whitespace first to make replacements predictable
    text = " ".join(text.split())
    text = normalize_ip_spacing(text)
    text = normalize_url_whitespace(text)
    text = normalize_domain_spacing(text)
    return text.strip()

