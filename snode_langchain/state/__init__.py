"""
SNODE State Management

Provides state persistence for discoveries (subdomains, ports, etc.)
"""
from .subdomain_state import (
    SubdomainState,
    get_subdomain_state,
    save_subdomains,
    get_subdomain_file,
    load_subdomains,
)

__all__ = [
    "SubdomainState",
    "get_subdomain_state",
    "save_subdomains",
    "get_subdomain_file",
    "load_subdomains",
]
