"""
Sandbox Module - Isolated tool executors
=========================================

Each tool gets its own executor class with:
- Clean interface
- Input validation
- Output parsing
- Error handling

Ready to be split into microservices later.
"""
from .executors import (
    NmapExecutor, 
    SubfinderExecutor,
    BbotExecutor,
    AmassExecutor,
    NaabuExecutor,
    MasscanExecutor,
    NucleiExecutor,
)
from .validator import validate_target, validate_domain, validate_ports

__all__ = [
    "NmapExecutor",
    "SubfinderExecutor", 
    "BbotExecutor",
    "AmassExecutor",
    "NaabuExecutor",
    "MasscanExecutor",
    "NucleiExecutor",
    "validate_target",
    "validate_domain",
    "validate_ports",
]
