"""
Web search module (rutx).

This is a lightweight, firestarter-inspired web search layer that provides
one stable interface for performing web search and (optionally) fetching
snippets/content in the future.
"""

from .aggregator import SearchAggregator

__all__ = ["SearchAggregator"]

