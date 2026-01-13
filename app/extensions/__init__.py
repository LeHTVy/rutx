"""
Extensions Framework for SNODE
==============================

Plugin system that allows extending agent behavior at key points.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import importlib
import inspect
from pathlib import Path

from .base import Extension


# Extension registry
_extensions: Dict[str, List[type]] = {}
_extension_cache: Dict[str, List[type]] = {}


async def call_extensions(
    extension_point: str,
    agent=None,
    **kwargs
) -> Any:
    """
    Call all extensions registered for an extension point.
    
    Args:
        extension_point: The extension point name (e.g., "message_loop_start")
        agent: Optional agent instance
        **kwargs: Additional arguments to pass to extensions
        
    Returns:
        Result from last extension (if any)
    """
    extensions = _get_extensions(extension_point, agent)
    
    result = None
    for ext_class in extensions:
        try:
            ext = ext_class(agent=agent)
            # Execute async if coroutine, sync otherwise
            if hasattr(ext.execute, '__call__'):
                import inspect
                if inspect.iscoroutinefunction(ext.execute):
                    result = await ext.execute(**kwargs)
                else:
                    result = ext.execute(**kwargs)
        except Exception as e:
            print(f"  ⚠️ Extension {ext_class.__name__} failed: {e}")
    
    return result


def call_extensions_sync(
    extension_point: str,
    agent=None,
    **kwargs
) -> Any:
    """
    Synchronous wrapper for call_extensions.
    Use this when you can't use async/await.
    """
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is running, create a task
            task = asyncio.create_task(call_extensions(extension_point, agent, **kwargs))
            return None  # Can't return result from task
        else:
            return loop.run_until_complete(call_extensions(extension_point, agent, **kwargs))
    except RuntimeError:
        # No event loop, create new one
        return asyncio.run(call_extensions(extension_point, agent, **kwargs))


def _get_extensions(extension_point: str, agent=None) -> List[type]:
    """Get extensions for an extension point."""
    cache_key = f"{extension_point}"
    
    if cache_key in _extension_cache:
        return _extension_cache[cache_key]
    
    extensions = []
    
    # Load from default extensions folder
    default_exts = _load_extensions_from_folder("app/extensions/default")
    extensions.extend(default_exts)
    
    # Load from agent-specific extensions if agent has profile
    if agent and hasattr(agent, 'config') and hasattr(agent.config, 'profile'):
        profile_exts = _load_extensions_from_folder(f"app/extensions/profiles/{agent.config.profile}")
        extensions.extend(profile_exts)
    
    # Cache and return
    _extension_cache[cache_key] = extensions
    return extensions


def _load_extensions_from_folder(folder: str) -> List[type]:
    """Load extension classes from a folder."""
    extensions = []
    
    try:
        folder_path = Path(folder)
        if not folder_path.exists():
            return extensions
        
        # Import all Python files in folder
        for file_path in folder_path.glob("*.py"):
            if file_path.name == "__init__.py":
                continue
            
            module_name = f"{folder.replace('/', '.')}.{file_path.stem}"
            try:
                module = importlib.import_module(module_name)
                
                # Find Extension subclasses
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, Extension) and 
                        obj != Extension):
                        extensions.append(obj)
            except Exception as e:
                print(f"  ⚠️ Failed to load extension from {file_path}: {e}")
    
    except Exception as e:
        print(f"  ⚠️ Failed to load extensions from {folder}: {e}")
    
    return extensions


def register_extension(extension_point: str, extension_class: type):
    """Manually register an extension."""
    if extension_point not in _extensions:
        _extensions[extension_point] = []
    _extensions[extension_point].append(extension_class)
    # Clear cache
    _extension_cache.clear()


__all__ = [
    "Extension",
    "call_extensions",
    "register_extension",
]
