#!/usr/bin/env python3
"""Verify that all tools can be loaded and their dependencies are available."""

import sys
import importlib
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.registry import get_registry
from tools.executor import get_executor


def check_python_import(module_name: str) -> Tuple[bool, str]:
    """Check if a Python module can be imported.
    
    Args:
        module_name: Module name to check
        
    Returns:
        (success, message) tuple
    """
    try:
        importlib.import_module(module_name)
        return True, "OK"
    except ImportError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Error: {str(e)}"


def check_system_command(command: str) -> Tuple[bool, str]:
    """Check if a system command is available.
    
    Args:
        command: Command name to check
        
    Returns:
        (success, message) tuple
    """
    try:
        result = subprocess.run(
            ["which", command],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            return False, "Not found in PATH"
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, f"Error: {str(e)}"


def verify_tool_implementations():
    """Verify all tool implementations can be loaded."""
    print("=" * 80)
    print("TOOL IMPLEMENTATION VERIFICATION")
    print("=" * 80)
    
    registry = get_registry()
    executor = get_executor()
    
    all_tools = registry.list_tools()
    tools_with_impl = []
    tools_without_impl = []
    tools_with_errors = []
    
    for tool in all_tools:
        if tool.implementation:
            tools_with_impl.append(tool)
            
            # Try to import the implementation
            try:
                parts = tool.implementation.split(".")
                module_path = ".".join(parts[:-1])
                function_name = parts[-1]
                
                module = importlib.import_module(module_path)
                func = getattr(module, function_name)
                
                print(f"✅ {tool.name}: {tool.implementation}")
            except ImportError as e:
                tools_with_errors.append((tool.name, f"Import error: {str(e)}"))
                print(f"❌ {tool.name}: Import error - {str(e)}")
            except AttributeError as e:
                tools_with_errors.append((tool.name, f"Function not found: {str(e)}"))
                print(f"❌ {tool.name}: Function not found - {str(e)}")
            except Exception as e:
                tools_with_errors.append((tool.name, f"Error: {str(e)}"))
                print(f"❌ {tool.name}: Error - {str(e)}")
        else:
            tools_without_impl.append(tool)
            print(f"⚠️  {tool.name}: No implementation (will use generic execution)")
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total tools: {len(all_tools)}")
    print(f"Tools with implementation: {len(tools_with_impl)}")
    print(f"Tools without implementation: {len(tools_without_impl)}")
    print(f"Tools with errors: {len(tools_with_errors)}")
    
    if tools_with_errors:
        print("\nTools with errors:")
        for tool_name, error in tools_with_errors:
            print(f"  - {tool_name}: {error}")
    
    return len(tools_with_errors) == 0


def verify_dependencies():
    """Verify required dependencies are installed."""
    print("\n" + "=" * 80)
    print("DEPENDENCY VERIFICATION")
    print("=" * 80)
    
    # Python package dependencies
    python_packages = {
        "nmap": "python-nmap",
        "pymetasploit3": "pymetasploit3",
        "shodan": "shodan",
        "virustotal": "virustotal-api",
        "requests": "requests",
        "beautifulsoup4": "beautifulsoup4",
        "newspaper": "newspaper3k",
        "lxml": "lxml",
        "playwright": "playwright",
        "chromadb": "chromadb",
        "langchain": "langchain",
        "langgraph": "langgraph",
        "ollama": "ollama",
        "rapidfuzz": "rapidfuzz",
        "Levenshtein": "python-Levenshtein",
    }
    
    all_ok = True
    
    for module_name, package_name in python_packages.items():
        success, message = check_python_import(module_name)
        if success:
            print(f"✅ {package_name} ({module_name}): {message}")
        else:
            # Some packages have different import names - try alternatives
            if module_name == "virustotal_python":
                # Try virustotal-api alternative imports
                try:
                    import virustotal_python
                    print(f"✅ {package_name} (virustotal_python): OK")
                    success = True
                except ImportError:
                    print(f"⚠️  {package_name} ({module_name}): {message} (optional - can use requests fallback)")
            elif module_name == "bs4":
                # beautifulsoup4 imports as bs4
                try:
                    from bs4 import BeautifulSoup
                    print(f"✅ {package_name} (bs4): OK")
                    success = True
                except ImportError:
                    print(f"❌ {package_name} ({module_name}): {message}")
                    all_ok = False
            else:
                print(f"❌ {package_name} ({module_name}): {message}")
                all_ok = False
    
    # System command dependencies (optional)
    print("\nSystem Commands (optional):")
    system_commands = ["nmap", "msfconsole", "msfrpc"]
    for cmd in system_commands:
        success, message = check_system_command(cmd)
        if success:
            print(f"✅ {cmd}: {message}")
        else:
            print(f"⚠️  {cmd}: {message} (optional)")
    
    return all_ok


def verify_tool_execution():
    """Verify tools can be executed (dry run)."""
    print("\n" + "=" * 80)
    print("TOOL EXECUTION VERIFICATION (DRY RUN)")
    print("=" * 80)
    
    executor = get_executor()
    registry = get_registry()
    
    # Test a few common tools
    test_tools = ["nmap", "whois_lookup", "dns_lookup"]
    
    for tool_name in test_tools:
        tool = registry.get_tool(tool_name)
        if not tool:
            print(f"⚠️  {tool_name}: Not found in registry")
            continue
        
        if not tool.implementation:
            print(f"⚠️  {tool_name}: No implementation")
            continue
        
        # Try to load the implementation (don't actually execute)
        try:
            parts = tool.implementation.split(".")
            module_path = ".".join(parts[:-1])
            function_name = parts[-1]
            
            module = importlib.import_module(module_path)
            func = getattr(module, function_name)
            
            # Check function signature
            import inspect
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            
            print(f"✅ {tool_name}: Can be loaded")
            print(f"   Function: {tool.implementation}")
            print(f"   Parameters: {', '.join(params)}")
        except Exception as e:
            print(f"❌ {tool_name}: Cannot be loaded - {str(e)}")


def main():
    """Main verification function."""
    print("\n" + "=" * 80)
    print("TOOL VERIFICATION SCRIPT")
    print("=" * 80)
    print()
    
    # Verify dependencies
    deps_ok = verify_dependencies()
    
    # Verify implementations
    impl_ok = verify_tool_implementations()
    
    # Verify execution (dry run)
    verify_tool_execution()
    
    print("\n" + "=" * 80)
    print("FINAL STATUS")
    print("=" * 80)
    
    if deps_ok and impl_ok:
        print("✅ All checks passed!")
        return 0
    else:
        print("❌ Some checks failed. Please review the errors above.")
        if not deps_ok:
            print("   - Missing dependencies. Run: pip install -r requirements.txt")
        if not impl_ok:
            print("   - Some tool implementations have errors.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
