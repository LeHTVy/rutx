"""
Tool Integration - Database Integration for Tool Runners
Wraps tool runner functions to automatically persist results to database.
"""

import os
import sys
from typing import Dict, Any, Optional
from datetime import datetime
from functools import wraps

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import ENABLE_DATABASE, AUTO_PARSE_RESULTS
from database.database import init_database, get_db_manager
from database.service import ScanService

# Initialize database on import
if ENABLE_DATABASE:
    try:
        init_database()
    except Exception as e:
        print(f"⚠️  Database initialization failed: {e}")


def with_database_persistence(tool_name: str):
    """
    Decorator to add database persistence to tool runner functions.

    Usage:
        @with_database_persistence("nmap")
        def run_nmap_native(target, scan_type="quick", ...):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not ENABLE_DATABASE:
                return func(*args, **kwargs)

            # Extract target from args/kwargs
            target = kwargs.get('target') or kwargs.get('domain') or (args[0] if args else 'unknown')
            scan_profile = kwargs.get('scan_type') or kwargs.get('preset') or kwargs.get('mode')

            # Start scan in database
            try:
                scan_id = ScanService.start_scan(
                    tool=tool_name,
                    target=target,
                    scan_profile=scan_profile
                )
            except Exception as e:
                print(f"⚠️  Database start_scan failed: {e}")
                scan_id = None

            # Run the actual tool
            result = func(*args, **kwargs)

            # Save results to database
            if scan_id and ENABLE_DATABASE and AUTO_PARSE_RESULTS:
                try:
                    output_file = (
                        result.get('output_xml') or
                        result.get('output_json') or
                        result.get('summary_json')
                    )

                    if output_file and result.get('success'):
                        db_result = ScanService.complete_scan(
                            scan_id=scan_id,
                            output_file=output_file,
                            elapsed_seconds=result.get('elapsed_seconds', 0),
                            stdout=result.get('stdout'),
                            return_code=result.get('returncode', 0)
                        )

                        # Add database info to result
                        result['database'] = {
                            'scan_id': scan_id,
                            'hosts_stored': db_result.get('hosts_discovered', 0),
                            'findings_stored': db_result.get('findings_count', 0),
                            'subdomains_stored': db_result.get('subdomains_count', 0)
                        }
                        print(f"💾 Results saved to database (scan_id: {scan_id})")
                    else:
                        ScanService.fail_scan(scan_id, result.get('error', 'Unknown error'))

                except Exception as e:
                    print(f"⚠️  Database persistence failed: {e}")

            return result

        return wrapper
    return decorator


def save_scan_to_database(
    tool: str,
    target: str,
    result: Dict[str, Any],
    scan_profile: Optional[str] = None,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Manually save a scan result to the database.

    Use this when you want explicit control over database persistence.

    Args:
        tool: Tool name (nmap, amass, bbot, shodan)
        target: Scan target
        result: Tool result dictionary
        scan_profile: Scan type/profile
        session_id: Optional session ID

    Returns:
        Database operation result
    """
    if not ENABLE_DATABASE:
        return {"success": False, "error": "Database disabled"}

    try:
        # Start scan
        scan_id = ScanService.start_scan(
            tool=tool,
            target=target,
            scan_profile=scan_profile,
            command=result.get('command'),
            session_id=session_id
        )

        if not result.get('success'):
            return ScanService.fail_scan(scan_id, result.get('error', 'Scan failed'))

        # Get output file
        output_file = (
            result.get('output_xml') or
            result.get('output_json') or
            result.get('summary_json')
        )

        if not output_file:
            return ScanService.fail_scan(scan_id, "No output file found")

        # Complete scan
        return ScanService.complete_scan(
            scan_id=scan_id,
            output_file=output_file,
            elapsed_seconds=result.get('elapsed_seconds', 0),
            stdout=result.get('stdout'),
            return_code=result.get('returncode', 0)
        )

    except Exception as e:
        return {"success": False, "error": str(e)}


# Wrapped versions of tool runners with database persistence
def run_nmap_with_db(target, scan_type="quick", ports=None, timeout=None, session_id=None):
    """Run Nmap and save results to database."""
    from rutx.backup.unified_tool_runner import run_nmap_native

    result = run_nmap_native(target, scan_type, ports, timeout)

    if ENABLE_DATABASE:
        db_result = save_scan_to_database(
            tool="nmap",
            target=target,
            result=result,
            scan_profile=scan_type,
            session_id=session_id
        )
        result['database'] = db_result

    return result


def run_amass_with_db(domain, mode="enum", passive=False, timeout=None, session_id=None):
    """Run Amass and save results to database."""
    from rutx.backup.unified_tool_runner import run_amass_native

    result = run_amass_native(domain, mode, passive, timeout)

    if ENABLE_DATABASE:
        db_result = save_scan_to_database(
            tool="amass",
            target=domain,
            result=result,
            scan_profile=f"{mode}_{'passive' if passive else 'active'}",
            session_id=session_id
        )
        result['database'] = db_result

    return result


def run_bbot_with_db(target, preset="subdomain-enum", modules=None, timeout=None, session_id=None):
    """Run BBOT and save results to database."""
    from rutx.backup.unified_tool_runner import run_bbot_native

    result = run_bbot_native(target, preset, modules, timeout)

    if ENABLE_DATABASE:
        db_result = save_scan_to_database(
            tool="bbot",
            target=target,
            result=result,
            scan_profile=preset or "custom",
            session_id=session_id
        )
        result['database'] = db_result

    return result


def run_shodan_with_db(target, lookup_type="host", api_key=None, session_id=None):
    """Run Shodan query and save results to database."""
    from rutx.backup.unified_tool_runner import run_shodan_native

    result = run_shodan_native(target, lookup_type, api_key)

    if ENABLE_DATABASE:
        db_result = save_scan_to_database(
            tool="shodan",
            target=target,
            result=result,
            scan_profile=lookup_type,
            session_id=session_id
        )
        result['database'] = db_result

    return result


# Convenience exports
__all__ = [
    'with_database_persistence',
    'save_scan_to_database',
    'run_nmap_with_db',
    'run_amass_with_db',
    'run_bbot_with_db',
    'run_shodan_with_db'
]
