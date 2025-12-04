"""
Output File Manager - Unified filename generation for tool outputs

Consolidates duplicate timestamp + sanitize filename patterns across all tool files.
"""

import os
import re
from datetime import datetime
from typing import Optional
from pathlib import Path


class OutputFileManager:
    """
    Manages output file path generation for scan tools

    Provides:
    - Timestamp generation
    - Filename sanitization
    - Output path construction
    - Directory creation
    """

    DEFAULT_BASE_DIR = "/tmp"

    @staticmethod
    def generate_timestamp() -> str:
        """
        Generate consistent timestamp string

        Returns:
            Timestamp in format: YYYYMMDD_HHMMSS
        """
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    @staticmethod
    def sanitize_filename(filename: str, replacement: str = "_") -> str:
        """
        Sanitize filename by removing invalid characters

        Args:
            filename: Original filename
            replacement: Character to replace invalid chars with (default: "_")

        Returns:
            Sanitized filename safe for filesystem

        Examples:
            >>> OutputFileManager.sanitize_filename("192.168.1.0/24")
            "192.168.1.0_24"
            >>> OutputFileManager.sanitize_filename("example.com:443")
            "example.com_443"
        """
        # Keep alphanumeric, dots, hyphens, underscores
        # Replace everything else with replacement character
        return re.sub(r'[^\w\-.]', replacement, filename)

    @staticmethod
    def generate_output_path(
        tool: str,
        target: str,
        ext: str,
        base_dir: Optional[str] = None,
        include_timestamp: bool = True,
        suffix: Optional[str] = None
    ) -> str:
        """
        Generate complete output file path for a tool

        Args:
            tool: Tool name (e.g., "nmap", "masscan", "amass")
            target: Scan target (will be sanitized)
            ext: File extension (e.g., "xml", "json", "txt")
            base_dir: Base directory (default: /tmp/<tool>_scans)
            include_timestamp: Include timestamp in filename
            suffix: Optional suffix to add before extension

        Returns:
            Complete file path

        Examples:
            >>> OutputFileManager.generate_output_path("nmap", "192.168.1.1", "xml")
            "/tmp/nmap_scans/nmap_192.168.1.1_20250101_120000.xml"

            >>> OutputFileManager.generate_output_path("amass", "example.com", "txt", suffix="passive")
            "/tmp/amass_scans/amass_example.com_passive_20250101_120000.txt"
        """
        # Sanitize target for filename
        safe_target = OutputFileManager.sanitize_filename(target)

        # Build filename components
        filename_parts = [tool, safe_target]

        # Add optional suffix
        if suffix:
            filename_parts.append(suffix)

        # Add timestamp
        if include_timestamp:
            timestamp = OutputFileManager.generate_timestamp()
            filename_parts.append(timestamp)

        # Join parts with underscore
        filename = "_".join(filename_parts)

        # Add extension
        if not ext.startswith("."):
            ext = f".{ext}"
        filename = f"{filename}{ext}"

        # Determine base directory
        if base_dir is None:
            base_dir = f"{OutputFileManager.DEFAULT_BASE_DIR}/{tool}_scans"

        # Create directory if it doesn't exist
        os.makedirs(base_dir, exist_ok=True)

        # Return complete path
        return os.path.join(base_dir, filename)

    @staticmethod
    def generate_output_dir(
        tool: str,
        target: str,
        base_dir: Optional[str] = None,
        include_timestamp: bool = True,
        suffix: Optional[str] = None
    ) -> str:
        """
        Generate output directory path for a tool

        Args:
            tool: Tool name (e.g., "bbot")
            target: Scan target (will be sanitized)
            base_dir: Base directory (default: /tmp)
            include_timestamp: Include timestamp in directory name
            suffix: Optional suffix to add

        Returns:
            Complete directory path

        Examples:
            >>> OutputFileManager.generate_output_dir("bbot", "example.com")
            "/tmp/bbot_example.com_20250101_120000"
        """
        # Sanitize target for directory name
        safe_target = OutputFileManager.sanitize_filename(target)

        # Build directory name components
        dir_parts = [tool, safe_target]

        # Add optional suffix
        if suffix:
            dir_parts.append(suffix)

        # Add timestamp
        if include_timestamp:
            timestamp = OutputFileManager.generate_timestamp()
            dir_parts.append(timestamp)

        # Join parts with underscore
        dir_name = "_".join(dir_parts)

        # Determine base directory
        if base_dir is None:
            base_dir = OutputFileManager.DEFAULT_BASE_DIR

        # Return complete path
        return os.path.join(base_dir, dir_name)

    @staticmethod
    def ensure_dir_exists(path: str) -> str:
        """
        Ensure directory exists, create if needed

        Args:
            path: Directory path or file path (will extract directory)

        Returns:
            Directory path
        """
        # If it's a file path, get the directory
        path_obj = Path(path)
        if path_obj.suffix:  # Has file extension
            dir_path = path_obj.parent
        else:
            dir_path = path_obj

        # Create directory
        os.makedirs(dir_path, exist_ok=True)

        return str(dir_path)

    @staticmethod
    def get_unique_path(filepath: str) -> str:
        """
        Get unique filepath by adding counter if file exists

        Args:
            filepath: Desired file path

        Returns:
            Unique file path (may have _1, _2, etc. appended)

        Examples:
            If "scan.xml" exists:
            >>> OutputFileManager.get_unique_path("/tmp/scan.xml")
            "/tmp/scan_1.xml"
        """
        if not os.path.exists(filepath):
            return filepath

        # Split path and extension
        path_obj = Path(filepath)
        base = path_obj.stem
        ext = path_obj.suffix
        directory = path_obj.parent

        # Find unique name
        counter = 1
        while True:
            new_path = directory / f"{base}_{counter}{ext}"
            if not new_path.exists():
                return str(new_path)
            counter += 1


# Convenience functions for backward compatibility
def generate_output_path(tool: str, target: str, ext: str, base_dir: str = "/tmp") -> str:
    """Generate output file path (convenience function)"""
    return OutputFileManager.generate_output_path(tool, target, ext, base_dir)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename (convenience function)"""
    return OutputFileManager.sanitize_filename(filename)


if __name__ == "__main__":
    # Test the OutputFileManager
    print("Testing OutputFileManager:\n")

    # Test sanitization
    print("1. Filename sanitization:")
    test_filenames = [
        "192.168.1.0/24",
        "example.com:443",
        "user@host.com",
        "valid-filename_123.txt"
    ]
    for fname in test_filenames:
        sanitized = OutputFileManager.sanitize_filename(fname)
        print(f"   '{fname}' -> '{sanitized}'")

    # Test path generation
    print("\n2. Output path generation:")
    path1 = OutputFileManager.generate_output_path("nmap", "192.168.1.1", "xml")
    print(f"   nmap: {path1}")

    path2 = OutputFileManager.generate_output_path("amass", "example.com", "txt", suffix="passive")
    print(f"   amass: {path2}")

    path3 = OutputFileManager.generate_output_path("masscan", "10.0.0.0/8", "json")
    print(f"   masscan: {path3}")

    # Test directory generation
    print("\n3. Output directory generation:")
    dir1 = OutputFileManager.generate_output_dir("bbot", "example.com")
    print(f"   bbot: {dir1}")

    dir2 = OutputFileManager.generate_output_dir("bbot", "test.com", suffix="quick")
    print(f"   bbot (quick): {dir2}")
