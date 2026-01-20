#!/usr/bin/env python3
"""Backup script for SQLite3 ChromaDB before migration."""

import os
import sys
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def backup_sqlite_directory(persist_directory: str, backup_dir: Optional[str] = None) -> str:
    """Backup SQLite3 ChromaDB directory.
    
    Args:
        persist_directory: Path to .chroma directory
        backup_dir: Backup directory path. If None, creates timestamped backup
        
    Returns:
        Path to backup directory
    """
    if not os.path.exists(persist_directory):
        print(f"❌ SQLite3 directory not found: {persist_directory}")
        return ""
    
    if backup_dir is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = f"{persist_directory}.backup_{timestamp}"
    
    if os.path.exists(backup_dir):
        response = input(f"⚠️  Backup directory {backup_dir} already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("⏭️  Skipping backup")
            return ""
        shutil.rmtree(backup_dir)
    
    print(f"💾 Creating backup from {persist_directory} to {backup_dir}...")
    
    try:
        shutil.copytree(persist_directory, backup_dir)
        
        # Verify backup
        original_size = sum(f.stat().st_size for f in Path(persist_directory).rglob('*') if f.is_file())
        backup_size = sum(f.stat().st_size for f in Path(backup_dir).rglob('*') if f.is_file())
        
        if original_size == backup_size:
            print(f"✅ Backup created successfully: {backup_dir}")
            print(f"   Original size: {original_size:,} bytes")
            print(f"   Backup size: {backup_size:,} bytes")
            return backup_dir
        else:
            print(f"⚠️  Backup size mismatch: original {original_size:,} vs backup {backup_size:,}")
            return backup_dir
    except Exception as e:
        print(f"❌ Error creating backup: {e}")
        return ""


def main():
    """Main backup function."""
    print("=" * 60)
    print("ChromaDB SQLite3 Backup")
    print("=" * 60)
    
    persist_directory = os.getenv("CHROMA_PERSIST_DIRECTORY", str(project_root / ".chroma"))
    
    print(f"\nSQLite3 directory: {persist_directory}")
    
    backup_path = backup_sqlite_directory(persist_directory)
    
    if backup_path:
        print(f"\n✅ Backup completed: {backup_path}")
        print("\nYou can now safely run the migration script.")
    else:
        print("\n❌ Backup failed or skipped.")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
