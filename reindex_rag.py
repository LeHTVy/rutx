#!/usr/bin/env python3
"""
Re-index ChromaDB RAG Collections
==================================

Script để re-index tất cả collections trong UnifiedRAG với metadata mới:
- Tools/Commands với description và use_cases
- Security Technologies (WAF, CDN, firewall bypass)
- Port metadata
- Cloud services

Usage:
    python reindex_rag.py [--force] [--collections tools,ports,security_tech,cloud]

Options:
    --force: Xóa collections cũ trước khi re-index
    --collections: Chỉ re-index các collections được chỉ định (comma-separated)
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app.rag.unified_memory import get_unified_rag


def reindex_tools(rag, force: bool = False):
    """Re-index tools and commands collection."""
    print("\n📚 Re-indexing Tools & Commands...")
    
    if force:
        try:
            rag.client.delete_collection(name="tools_commands")
            print("  ✓ Deleted old tools_commands collection")
        except Exception as e:
            print(f"  ⚠️ Could not delete collection (may not exist): {e}")
        
        # Recreate collection
        rag.tools_collection = rag.client.get_or_create_collection(
            name="tools_commands",
            metadata={"description": "SNODE security tools and their commands"}
        )
        rag._tool_index_populated = False
    
    # Force re-index
    rag._tool_index_populated = False
    rag._ensure_tools_indexed()
    print(f"  ✓ Tools collection indexed: {rag.tools_collection.count()} commands")


def reindex_security_tech(rag, force: bool = False):
    """Re-index security technologies collection."""
    print("\n🛡️ Re-indexing Security Technologies...")
    
    if force:
        try:
            rag.client.delete_collection(name="security_tech")
            print("  ✓ Deleted old security_tech collection")
        except Exception as e:
            print(f"  ⚠️ Could not delete collection (may not exist): {e}")
        
        # Recreate collection
        rag.security_tech_collection = rag.client.get_or_create_collection(
            name="security_tech",
            metadata={"description": "Security technology detection and bypass methods (WAF, CDN, firewall)"}
        )
        rag._security_tech_indexed = False
    
    # Force re-index
    rag._security_tech_indexed = False
    rag._ensure_security_tech_indexed()
    print(f"  ✓ Security tech collection indexed: {rag.security_tech_collection.count()} technologies")


def reindex_ports(rag, force: bool = False):
    """Re-index port metadata collection."""
    print("\n🔌 Re-indexing Port Metadata...")
    
    if force:
        try:
            rag.client.delete_collection(name="port_metadata")
            print("  ✓ Deleted old port_metadata collection")
        except Exception as e:
            print(f"  ⚠️ Could not delete collection (may not exist): {e}")
        
        # Recreate collection
        rag.ports_collection = rag.client.get_or_create_collection(
            name="port_metadata",
            metadata={"description": "TCP/UDP port and service metadata for network scanning"}
        )
        rag._ports_indexed = False
    
    # Force re-index
    rag._ports_indexed = False
    rag._ensure_ports_indexed()
    print(f"  ✓ Ports collection indexed: {rag.ports_collection.count()} entries")


def reindex_cloud_services(rag, force: bool = False):
    """Re-index cloud services collection."""
    print("\n☁️ Re-indexing Cloud Services...")
    
    if force:
        try:
            rag.client.delete_collection(name="cloud_services")
            print("  ✓ Deleted old cloud_services collection")
        except Exception as e:
            print(f"  ⚠️ Could not delete collection (may not exist): {e}")
        
        # Recreate collection
        rag.cloud_services_collection = rag.client.get_or_create_collection(
            name="cloud_services",
            metadata={"description": "Cloud service provider metadata (CDN, hosting, etc.)"}
        )
        rag._cloud_services_indexed = False
    
    # Force re-index
    rag._cloud_services_indexed = False
    rag._ensure_cloud_services_indexed()
    print(f"  ✓ Cloud services collection indexed: {rag.cloud_services_collection.count()} services")


def main():
    parser = argparse.ArgumentParser(
        description="Re-index ChromaDB RAG collections with updated metadata",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Re-index all collections (force delete old data, skip confirmation)
  python reindex_rag.py --force --yes
  
  # Re-index only tools and security_tech
  python reindex_rag.py --force --yes --collections tools,security_tech
  
  # Re-index without deleting (may cause duplicates)
  python reindex_rag.py --collections tools
  
  # Re-index with confirmation prompt (may have encoding issues)
  python reindex_rag.py --force
        """
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Delete existing collections before re-indexing (recommended)"
    )
    parser.add_argument(
        "--collections",
        type=str,
        default="all",
        help="Comma-separated list of collections to re-index: tools,ports,security_tech,cloud (default: all)"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt (auto-confirm)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("ChromaDB RAG Re-indexing Script")
    print("=" * 60)
    
    if args.force and not args.yes:
        print("\n⚠️  FORCE MODE: Existing collections will be deleted!")
        try:
            # Try to read input with proper encoding handling
            import sys
            import io
            # Set stdin encoding if possible
            if sys.stdin.encoding:
                response = input("Continue? (yes/no): ")
            else:
                # Fallback: read bytes and decode
                sys.stdout.write("Continue? (yes/no): ")
                sys.stdout.flush()
                response_bytes = sys.stdin.buffer.readline()
                response = response_bytes.decode('utf-8', errors='ignore').strip()
        except (UnicodeDecodeError, KeyboardInterrupt, EOFError) as e:
            print(f"\n⚠️  Could not read input: {e}")
            print("Use --yes flag to skip confirmation: python reindex_rag.py --force --yes")
            return
        
        if response.lower() not in ["yes", "y"]:
            print("Cancelled.")
            return
    
    # Get UnifiedRAG instance
    print("\n🔧 Initializing UnifiedRAG...")
    rag = get_unified_rag()
    
    # Determine which collections to re-index
    collections_to_index = []
    if args.collections.lower() == "all":
        collections_to_index = ["tools", "ports", "security_tech", "cloud"]
    else:
        collections_to_index = [c.strip() for c in args.collections.split(",")]
    
    print(f"\n📋 Collections to re-index: {', '.join(collections_to_index)}")
    
    # Re-index each collection
    try:
        if "tools" in collections_to_index:
            reindex_tools(rag, force=args.force)
        
        if "security_tech" in collections_to_index:
            reindex_security_tech(rag, force=args.force)
        
        if "ports" in collections_to_index:
            reindex_ports(rag, force=args.force)
        
        if "cloud" in collections_to_index:
            reindex_cloud_services(rag, force=args.force)
        
        print("\n" + "=" * 60)
        print("✅ Re-indexing completed successfully!")
        print("=" * 60)
        
        # Show summary
        print("\n📊 Collection Summary:")
        if "tools" in collections_to_index:
            print(f"  • Tools/Commands: {rag.tools_collection.count()} entries")
        if "security_tech" in collections_to_index:
            print(f"  • Security Tech: {rag.security_tech_collection.count()} entries")
        if "ports" in collections_to_index:
            print(f"  • Ports: {rag.ports_collection.count()} entries")
        if "cloud" in collections_to_index:
            print(f"  • Cloud Services: {rag.cloud_services_collection.count()} entries")
        
    except Exception as e:
        print(f"\n❌ Error during re-indexing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
