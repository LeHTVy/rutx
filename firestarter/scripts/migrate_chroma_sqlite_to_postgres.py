#!/usr/bin/env python3
"""Migration script to migrate ChromaDB data from SQLite3 to PostgreSQL via Chroma Server."""

import os
import sys
import json
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import chromadb
from chromadb.config import Settings


def export_from_sqlite(persist_directory: str) -> Dict[str, Any]:
    """Export all collections from SQLite3 ChromaDB.
    
    Args:
        persist_directory: Path to .chroma directory
        
    Returns:
        Dictionary with collections data
    """
    print(f"📦 Exporting data from SQLite3 at {persist_directory}...")
    
    if not os.path.exists(persist_directory):
        print(f"❌ SQLite3 directory not found: {persist_directory}")
        return {}
    
    try:
        # Connect to SQLite3 ChromaDB
        client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(anonymized_telemetry=False)
        )
        
        # List all collections
        collections = client.list_collections()
        print(f"✅ Found {len(collections)} collections")
        
        exported_data = {}
        
        for collection in collections:
            collection_name = collection.name
            print(f"  📄 Exporting collection: {collection_name}")
            
            # Get all data from collection
            try:
                data = collection.get()
                
                exported_data[collection_name] = {
                    "ids": data.get("ids", []),
                    "documents": data.get("documents", []),
                    "metadatas": data.get("metadatas", []),
                    "embeddings": data.get("embeddings", []),
                    "count": len(data.get("ids", []))
                }
                
                print(f"    ✅ Exported {exported_data[collection_name]['count']} documents")
            except Exception as e:
                print(f"    ⚠️  Error exporting collection {collection_name}: {e}")
                exported_data[collection_name] = {
                    "ids": [],
                    "documents": [],
                    "metadatas": [],
                    "embeddings": [],
                    "count": 0,
                    "error": str(e)
                }
        
        print(f"✅ Export completed: {len(exported_data)} collections")
        return exported_data
        
    except Exception as e:
        print(f"❌ Error connecting to SQLite3: {e}")
        return {}


def import_to_chroma_server(exported_data: Dict[str, Any],
                           server_host: str = "localhost",
                           server_port: int = 8000,
                           auth_token: Optional[str] = None) -> bool:
    """Import collections to Chroma Server (PostgreSQL backend).
    
    Args:
        exported_data: Exported collections data
        server_host: Chroma Server host
        server_port: Chroma Server port
        auth_token: Authentication token
        
    Returns:
        True if successful, False otherwise
    """
    print(f"\n📥 Importing data to Chroma Server at {server_host}:{server_port}...")
    
    try:
        # Connect to Chroma Server
        settings = Settings(anonymized_telemetry=False)
        if auth_token:
            settings.chroma_client_auth_provider = "chromadb.auth.token.TokenAuthClientProvider"
            settings.chroma_client_auth_credentials = auth_token
        
        client = chromadb.HttpClient(
            host=server_host,
            port=server_port,
            settings=settings
        )
        
        # Test connection
        try:
            heartbeat = client.heartbeat()
            print(f"✅ Connected to Chroma Server: {heartbeat}")
        except Exception as e:
            print(f"❌ Cannot connect to Chroma Server: {e}")
            print("   Make sure Chroma Server is running and accessible")
            return False
        
        # Import each collection
        success_count = 0
        error_count = 0
        
        for collection_name, data in exported_data.items():
            if "error" in data:
                print(f"  ⚠️  Skipping {collection_name} (had export error)")
                error_count += 1
                continue
            
            if data["count"] == 0:
                print(f"  ⚠️  Skipping {collection_name} (empty collection)")
                continue
            
            print(f"  📄 Importing collection: {collection_name} ({data['count']} documents)")
            
            try:
                # Get or create collection
                collection = client.get_or_create_collection(
                    name=collection_name,
                    metadata={"hnsw:space": "cosine"}
                )
                
                # Check if collection already has data
                existing_count = collection.count()
                if existing_count > 0:
                    response = input(f"    ⚠️  Collection {collection_name} already has {existing_count} documents. Overwrite? (y/N): ")
                    if response.lower() != 'y':
                        print(f"    ⏭️  Skipping {collection_name}")
                        continue
                    # Delete existing collection and recreate
                    client.delete_collection(name=collection_name)
                    collection = client.create_collection(
                        name=collection_name,
                        metadata={"hnsw:space": "cosine"}
                    )
                
                # Import data in batches (Chroma has limits)
                batch_size = 100
                ids = data["ids"]
                documents = data.get("documents", [])
                metadatas = data.get("metadatas", [])
                embeddings = data.get("embeddings", [])
                
                for i in range(0, len(ids), batch_size):
                    batch_ids = ids[i:i+batch_size]
                    batch_documents = documents[i:i+batch_size] if documents else None
                    batch_metadatas = metadatas[i:i+batch_size] if metadatas else None
                    batch_embeddings = embeddings[i:i+batch_size] if embeddings else None
                    
                    # Prepare add parameters
                    add_params = {"ids": batch_ids}
                    if batch_documents:
                        add_params["documents"] = batch_documents
                    if batch_metadatas:
                        add_params["metadatas"] = batch_metadatas
                    if batch_embeddings:
                        add_params["embeddings"] = batch_embeddings
                    
                    collection.add(**add_params)
                    
                    print(f"    ✅ Imported batch {i//batch_size + 1} ({len(batch_ids)} documents)")
                
                # Verify import
                final_count = collection.count()
                if final_count == data["count"]:
                    print(f"    ✅ Successfully imported {final_count} documents")
                    success_count += 1
                else:
                    print(f"    ⚠️  Count mismatch: expected {data['count']}, got {final_count}")
                    error_count += 1
                    
            except Exception as e:
                print(f"    ❌ Error importing {collection_name}: {e}")
                error_count += 1
        
        print(f"\n✅ Import completed: {success_count} successful, {error_count} errors")
        return error_count == 0
        
    except Exception as e:
        print(f"❌ Error connecting to Chroma Server: {e}")
        return False


def delete_sqlite_directory(persist_directory: str, backup: bool = True) -> bool:
    """Delete SQLite3 directory after successful migration.
    
    Args:
        persist_directory: Path to .chroma directory
        backup: Whether to create backup before deletion
        
    Returns:
        True if successful, False otherwise
    """
    if not os.path.exists(persist_directory):
        print(f"ℹ️  SQLite3 directory already removed: {persist_directory}")
        return True
    
    if backup:
        backup_path = f"{persist_directory}.backup"
        if os.path.exists(backup_path):
            response = input(f"⚠️  Backup directory {backup_path} already exists. Overwrite? (y/N): ")
            if response.lower() != 'y':
                print("⏭️  Skipping backup")
                backup = False
            else:
                shutil.rmtree(backup_path)
        
        if backup:
            print(f"💾 Creating backup at {backup_path}...")
            shutil.copytree(persist_directory, backup_path)
            print(f"✅ Backup created")
    
    response = input(f"\n🗑️  Delete SQLite3 directory {persist_directory}? (y/N): ")
    if response.lower() != 'y':
        print("⏭️  Skipping deletion")
        return False
    
    try:
        shutil.rmtree(persist_directory)
        print(f"✅ Deleted SQLite3 directory: {persist_directory}")
        return True
    except Exception as e:
        print(f"❌ Error deleting directory: {e}")
        return False


def main():
    """Main migration function."""
    print("=" * 60)
    print("ChromaDB Migration: SQLite3 → PostgreSQL (via Chroma Server)")
    print("=" * 60)
    
    # Get configuration from environment or defaults
    persist_directory = os.getenv("CHROMA_PERSIST_DIRECTORY", str(project_root / ".chroma"))
    server_host = os.getenv("CHROMA_SERVER_HOST", "localhost")
    server_port = int(os.getenv("CHROMA_SERVER_PORT", "8000"))
    auth_token = os.getenv("CHROMA_SERVER_AUTH_TOKEN")
    
    print(f"\nConfiguration:")
    print(f"  SQLite3 directory: {persist_directory}")
    print(f"  Chroma Server: {server_host}:{server_port}")
    print(f"  Auth token: {'Set' if auth_token else 'Not set'}")
    
    # Step 1: Export from SQLite3
    exported_data = export_from_sqlite(persist_directory)
    
    if not exported_data:
        print("\n❌ No data to migrate. Exiting.")
        return 1
    
    total_documents = sum(data.get("count", 0) for data in exported_data.values())
    print(f"\n📊 Total documents to migrate: {total_documents}")
    
    # Step 2: Import to Chroma Server
    if not import_to_chroma_server(exported_data, server_host, server_port, auth_token):
        print("\n❌ Migration failed. SQLite3 data preserved.")
        return 1
    
    # Step 3: Verify migration
    print("\n🔍 Verifying migration...")
    try:
        settings = Settings(anonymized_telemetry=False)
        if auth_token:
            settings.chroma_client_auth_provider = "chromadb.auth.token.TokenAuthClientProvider"
            settings.chroma_client_auth_credentials = auth_token
        
        client = chromadb.HttpClient(
            host=server_host,
            port=server_port,
            settings=settings
        )
        
        server_collections = client.list_collections()
        print(f"✅ Found {len(server_collections)} collections in Chroma Server")
        
        for collection in server_collections:
            count = collection.count()
            print(f"  - {collection.name}: {count} documents")
        
    except Exception as e:
        print(f"⚠️  Verification warning: {e}")
    
    # Step 4: Delete SQLite3 directory
    print("\n" + "=" * 60)
    delete_sqlite_directory(persist_directory, backup=True)
    
    print("\n" + "=" * 60)
    print("✅ Migration completed successfully!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Update your .env file with Chroma Server configuration")
    print("2. Restart your application")
    print("3. Test the application to ensure everything works")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
