"""Migration script from ChromaDB to pgvector.

This script migrates embeddings from ChromaDB (if exists) to PostgreSQL with pgvector.
Only runs if ChromaDB data exists (SQLite files).
"""

import os
import sys
from pathlib import Path
import json
from typing import List, Dict, Any, Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
load_dotenv(project_root / ".env")

from rag.pgvector_store import PgVectorStore
import warnings


def find_chroma_sqlite_files() -> List[Path]:
    """Find ChromaDB SQLite files if they exist.
    
    Returns:
        List of SQLite database file paths
    """
    sqlite_files = []
    
    # Common locations for ChromaDB SQLite files
    possible_locations = [
        project_root / ".chroma",
        project_root / "data" / "chroma_db",
        project_root / "chroma_db",
    ]
    
    for location in possible_locations:
        if location.exists():
            # Look for .sqlite3 or .db files
            for sqlite_file in location.rglob("*.sqlite3"):
                sqlite_files.append(sqlite_file)
            for sqlite_file in location.rglob("*.db"):
                sqlite_files.append(sqlite_file)
    
    return sqlite_files


def migrate_chroma_collection(sqlite_path: Path, collection_name: str, pg_store: PgVectorStore) -> int:
    """Migrate a single ChromaDB collection to pgvector.
    
    Args:
        sqlite_path: Path to ChromaDB SQLite file
        collection_name: Collection name to migrate
        pg_store: PgVectorStore instance
        
    Returns:
        Number of documents migrated
    """
    try:
        import sqlite3
        
        conn = sqlite3.connect(str(sqlite_path))
        cursor = conn.cursor()
        
        # Try to read from ChromaDB SQLite schema
        # Note: This is a simplified migration - actual ChromaDB schema may vary
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name LIKE '%collection%'
        """)
        
        tables = cursor.fetchall()
        if not tables:
            return 0
        
        # Try to extract embeddings from ChromaDB tables
        # This is a best-effort migration as ChromaDB schema can vary
        migrated_count = 0
        
        # Attempt to read embeddings (schema-dependent)
        try:
            cursor.execute("""
                SELECT id, document, embedding, metadata 
                FROM embeddings 
                WHERE collection_id = (SELECT id FROM collections WHERE name = ?)
            """, (collection_name,))
            
            rows = cursor.fetchall()
            for row in rows:
                doc_id, document, embedding_json, metadata_json = row
                
                # Parse embedding (may be JSON or binary)
                try:
                    if isinstance(embedding_json, str):
                        embedding = json.loads(embedding_json)
                    else:
                        import numpy as np
                        embedding = np.frombuffer(embedding_json, dtype=np.float32).tolist()
                except Exception:
                    continue
                
                # Parse metadata
                try:
                    metadata = json.loads(metadata_json) if metadata_json else {}
                except Exception:
                    metadata = {}
                
                # Add to pgvector
                pg_store.add_documents(
                    texts=[document],
                    metadatas=[metadata],
                    ids=[doc_id]
                )
                migrated_count += 1
        except Exception as e:
            warnings.warn(f"Could not migrate collection {collection_name}: {e}")
        
        conn.close()
        return migrated_count
        
    except ImportError:
        warnings.warn("sqlite3 not available for migration")
        return 0
    except Exception as e:
        warnings.warn(f"Migration failed for {sqlite_path}: {e}")
        return 0


def main():
    """Main migration function."""
    print("🔄 ChromaDB to pgvector Migration Script")
    print("=" * 50)
    
    # Check if ChromaDB SQLite files exist
    sqlite_files = find_chroma_sqlite_files()
    
    if not sqlite_files:
        print("✅ No ChromaDB SQLite files found. Migration not needed.")
        print("   If you have ChromaDB data elsewhere, please export manually.")
        return
    
    print(f"📦 Found {len(sqlite_files)} ChromaDB SQLite file(s)")
    
    # Initialize pgvector store
    print("\n🔌 Connecting to PostgreSQL...")
    pg_store = PgVectorStore(collection_name="migrated")
    
    if not pg_store.health_check():
        print("❌ Cannot connect to PostgreSQL. Please check your configuration.")
        return
    
    print("✅ PostgreSQL connection successful")
    
    # Migrate each SQLite file
    total_migrated = 0
    for sqlite_file in sqlite_files:
        print(f"\n📄 Processing: {sqlite_file}")
        
        # Try to detect collection names (simplified)
        # In practice, you may need to inspect the SQLite schema
        collection_name = sqlite_file.stem
        
        migrated = migrate_chroma_collection(sqlite_file, collection_name, pg_store)
        total_migrated += migrated
        
        if migrated > 0:
            print(f"   ✅ Migrated {migrated} documents")
        else:
            print(f"   ⚠️  No documents found or migration failed")
    
    print("\n" + "=" * 50)
    print(f"✅ Migration complete! Total documents migrated: {total_migrated}")
    print("\nNote: This is a simplified migration. For complex ChromaDB setups,")
    print("      you may need to export data manually and import to pgvector.")


if __name__ == "__main__":
    main()
