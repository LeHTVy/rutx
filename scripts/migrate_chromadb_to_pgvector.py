#!/usr/bin/env python3
"""
ChromaDB to pgvector Migration Script
======================================

Exports all vectors from ChromaDB and imports them into PostgreSQL with pgvector.

Usage:
    python scripts/migrate_chromadb_to_pgvector.py [--dry-run] [--batch-size 100]

Requirements:
    - ChromaDB data in ~/.chromadb or CHROMA_PERSIST_DIR
    - PostgreSQL with pgvector extension
    - Environment variables: POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DATABASE, POSTGRES_USER, POSTGRES_PASSWORD
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def get_chromadb_data(persist_dir: str = None) -> Dict[str, Any]:
    """Extract all data from ChromaDB.
    
    Returns:
        Dict with collections and their documents, embeddings, metadata
    """
    try:
        import chromadb
    except ImportError:
        print("❌ ChromaDB not installed. Run: pip install chromadb")
        sys.exit(1)
    
    # Find ChromaDB persist directory
    if persist_dir is None:
        persist_dir = os.getenv("CHROMA_PERSIST_DIR", str(Path.home() / ".chromadb"))
    
    if not Path(persist_dir).exists():
        print(f"❌ ChromaDB directory not found: {persist_dir}")
        print("   Set CHROMA_PERSIST_DIR environment variable or pass --chroma-dir")
        sys.exit(1)
    
    print(f"📂 Reading ChromaDB from: {persist_dir}")
    
    # Connect to ChromaDB using new API (v0.4+)
    try:
        # New API: PersistentClient
        client = chromadb.PersistentClient(path=persist_dir)
    except Exception:
        # Fallback for even older data - try EphemeralClient and copy
        print("   ⚠️ Trying legacy mode...")
        try:
            from chromadb.config import Settings
            client = chromadb.Client(Settings(
                is_persistent=True,
                persist_directory=persist_dir,
                anonymized_telemetry=False
            ))
        except Exception as e:
            print(f"❌ Failed to open ChromaDB: {e}")
            print("   Your ChromaDB data may need migration. Try:")
            print("   pip install chroma-migrate && chroma-migrate")
            sys.exit(1)
    
    # Get all collections
    collections = client.list_collections()
    print(f"   Found {len(collections)} collection(s)")
    
    data = {
        "exported_at": datetime.now().isoformat(),
        "source": persist_dir,
        "collections": {}
    }
    
    for collection in collections:
        name = collection.name
        print(f"   📦 Collection: {name}")
        
        # Get all items from collection
        items = collection.get(include=["embeddings", "documents", "metadatas"])
        
        data["collections"][name] = {
            "ids": items.get("ids", []),
            "embeddings": items.get("embeddings", []),
            "documents": items.get("documents", []),
            "metadatas": items.get("metadatas", [])
        }
        
        count = len(items.get("ids", []))
        print(f"      • {count} documents")
    
    return data


def import_to_pgvector(data: Dict[str, Any], batch_size: int = 100, dry_run: bool = False):
    """Import data into PostgreSQL with pgvector.
    
    Args:
        data: Exported ChromaDB data
        batch_size: Number of records per batch insert
        dry_run: If True, don't actually insert
    """
    try:
        import psycopg2
        from psycopg2.extras import execute_values
    except ImportError:
        print("❌ psycopg2 not installed. Run: pip install psycopg2-binary")
        sys.exit(1)
    
    # Get PostgreSQL connection info
    pg_host = os.getenv("POSTGRES_HOST", "localhost")
    pg_port = os.getenv("POSTGRES_PORT", "5432")
    pg_db = os.getenv("POSTGRES_DATABASE", "snode_db")
    pg_user = os.getenv("POSTGRES_USER", "snode")
    pg_password = os.getenv("POSTGRES_PASSWORD", "")
    
    if not pg_password:
        print("⚠️  POSTGRES_PASSWORD not set in environment")
        print("   Set it in .env or export POSTGRES_PASSWORD=your_password")
        if not dry_run:
            sys.exit(1)
    
    print(f"\n📡 Connecting to PostgreSQL: {pg_host}:{pg_port}/{pg_db}")
    
    if dry_run:
        print("🔍 DRY RUN - no data will be inserted")
        # Just print what would be done
        for coll_name, coll_data in data["collections"].items():
            count = len(coll_data["ids"])
            print(f"   Would insert {count} vectors from '{coll_name}'")
        return
    
    # Connect to PostgreSQL
    try:
        conn = psycopg2.connect(
            host=pg_host,
            port=pg_port,
            dbname=pg_db,
            user=pg_user,
            password=pg_password
        )
        conn.autocommit = False
    except Exception as e:
        print(f"❌ Failed to connect to PostgreSQL: {e}")
        sys.exit(1)
    
    cursor = conn.cursor()
    
    # Ensure pgvector extension exists
    cursor.execute("CREATE EXTENSION IF NOT EXISTS vector;")
    
    # Create table if not exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vector_embeddings (
            id SERIAL PRIMARY KEY,
            external_id VARCHAR(255) UNIQUE,
            collection_name VARCHAR(100) NOT NULL,
            content TEXT,
            embedding vector(768),
            metadata JSONB DEFAULT '{}',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            migrated_from VARCHAR(50) DEFAULT 'chromadb'
        );
        
        -- Index for similarity search
        CREATE INDEX IF NOT EXISTS idx_vector_embeddings_embedding 
        ON vector_embeddings USING hnsw (embedding vector_cosine_ops);
        
        -- Index for collection filtering
        CREATE INDEX IF NOT EXISTS idx_vector_embeddings_collection 
        ON vector_embeddings (collection_name);
    """)
    
    total_inserted = 0
    
    for coll_name, coll_data in data["collections"].items():
        ids = coll_data["ids"]
        embeddings = coll_data["embeddings"]
        documents = coll_data["documents"]
        metadatas = coll_data["metadatas"]
        
        print(f"\n📥 Importing collection '{coll_name}' ({len(ids)} vectors)...")
        
        # Prepare batch data
        batch = []
        for i, doc_id in enumerate(ids):
            embedding = embeddings[i] if embeddings and i < len(embeddings) else None
            document = documents[i] if documents and i < len(documents) else ""
            metadata = metadatas[i] if metadatas and i < len(metadatas) else {}
            
            if embedding is None:
                print(f"   ⚠️ Skipping {doc_id}: no embedding")
                continue
            
            # Convert embedding to PostgreSQL vector format
            embedding_str = "[" + ",".join(str(v) for v in embedding) + "]"
            
            batch.append((
                doc_id,
                coll_name,
                document,
                embedding_str,
                json.dumps(metadata) if metadata else "{}"
            ))
            
            # Insert batch
            if len(batch) >= batch_size:
                _insert_batch(cursor, batch)
                total_inserted += len(batch)
                print(f"   ✓ Inserted {total_inserted} vectors...")
                batch = []
        
        # Insert remaining
        if batch:
            _insert_batch(cursor, batch)
            total_inserted += len(batch)
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print(f"\n✅ Migration complete! Inserted {total_inserted} vectors into pgvector")


def _insert_batch(cursor, batch: List[tuple]):
    """Insert a batch of records."""
    from psycopg2.extras import execute_values
    
    execute_values(
        cursor,
        """
        INSERT INTO vector_embeddings (external_id, collection_name, content, embedding, metadata)
        VALUES %s
        ON CONFLICT (external_id) DO UPDATE SET
            content = EXCLUDED.content,
            embedding = EXCLUDED.embedding,
            metadata = EXCLUDED.metadata
        """,
        batch,
        template="(%s, %s, %s, %s::vector, %s::jsonb)"
    )


def export_to_json(data: Dict[str, Any], output_file: str):
    """Export data to JSON file for backup.
    
    Args:
        data: ChromaDB export data
        output_file: Output JSON file path
    """
    # Convert embeddings to lists for JSON serialization
    export_data = {
        "exported_at": data["exported_at"],
        "source": data["source"],
        "collections": {}
    }
    
    for name, coll in data["collections"].items():
        export_data["collections"][name] = {
            "ids": coll["ids"],
            "documents": coll["documents"],
            "metadatas": coll["metadatas"],
            "embeddings": [list(e) if e else None for e in coll.get("embeddings", [])]
        }
    
    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=2, default=str)
    
    print(f"💾 Exported to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Migrate ChromaDB vectors to PostgreSQL pgvector"
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of vectors to insert per batch (default: 100)"
    )
    parser.add_argument(
        "--chroma-dir",
        type=str,
        default=None,
        help="ChromaDB persist directory (default: ~/.chromadb)"
    )
    parser.add_argument(
        "--export-json",
        type=str,
        default=None,
        help="Also export to JSON file for backup"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("ChromaDB → pgvector Migration")
    print("=" * 60)
    
    # Step 1: Export from ChromaDB
    data = get_chromadb_data(args.chroma_dir)
    
    # Step 2: Optional JSON backup
    if args.export_json:
        export_to_json(data, args.export_json)
    
    # Step 3: Import to pgvector
    import_to_pgvector(data, batch_size=args.batch_size, dry_run=args.dry_run)
    
    print("\n" + "=" * 60)
    if args.dry_run:
        print("DRY RUN complete. Run without --dry-run to perform migration.")
    else:
        print("Migration complete!")
        print("\nNext steps:")
        print("1. Update app code to use PgVectorStore instead of VectorMemory")
        print("2. Verify data in PostgreSQL: SELECT COUNT(*) FROM vector_embeddings;")
        print("3. Once verified, you can remove ChromaDB dependency")
    print("=" * 60)


if __name__ == "__main__":
    main()
