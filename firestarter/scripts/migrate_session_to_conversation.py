#!/usr/bin/env python3
"""Migration script to convert existing session_id data to conversation_id."""

import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from memory.conversation_store import ConversationStore
from memory.manager import get_memory_manager
from rag.retriever import ConversationRetriever
from rag.results_storage import ToolResultsStorage
import chromadb
from chromadb.config import Settings


def migrate_vector_db_metadata():
    """Migrate Vector DB metadata from session_id to conversation_id."""
    print("🔄 Migrating Vector DB metadata...")
    
    try:
        # Connect to Chroma Server
        server_host = os.getenv("CHROMA_SERVER_HOST", "localhost")
        server_port = int(os.getenv("CHROMA_SERVER_PORT", "8000"))
        auth_token = os.getenv("CHROMA_SERVER_AUTH_TOKEN")
        
        settings = Settings(anonymized_telemetry=False)
        if auth_token:
            settings.chroma_client_auth_provider = "chromadb.auth.token.TokenAuthClientProvider"
            settings.chroma_client_auth_credentials = auth_token
        
        client = chromadb.HttpClient(
            host=server_host,
            port=server_port,
            settings=settings
        )
        
        # Get all collections
        collections = client.list_collections()
        
        migrated_count = 0
        
        for collection in collections:
            collection_name = collection.name
            print(f"  Processing collection: {collection_name}")
            
            try:
                # Get all items
                results = collection.get()
                
                if not results or not results.get("ids"):
                    continue
                
                ids = results["ids"]
                metadatas = results.get("metadatas", [])
                
                if not metadatas:
                    continue
                
                # Find items with session_id but no conversation_id
                updates_needed = []
                for i, metadata in enumerate(metadatas):
                    if metadata and metadata.get("session_id") and not metadata.get("conversation_id"):
                        session_id = metadata["session_id"]
                        
                        # Try to find conversation by session_id
                        conversation_store = ConversationStore()
                        conversation = conversation_store.get_conversation_by_session_id(session_id)
                        
                        if conversation:
                            conversation_id = conversation["id"]
                            # Update metadata
                            new_metadata = metadata.copy()
                            new_metadata["conversation_id"] = conversation_id
                            updates_needed.append((ids[i], new_metadata))
                
                # Update in batches
                if updates_needed:
                    # Note: Chroma doesn't support direct metadata update
                    # We need to delete and re-add with new metadata
                    # For now, just log what would be updated
                    print(f"    Found {len(updates_needed)} items to migrate")
                    migrated_count += len(updates_needed)
                    # TODO: Implement actual update (delete + re-add with new metadata)
                    
            except Exception as e:
                print(f"    ⚠️  Error processing {collection_name}: {e}")
        
        print(f"✅ Vector DB migration: {migrated_count} items found (manual update may be needed)")
        return migrated_count
        
    except Exception as e:
        print(f"⚠️  Vector DB migration warning: {e}")
        return 0


def migrate_in_memory_buffers(memory_manager):
    """Migrate in-memory conversation buffers to PostgreSQL.
    
    Args:
        memory_manager: MemoryManager instance
    """
    print("🔄 Migrating in-memory buffers...")
    
    if not hasattr(memory_manager, '_conversation_buffers'):
        print("  ℹ️  No in-memory buffers found")
        return 0
    
    buffers = memory_manager._conversation_buffers
    if not buffers:
        print("  ℹ️  No in-memory buffers to migrate")
        return 0
    
    migrated_count = 0
    conversation_store = ConversationStore()
    
    for session_id, messages in buffers.items():
        print(f"  Migrating session: {session_id[:8]}... ({len(messages)} messages)")
        
        try:
            # Try to find existing conversation by session_id
            conversation = conversation_store.get_conversation_by_session_id(session_id)
            
            if conversation:
                conversation_id = conversation["id"]
            else:
                # Create new conversation
                conversation_id = conversation_store.create_conversation(
                    title=f"Migrated Session {session_id[:8]}",
                    session_id=session_id
                )
            
            # Add messages to conversation
            for msg in messages:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if content:
                    conversation_store.add_message(conversation_id, role, content)
                    migrated_count += 1
            
            print(f"    ✅ Migrated {len(messages)} messages to conversation {conversation_id[:8]}...")
            
        except Exception as e:
            print(f"    ⚠️  Error migrating session {session_id[:8]}...: {e}")
    
    print(f"✅ Buffer migration: {migrated_count} messages migrated")
    return migrated_count


def migrate_verified_targets(memory_manager):
    """Migrate verified targets from in-memory to PostgreSQL.
    
    Args:
        memory_manager: MemoryManager instance
    """
    print("🔄 Migrating verified targets...")
    
    if not hasattr(memory_manager, '_verified_targets'):
        print("  ℹ️  No verified targets found")
        return 0
    
    targets = memory_manager._verified_targets
    if not targets:
        print("  ℹ️  No verified targets to migrate")
        return 0
    
    migrated_count = 0
    conversation_store = ConversationStore()
    
    for session_id, domain in targets.items():
        print(f"  Migrating target: {session_id[:8]}... -> {domain}")
        
        try:
            # Try to find existing conversation by session_id
            conversation = conversation_store.get_conversation_by_session_id(session_id)
            
            if conversation:
                conversation_id = conversation["id"]
                conversation_store.update_verified_target(conversation_id, domain)
                migrated_count += 1
                print(f"    ✅ Updated conversation {conversation_id[:8]}... with target {domain}")
            else:
                print(f"    ⚠️  No conversation found for session {session_id[:8]}...")
                
        except Exception as e:
            print(f"    ⚠️  Error migrating target: {e}")
    
    print(f"✅ Verified targets migration: {migrated_count} targets migrated")
    return migrated_count


def main():
    """Main migration function."""
    print("=" * 60)
    print("Migration: Session ID → Conversation ID")
    print("=" * 60)
    print("")
    
    # Initialize components
    memory_manager = get_memory_manager()
    conversation_store = ConversationStore()
    
    # Step 1: Migrate in-memory buffers
    buffer_count = migrate_in_memory_buffers(memory_manager)
    
    # Step 2: Migrate verified targets
    target_count = migrate_verified_targets(memory_manager)
    
    # Step 3: Migrate Vector DB metadata
    vector_count = migrate_vector_db_metadata()
    
    print("")
    print("=" * 60)
    print("✅ Migration completed!")
    print("=" * 60)
    print(f"  Messages migrated: {buffer_count}")
    print(f"  Targets migrated: {target_count}")
    print(f"  Vector items found: {vector_count}")
    print("")
    print("Note: Vector DB metadata updates may require manual intervention.")
    print("      The new system will use conversation_id going forward.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
