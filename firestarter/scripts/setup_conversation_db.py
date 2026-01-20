#!/usr/bin/env python3
"""Setup script for conversation database schema."""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Load .env file BEFORE importing other modules
from dotenv import load_dotenv
load_dotenv(project_root / ".env")

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT


def run_migration():
    """Run database migration."""
    # Load environment variables
    postgres_host = os.getenv("POSTGRES_HOST", "localhost")
    postgres_port = int(os.getenv("POSTGRES_PORT", "5432"))
    postgres_database = os.getenv("POSTGRES_DATABASE", "firestarter_pg")
    postgres_user = os.getenv("POSTGRES_USER", "firestarter_ad")
    postgres_password = os.getenv("POSTGRES_PASSWORD", "")
    
    print("🔧 Setting up conversation database schema...")
    print(f"   Host: {postgres_host}:{postgres_port}")
    print(f"   Database: {postgres_database}")
    print(f"   User: {postgres_user}")
    print("")
    
    # Try to use schema.sql first (simpler), then fallback to migration file
    schema_file = project_root / "database" / "schema.sql"
    migration_file = project_root / "database" / "migrations" / "001_initial_schema.sql"
    
    sql_file = None
    if schema_file.exists():
        sql_file = schema_file
        print(f"📄 Using schema file: {sql_file.name}")
    elif migration_file.exists():
        sql_file = migration_file
        print(f"📄 Using migration file: {sql_file.name}")
    else:
        print(f"❌ Neither schema.sql nor migration file found")
        return 1
    
    with open(sql_file, 'r') as f:
        migration_sql = f.read()
    
    try:
        # Connect to PostgreSQL
        conn = psycopg2.connect(
            host=postgres_host,
            port=postgres_port,
            database=postgres_database,
            user=postgres_user,
            password=postgres_password
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        print("✅ Connected to PostgreSQL")
        print("📝 Running migration...")
        
        # Execute migration SQL
        # Handle both single statement execution and statement-by-statement
        # For schema.sql with functions/triggers, we need smarter splitting
        try:
            # First, try to execute as a whole (works for simple schemas)
            cursor.execute(migration_sql)
        except psycopg2.Error as e:
            error_msg = str(e).lower()
            
            # If "already exists" error, that's OK for idempotent operations
            if 'already exists' in error_msg or 'duplicate' in error_msg:
                print("   ℹ️  Schema objects already exist, verifying...")
                # Continue to verification step
            else:
                # For other errors, try executing statements separately
                # But we need to be smart about function bodies
                print("   ⚠️  Trying statement-by-statement execution...")
                
                # Split by semicolon, but preserve function/trigger bodies
                statements = []
                current_stmt = ""
                in_function = False
                dollar_count = 0
                
                for line in migration_sql.split('\n'):
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith('--'):
                        continue
                    
                    # Check if we're entering/exiting a function body
                    if '$$' in line:
                        dollar_count += line.count('$$')
                        in_function = (dollar_count % 2 == 1)
                    
                    current_stmt += line + "\n"
                    
                    # Only split on semicolon if not in function body
                    if ';' in line and not in_function:
                        # Split by semicolon
                        parts = current_stmt.split(';')
                        for i, part in enumerate(parts):
                            part = part.strip()
                            if part and not part.startswith('--'):
                                if i < len(parts) - 1:
                                    # This part ends with semicolon
                                    statements.append(part + ';')
                                else:
                                    # Last part, keep for next statement
                                    current_stmt = part
                        current_stmt = ""
                
                # Add remaining statement
                if current_stmt.strip():
                    statements.append(current_stmt.strip())
                
                # Execute statements one by one
                for statement in statements:
                    if not statement:
                        continue
                    try:
                        cursor.execute(statement)
                    except psycopg2.Error as e2:
                        error_msg2 = str(e2).lower()
                        if 'already exists' in error_msg2 or 'duplicate' in error_msg2:
                            print(f"   ℹ️  Object already exists, skipping...")
                        else:
                            # Re-raise if it's a different error
                            raise
        
        # Verify tables were created
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('conversations', 'conversation_messages', 'agent_states')
            ORDER BY table_name;
        """)
        
        tables = cursor.fetchall()
        if len(tables) == 3:
            print("✅ All tables created successfully:")
            for table in tables:
                print(f"   - {table[0]}")
        else:
            print(f"⚠️  Warning: Expected 3 tables, found {len(tables)}")
        
        cursor.close()
        conn.close()
        
        print("")
        print("✅ Database schema setup completed!")
        return 0
        
    except psycopg2.Error as e:
        print(f"❌ Database error: {e}")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(run_migration())
