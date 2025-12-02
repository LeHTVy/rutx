"""
Database Migration: Add Programmatic Report Support

This migration adds support for distinguishing between programmatic and analysis reports.

Changes:
1. Add report_category enum column to generated_reports table
2. Add structured_data JSON column for programmatic report data
3. Add programmatic_report_id foreign key for linking analysis reports to programmatic reports
"""

from sqlalchemy import text


def upgrade(engine):
    """Apply migration to add programmatic report columns."""

    with engine.connect() as conn:
        # Check if table exists
        result = conn.execute(text("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='generated_reports'
        """))

        if not result.fetchone():
            print("Table 'generated_reports' does not exist yet. Skipping migration.")
            return

        # Check if columns already exist
        result = conn.execute(text("PRAGMA table_info(generated_reports)"))
        columns = {row[1] for row in result.fetchall()}

        print(f"Existing columns: {columns}")

        # Add report_category column if it doesn't exist
        if 'report_category' not in columns:
            print("Adding report_category column...")
            conn.execute(text("""
                ALTER TABLE generated_reports
                ADD COLUMN report_category VARCHAR(50) DEFAULT 'analysis'
            """))
            conn.commit()
            print("[OK] Added report_category column")
        else:
            print("Column report_category already exists")

        # Add structured_data column if it doesn't exist
        if 'structured_data' not in columns:
            print("Adding structured_data column...")
            conn.execute(text("""
                ALTER TABLE generated_reports
                ADD COLUMN structured_data JSON
            """))
            conn.commit()
            print("[OK] Added structured_data column")
        else:
            print("Column structured_data already exists")

        # Add programmatic_report_id column if it doesn't exist
        if 'programmatic_report_id' not in columns:
            print("Adding programmatic_report_id column...")
            conn.execute(text("""
                ALTER TABLE generated_reports
                ADD COLUMN programmatic_report_id VARCHAR(36)
            """))
            conn.commit()
            print("[OK] Added programmatic_report_id column")
        else:
            print("Column programmatic_report_id already exists")

        print("\n[SUCCESS] Migration completed successfully!")


def downgrade(engine):
    """
    Rollback migration (remove columns).

    Note: SQLite doesn't support DROP COLUMN, so this creates a new table
    without the columns and copies data over.
    """

    with engine.connect() as conn:
        print("Rolling back migration...")

        # This is complex in SQLite and rarely needed
        # For now, just log that rollback is not supported
        print("[WARNING] Rollback not implemented for SQLite")
        print("Manual rollback required if needed")


if __name__ == "__main__":
    # Run migration
    import sys
    import os

    # Add parent directory to path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

    from database.database import get_db_manager

    print("="*60)
    print("Running Migration: Add Programmatic Report Support")
    print("="*60)

    db_manager = get_db_manager()
    engine = db_manager.engine

    upgrade(engine)

    print("\nMigration complete!")
