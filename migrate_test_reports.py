"""
Add status tracking columns to test_reports table
"""
from database import SessionLocal
from sqlalchemy import text

def migrate():
    db = SessionLocal()
    
    try:
        print("🔧 Adding status tracking columns to test_reports table...")
        
        # Check if columns already exist
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'test_reports' 
            AND column_name IN ('status', 'reviewed_at', 'reviewed_by', 'review_notes')
        """))
        existing_columns = [row[0] for row in result]
        
        migrations = []
        if 'status' not in existing_columns:
            migrations.append("ALTER TABLE test_reports ADD COLUMN status VARCHAR DEFAULT 'pending'")
        if 'reviewed_at' not in existing_columns:
            migrations.append("ALTER TABLE test_reports ADD COLUMN reviewed_at TIMESTAMP WITH TIME ZONE")
        if 'reviewed_by' not in existing_columns:
            migrations.append("ALTER TABLE test_reports ADD COLUMN reviewed_by VARCHAR")
        if 'review_notes' not in existing_columns:
            migrations.append("ALTER TABLE test_reports ADD COLUMN review_notes TEXT")
        
        if migrations:
            for migration in migrations:
                print(f"  ✓ Executing: {migration}")
                db.execute(text(migration))
            db.commit()
            print("✅ Migration completed successfully!")
        else:
            print("  ⚠️  All columns already exist, nothing to migrate")
        
    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    migrate()
