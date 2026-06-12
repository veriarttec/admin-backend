"""
Seed script for admin portal
Creates admin users and activity logs in the database.
Requires ADMIN_SEED_PASSWORD to be set in the environment.
"""
import os
import sys

from database import SessionLocal, engine, Base
from models import Admin, ActivityLog, Bank
from auth import hash_password

SEED_PASSWORD = os.getenv("ADMIN_SEED_PASSWORD")
if not SEED_PASSWORD or len(SEED_PASSWORD) < 8:
    sys.exit("Set ADMIN_SEED_PASSWORD (min 8 chars) before running this script.")


def seed_admins():
    """Create sample admin users"""
    db = SessionLocal()
    
    try:
        # Create tables if they don't exist
        Base.metadata.create_all(bind=engine)
        
        print("🌱 Seeding admin users...")
        
        admins_data = [
            {
                "email": "admin@artpriv.com",
                "name": "Super Admin",
                "role": "super_admin"
            },
            {
                "email": "support@artpriv.com",
                "name": "Support Team",
                "role": "support"
            },
            {
                "email": "viewer@artpriv.com",
                "name": "Read Only User",
                "role": "viewer"
            }
        ]
        
        admin_objects = []
        for admin_data in admins_data:
            # Check if admin already exists
            existing = db.query(Admin).filter(Admin.email == admin_data["email"]).first()
            if existing:
                print(f"  ⚠️ Admin {admin_data['email']} already exists, skipping...")
                admin_objects.append(existing)
                continue
            
            admin = Admin(
                email=admin_data["email"],
                hashed_password=hash_password(SEED_PASSWORD),
                name=admin_data["name"],
                role=admin_data["role"],
                is_active=True
            )
            db.add(admin)
            db.flush()
            admin_objects.append(admin)
            print(f"  ✓ Created admin: {admin.name} ({admin.role})")
        
        db.commit()
        
        # Create sample activity logs
        print("\n📝 Creating sample activity logs...")
        banks = db.query(Bank).limit(3).all()
        
        if admin_objects and banks:
            sample_activities = [
                {"action": "bank_verified", "entity_type": "bank", "entity_id": str(banks[0].id) if banks else None, "details": {"bank_name": banks[0].name if banks else "Unknown"}},
                {"action": "subscription_updated", "entity_type": "bank", "entity_id": str(banks[1].id) if len(banks) > 1 else None, "details": {"tier": "Professional"}},
                {"action": "donor_viewed", "entity_type": "donor", "entity_id": None, "details": {"count": 15}},
                {"action": "dashboard_accessed", "entity_type": "system", "entity_id": None, "details": {}},
            ]
            
            for i, activity in enumerate(sample_activities):
                # Check if this log already exists to avoid duplicates
                existing_log = db.query(ActivityLog).filter(
                    ActivityLog.action == activity["action"],
                    ActivityLog.entity_id == activity["entity_id"]
                ).first()
                
                if not existing_log:
                    log = ActivityLog(
                        admin_id=str(admin_objects[i % len(admin_objects)].id),
                        action=activity["action"],
                        entity_type=activity["entity_type"],
                        entity_id=activity["entity_id"],
                        details=activity["details"],
                        ip_address="127.0.0.1"
                    )
                    db.add(log)
            
            db.commit()
            print(f"✅ Successfully created activity logs")
        
        print("\n" + "="*60)
        print("🎉 Admin seeding completed successfully!")
        print("="*60)
        print("\n🔑 Admin accounts:")
        print("   • admin@artpriv.com (super_admin)")
        print("   • support@artpriv.com (support)")
        print("   • viewer@artpriv.com (viewer)")
        print("   • Password: value of ADMIN_SEED_PASSWORD")
        print("="*60)
        
    except Exception as e:
        db.rollback()
        print(f"❌ Error seeding admins: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


if __name__ == "__main__":
    seed_admins()
