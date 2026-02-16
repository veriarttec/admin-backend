"""
Comprehensive seed script for testing the admin portal
Creates admins, banks, donors, and test reports for testing individual approval/rejection
"""
from database import SessionLocal, engine, Base
from models import (
    Admin, Bank, Donor, TestReport, DonorConsent, ConsentTemplate,
    CounselingSession, DonorStateHistory
)
from auth import hash_password
from datetime import datetime, timedelta
import uuid


def seed_test_data():
    """Create comprehensive test data"""
    db = SessionLocal()
    
    try:
        # Create tables if they don't exist
        Base.metadata.create_all(bind=engine)
        
        print("🌱 Starting comprehensive test data seeding...")
        print("="*60)
        
        # ========== ADMINS ==========
        print("\n👤 Creating admin users...")
        admins_data = [
            {"email": "admin@artpriv.com", "name": "Super Admin", "role": "super_admin"},
            {"email": "support@artpriv.com", "name": "Support Team", "role": "support"},
            {"email": "viewer@artpriv.com", "name": "Read Only User", "role": "viewer"}
        ]
        
        admins = []
        for admin_data in admins_data:
            existing = db.query(Admin).filter(Admin.email == admin_data["email"]).first()
            if existing:
                print(f"  ⚠️  Admin {admin_data['email']} exists")
                admins.append(existing)
            else:
                admin = Admin(
                    email=admin_data["email"],
                    hashed_password=hash_password("admin123"),
                    name=admin_data["name"],
                    role=admin_data["role"],
                    is_active=True
                )
                db.add(admin)
                db.flush()
                admins.append(admin)
                print(f"  ✓ Created: {admin.name} ({admin.role})")
        
        db.commit()
        
        # ========== BANKS ==========
        print("\n🏦 Creating test banks...")
        banks_data = [
            {
                "name": "LifeSpring Fertility Bank",
                "email": "lifespring@test.com",
                "phone": "+91-22-4567-8901",
                "address": "Andheri West, Mumbai, Maharashtra 400053",
                "website": "https://lifespring.in",
                "state": "operational",
                "is_verified": True,
                "is_subscribed": True,
                "subscription_tier": "Professional"
            },
            {
                "name": "Nova Reproductive Health",
                "email": "nova@test.com",
                "phone": "+91-11-2345-6789",
                "address": "Connaught Place, New Delhi, Delhi 110001",
                "website": "https://nova-fertility.com",
                "state": "operational",
                "is_verified": True,
                "is_subscribed": True,
                "subscription_tier": "Enterprise"
            }
        ]
        
        banks = []
        for bank_data in banks_data:
            existing = db.query(Bank).filter(Bank.email == bank_data["email"]).first()
            if existing:
                print(f"  ⚠️  Bank {bank_data['name']} exists")
                banks.append(existing)
            else:
                bank = Bank(
                    email=bank_data["email"],
                    hashed_password=hash_password("bank123"),
                    name=bank_data["name"],
                    state=bank_data["state"],
                    phone=bank_data["phone"],
                    address=bank_data["address"],
                    website=bank_data["website"],
                    is_verified=bank_data["is_verified"],
                    verified_at=datetime.utcnow() if bank_data["is_verified"] else None,
                    is_subscribed=bank_data["is_subscribed"],
                    subscription_tier=bank_data["subscription_tier"],
                    subscription_started_at=datetime.utcnow() if bank_data["is_subscribed"] else None,
                    subscription_expires_at=datetime.utcnow() + timedelta(days=365) if bank_data["is_subscribed"] else None
                )
                db.add(bank)
                db.flush()
                banks.append(bank)
                print(f"  ✓ Created: {bank.name}")
        
        db.commit()
        
        # ========== CONSENT TEMPLATES ==========
        print("\n📄 Creating consent templates...")
        for bank in banks:
            existing_template = db.query(ConsentTemplate).filter(
                ConsentTemplate.bank_id == bank.id
            ).first()
            
            if not existing_template:
                template = ConsentTemplate(
                    bank_id=bank.id,
                    title="Donor Consent Form",
                    content="I hereby consent to participate in the donor program...",
                    version="1.0",
                    order="1",
                    is_active=True
                )
                db.add(template)
                print(f"  ✓ Created consent template for {bank.name}")
        
        db.commit()
        
        # ========== DONORS ==========
        print("\n👥 Creating test donors...")
        donors_data = [
            {
                "first_name": "Karan",
                "last_name": "Parashar",
                "email": "karan.parashar@test.com",
                "phone": "+91-98765-43210",
                "date_of_birth": datetime(1995, 5, 15),
                "address": "Malad West, Mumbai, Maharashtra",
                "state": "tests_pending",
                "bank_index": 0,
                "tests_pending": True,
                "consent_pending": False
            },
            {
                "first_name": "Priya",
                "last_name": "Sharma",
                "email": "priya.sharma@test.com",
                "phone": "+91-98765-43211",
                "date_of_birth": datetime(1997, 8, 22),
                "address": "Bandra East, Mumbai, Maharashtra",
                "state": "tests_pending",
                "bank_index": 0,
                "tests_pending": True,
                "consent_pending": False
            },
            {
                "first_name": "Amit",
                "last_name": "Kumar",
                "email": "amit.kumar@test.com",
                "phone": "+91-98765-43212",
                "date_of_birth": datetime(1994, 3, 10),
                "address": "Green Park, New Delhi, Delhi",
                "state": "tests_pending",
                "bank_index": 1,
                "tests_pending": True,
                "consent_pending": False
            }
        ]
        
        donors = []
        for donor_data in donors_data:
            existing = db.query(Donor).filter(Donor.email == donor_data["email"]).first()
            if existing:
                print(f"  ⚠️  Donor {donor_data['first_name']} {donor_data['last_name']} exists")
                donors.append(existing)
            else:
                donor = Donor(
                    email=donor_data["email"],
                    hashed_password=hash_password("donor123"),
                    first_name=donor_data["first_name"],
                    last_name=donor_data["last_name"],
                    phone=donor_data["phone"],
                    date_of_birth=donor_data["date_of_birth"],
                    address=donor_data["address"],
                    state=donor_data["state"],
                    bank_id=banks[donor_data["bank_index"]].id,
                    selected_at=datetime.utcnow(),
                    tests_pending=donor_data["tests_pending"],
                    consent_pending=donor_data["consent_pending"],
                    eligibility_status="pending"
                )
                db.add(donor)
                db.flush()
                donors.append(donor)
                print(f"  ✓ Created: {donor.first_name} {donor.last_name}")
        
        db.commit()
        
        # ========== TEST REPORTS ==========
        print("\n🧪 Creating test reports...")
        
        # Test types as shown in the image
        test_types = [
            {"type": "hiv_type_1", "name": "HIV Type 1 Test"},
            {"type": "hiv_type_2", "name": "HIV Type 2 Test"},
            {"type": "hepatitis_b", "name": "Hepatitis B Test"},
            {"type": "hepatitis_c", "name": "Hepatitis C Test"},
            {"type": "syphilis", "name": "Syphilis Test"}
        ]
        
        for donor in donors:
            bank = db.query(Bank).filter(Bank.id == donor.bank_id).first()
            
            # Create 5 test reports per donor with different statuses
            for i, test_type in enumerate(test_types):
                existing_report = db.query(TestReport).filter(
                    TestReport.donor_id == donor.id,
                    TestReport.test_type == test_type["type"]
                ).first()
                
                if not existing_report:
                    # Mix of pending and approved reports
                    status = "pending" if i < 3 else "approved"  # First 3 pending, last 2 approved
                    
                    report = TestReport(
                        donor_id=donor.id,
                        bank_id=bank.id,
                        source="bank_conducted",
                        test_type=test_type["type"],
                        test_name=test_type["name"],
                        file_url=f"https://example.com/test-reports/{donor.id}/{test_type['type']}.pdf",
                        file_name=f"{test_type['type']}_report.pdf",
                        uploaded_by=bank.name,
                        uploaded_at=datetime.utcnow() - timedelta(days=i),
                        test_date=datetime.utcnow() - timedelta(days=i+1),
                        lab_name="Medical Labs India",
                        notes=f"Test conducted for {donor.first_name} {donor.last_name}",
                        status=status,
                        reviewed_at=datetime.utcnow() if status == "approved" else None,
                        reviewed_by="Super Admin" if status == "approved" else None,
                        review_notes="All parameters within normal range" if status == "approved" else None
                    )
                    db.add(report)
                    print(f"  ✓ Created {test_type['name']} for {donor.first_name} {donor.last_name} - Status: {status}")
        
        db.commit()
        
        # ========== SUMMARY ==========
        print("\n" + "="*60)
        print("🎉 Test data seeding completed successfully!")
        print("="*60)
        
        print("\n📊 Summary:")
        print(f"  • Admins: {len(admins)}")
        print(f"  • Banks: {len(banks)}")
        print(f"  • Donors: {len(donors)}")
        
        total_reports = db.query(TestReport).count()
        pending_reports = db.query(TestReport).filter(TestReport.status == "pending").count()
        approved_reports = db.query(TestReport).filter(TestReport.status == "approved").count()
        
        print(f"  • Test Reports: {total_reports}")
        print(f"    - Pending: {pending_reports}")
        print(f"    - Approved: {approved_reports}")
        
        print("\n🔑 Login Credentials:")
        print("\n  Admins:")
        print("    • admin@artpriv.com / admin123 (super_admin)")
        print("    • support@artpriv.com / admin123 (support)")
        print("    • viewer@artpriv.com / admin123 (viewer)")
        
        print("\n  Banks:")
        print("    • lifespring@test.com / bank123")
        print("    • nova@test.com / bank123")
        
        print("\n  Donors:")
        print("    • karan.parashar@test.com / donor123")
        print("    • priya.sharma@test.com / donor123")
        print("    • amit.kumar@test.com / donor123")
        
        print("\n💡 Tips:")
        print("  • Karan Parashar has 5 test reports (3 pending, 2 approved)")
        print("  • Navigate to Donors → Karan Parashar to test individual approval")
        print("  • All donors have tests_pending=True status")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_test_data()
