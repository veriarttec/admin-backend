from database import SessionLocal
from models import Donor, TestReport
from sqlalchemy import text

db = SessionLocal()

# Get Karan Parashar
karan = db.query(Donor).filter(Donor.email == "karan.parashar@test.com").first()
if karan:
    print(f"✓ Found donor: {karan.first_name} {karan.last_name}")
    print(f"  ID: {karan.id}")
    print(f"  Email: {karan.email}")
    print(f"  State: {karan.state}")
    print(f"  Tests Pending: {karan.tests_pending}")
    
    # Get test reports
    reports = db.query(TestReport).filter(TestReport.donor_id == karan.id).all()
    print(f"\n  Test Reports ({len(reports)}):")
    for report in reports:
        print(f"    - {report.test_name}: {report.status}")
else:
    print("❌ Donor not found")

db.close()
